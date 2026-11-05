"""Command line interface."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from gha_warden import __version__
from gha_warden.config import CONFIG_FILENAME, ConfigError, load_config
from gha_warden.models import Finding, Severity
from gha_warden.report import (
    format_github,
    format_json,
    format_markdown,
    format_sarif,
    format_text,
    neutralize,
)
from gha_warden.rules import ALL_RULES
from gha_warden.scan import collect_files, scan_workflow
from gha_warden.workflow import Workflow, WorkflowError

DEFAULT_PATH = ".github/workflows"
EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2
FORMATS = ("text", "json", "sarif", "github", "markdown")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gha-warden",
        description="Static security auditor for GitHub Actions workflows.",
        epilog="Exit codes: 0 no findings, 1 findings, 2 usage or parse error.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        metavar="PATHS",
        help=f"workflow files or directories to scan (default: {DEFAULT_PATH})",
    )
    parser.add_argument("--format", choices=FORMATS, default="text")
    parser.add_argument(
        "--min-severity",
        choices=[s.label for s in Severity],
        help="only report findings at or above this severity (default: config file, else low)",
    )
    parser.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="RULE_ID",
        help="rule to skip; repeat the option or separate IDs with commas "
        "(replaces the config file's 'ignore')",
    )
    parser.add_argument(
        "--config",
        type=Path,
        metavar="PATH",
        help=f"TOML config file (default: {CONFIG_FILENAME} in the current directory, if present)",
    )
    parser.add_argument("--output", metavar="FILE", help="write the report to FILE")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _repo_root(path: Path) -> Path | None:
    """The closest ancestor of `path` holding a `.git` entry (a directory, or a worktree file)."""
    return next((parent for parent in path.parents if (parent / ".git").exists()), None)


def _relative_to_cwd(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _display_path(path: Path) -> str:
    """Path used in reports: relative to the repository root, else to the cwd, else absolute.

    GitHub code scanning and annotations resolve paths against the repository root, which is
    not necessarily the directory gha-warden runs in.
    """
    resolved = path.resolve()
    root = _repo_root(resolved)
    if root is not None:
        return resolved.relative_to(root).as_posix()
    return _relative_to_cwd(path)


def _use_color(args: argparse.Namespace) -> bool:
    # no-color.org: only a non-empty NO_COLOR disables color.
    return not (args.no_color or args.output or os.environ.get("NO_COLOR")) and sys.stdout.isatty()


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"gha-warden: error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    ignore = [part.strip().upper() for item in args.ignore for part in item.split(",") if part]
    known = {rule.id for rule in ALL_RULES}
    for rule_id in ignore:
        if rule_id not in known:
            parser.error(f"unknown rule id '{rule_id}' (known: {', '.join(sorted(known))})")
    ignore = ignore or list(config.ignore)

    paths = [Path(p) for p in args.paths] or [Path(DEFAULT_PATH)]
    errors: list[str] = []
    for path in paths:
        if not path.exists():
            errors.append(f"{path.as_posix()}: no such file or directory")
    # A directory scan skips YAML that is not a workflow; a file named explicitly must be one.
    explicit = {p for p in paths if not p.is_dir()}
    files = collect_files(p for p in paths if p.exists())

    if args.min_severity is not None:
        min_severity = Severity.parse(args.min_severity)
    else:
        min_severity = config.min_severity or Severity.LOW
    findings: list[Finding] = []
    scanned = 0
    for file in files:
        display = _display_path(file)
        if config.is_excluded(_relative_to_cwd(file)):
            continue
        try:
            workflow = Workflow(display, file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"{display}: cannot read file: {exc}")
        except WorkflowError as exc:
            errors.append(f"{display}: {exc}")
        else:
            if file in explicit and not {"jobs", "runs"} & workflow.data.keys():
                errors.append(f"{display}: not a GitHub Actions workflow or action file")
                continue
            scanned += 1
            findings += scan_workflow(workflow, ignore=ignore, min_severity=min_severity)

    for message in errors:
        print(f"gha-warden: error: {neutralize(message)}", file=sys.stderr)

    if args.format == "json":
        report = format_json(findings, files_scanned=scanned)
    elif args.format == "sarif":
        report = format_sarif(findings)
    elif args.format == "github":
        report = format_github(findings)
    elif args.format == "markdown":
        report = format_markdown(findings, files_scanned=scanned)
    else:
        report = format_text(findings, files_scanned=scanned, color=_use_color(args))
    if args.output:
        # Always LF, also on Windows, so a report is byte-identical on every platform.
        with Path(args.output).open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(report)
    else:
        sys.stdout.write(report)

    if errors:
        return EXIT_ERROR
    return EXIT_FINDINGS if findings else EXIT_OK
