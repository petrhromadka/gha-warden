"""Command line interface."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from gha_warden import __version__
from gha_warden.models import Finding, Severity
from gha_warden.report import format_json, format_sarif, format_text
from gha_warden.rules import ALL_RULES
from gha_warden.scan import collect_files, scan_workflow
from gha_warden.workflow import Workflow, WorkflowError

DEFAULT_PATH = ".github/workflows"
EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


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
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument(
        "--min-severity",
        choices=[s.label for s in Severity],
        default=Severity.LOW.label,
        help="only report findings at or above this severity (default: low)",
    )
    parser.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="RULE_ID",
        help="rule to skip; repeat the option or separate IDs with commas",
    )
    parser.add_argument("--output", metavar="FILE", help="write the report to FILE")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _use_color(args: argparse.Namespace) -> bool:
    return not (args.no_color or args.output or "NO_COLOR" in os.environ) and sys.stdout.isatty()


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    ignore = [part.strip().upper() for item in args.ignore for part in item.split(",") if part]
    known = {rule.id for rule in ALL_RULES}
    for rule_id in ignore:
        if rule_id not in known:
            parser.error(f"unknown rule id '{rule_id}' (known: {', '.join(sorted(known))})")

    paths = [Path(p) for p in args.paths] or [Path(DEFAULT_PATH)]
    errors: list[str] = []
    for path in paths:
        if not path.exists():
            errors.append(f"{path}: no such file or directory")
    files = collect_files(p for p in paths if p.exists())

    min_severity = Severity.parse(args.min_severity)
    findings: list[Finding] = []
    scanned = 0
    for file in files:
        display = _display_path(file)
        try:
            workflow = Workflow(display, file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"{display}: cannot read file: {exc}")
        except WorkflowError as exc:
            errors.append(f"{display}: {exc}")
        else:
            scanned += 1
            findings += scan_workflow(workflow, ignore=ignore, min_severity=min_severity)

    for message in errors:
        print(f"gha-warden: error: {message}", file=sys.stderr)

    if args.format == "json":
        report = format_json(findings, files_scanned=scanned)
    elif args.format == "sarif":
        report = format_sarif(findings)
    else:
        report = format_text(findings, files_scanned=scanned, color=_use_color(args))
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)

    if errors:
        return EXIT_ERROR
    return EXIT_FINDINGS if findings else EXIT_OK
