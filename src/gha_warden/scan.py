"""Scanning: collect files, run rules, apply inline suppressions."""

from __future__ import annotations

import itertools
import re
from collections.abc import Collection, Iterable
from pathlib import Path

import yaml

from gha_warden.models import Finding, Severity
from gha_warden.rules import ALL_RULES
from gha_warden.workflow import Workflow

_SUPPRESSION = re.compile(r"(?:^|\s)#\s*gha-warden:\s*ignore(?:\[([^\]]*)\])?", re.IGNORECASE)
_SKIPPED_DIRS = frozenset({".git", ".venv", "node_modules"})
_SUFFIXES = frozenset({".yml", ".yaml"})
_ACTION_NAMES = frozenset({"action.yml", "action.yaml"})


def _looks_like_workflow(path: Path) -> bool:
    """Whether a YAML file found by walking a directory is a workflow or action file.

    Files under `.github/workflows` and files named `action.yml` always count. Any other YAML
    counts if its top-level mapping has `jobs` or `runs`. A file that cannot be read or parsed
    counts too, so that the error is reported instead of hiding a broken workflow.
    """
    if path.name.lower() in _ACTION_NAMES:
        return True
    parts = [part.lower() for part in path.parts]
    if any(a == ".github" and b == "workflows" for a, b in itertools.pairwise(parts)):
        return True
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError, ValueError, RecursionError):
        return True
    return isinstance(data, dict) and bool({"jobs", "runs"} & data.keys())


def collect_files(paths: Iterable[Path]) -> list[Path]:
    """Expand directories to the workflow files below them; files are kept as given.

    Walking a directory skips YAML that is not a workflow or action (dependabot.yml, issue
    templates, ...); a file named explicitly is always kept so that it is checked strictly.
    """
    files: dict[Path, None] = {}
    for path in paths:
        if path.is_dir():
            for candidate in sorted(path.rglob("*")):
                relative = candidate.relative_to(path)
                if (
                    candidate.is_file()
                    and candidate.suffix.lower() in _SUFFIXES
                    and not _SKIPPED_DIRS.intersection(relative.parts)
                    and _looks_like_workflow(candidate)
                ):
                    files[candidate] = None
        else:
            files[path] = None
    return list(files)


def is_suppressed(line: str, rule_id: str) -> bool:
    match = _SUPPRESSION.search(line)
    if match is None:
        return False
    if match.group(1) is None:
        return True
    return rule_id.upper() in {item.strip().upper() for item in match.group(1).split(",")}


def scan_workflow(
    workflow: Workflow,
    *,
    ignore: Collection[str] = (),
    min_severity: Severity = Severity.LOW,
) -> list[Finding]:
    ignored = {rule_id.upper() for rule_id in ignore}
    findings: list[Finding] = []
    for rule in ALL_RULES:
        if rule.id in ignored:
            continue
        for finding in rule.check(workflow):
            if finding.severity < min_severity:
                continue
            line = (
                workflow.lines[finding.line - 1] if 0 < finding.line <= len(workflow.lines) else ""
            )
            if not is_suppressed(line, finding.rule_id):
                findings.append(finding)
    return sorted(findings, key=lambda f: (f.line, f.column, f.rule_id))
