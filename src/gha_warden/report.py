"""Output formatters: text, json, sarif, github annotations, markdown."""

from __future__ import annotations

import itertools
import json
import re
from collections import Counter
from collections.abc import Sequence

from gha_warden import __version__
from gha_warden.models import Finding, Severity
from gha_warden.rules import ALL_RULES

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/petrhromadka/gha-warden"
_SECURITY_SEVERITY = {
    Severity.LOW: "3.0",
    Severity.MEDIUM: "5.0",
    Severity.HIGH: "7.5",
    Severity.CRITICAL: "9.5",
}
_SARIF_LEVEL = {
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}
_GITHUB_COMMAND = {
    Severity.LOW: "notice",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}
_COLORS = {
    Severity.LOW: "36",
    Severity.MEDIUM: "33",
    Severity.HIGH: "31",
    Severity.CRITICAL: "1;31",
}


_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029]")
_NAMED_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def neutralize(text: str) -> str:
    r"""Render control characters as visible escapes (`\n`, `\x1b`).

    Findings embed text from the scanned file. Printed raw, a newline in it would let the file
    start a line of its own in the CI log, e.g. a `::add-mask::` workflow command.
    """

    def escape(match: re.Match[str]) -> str:
        char = match.group()
        if char in _NAMED_ESCAPES:
            return _NAMED_ESCAPES[char]
        code = ord(char)
        return f"\\x{code:02x}" if code <= 0xFF else f"\\u{code:04x}"

    return _CONTROL.sub(escape, text)


def _summary_counts(findings: Sequence[Finding]) -> dict[str, int]:
    counts = Counter(f.severity for f in findings)
    return {s.label: counts[s] for s in sorted(Severity, reverse=True)}


def format_text(findings: Sequence[Finding], *, files_scanned: int, color: bool) -> str:
    def paint(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if color else text

    out: list[str] = []
    for path, group in itertools.groupby(findings, key=lambda f: f.path):
        out.append(paint(neutralize(path), "1;4"))
        for f in group:
            label = paint(f"{f.severity.label:<8}", _COLORS[f.severity])
            out.append(f"  {f'{f.line}:{f.column}':<8}{label} {f.rule_id}  {neutralize(f.message)}")
            out.append(paint(f"      fix: {neutralize(f.remediation)}", "2"))
        out.append("")
    files = f"{files_scanned} file{'s' if files_scanned != 1 else ''}"
    if findings:
        counts = ", ".join(f"{n} {name}" for name, n in _summary_counts(findings).items() if n)
        out.append(
            f"{len(findings)} finding{'s' if len(findings) != 1 else ''} ({counts}) in {files}"
        )
    else:
        out.append(f"No findings in {files}")
    return "\n".join(out) + "\n"


def format_json(findings: Sequence[Finding], *, files_scanned: int) -> str:
    document = {
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.label,
                "message": f.message,
                "path": f.path,
                "line": f.line,
                "column": f.column,
                "remediation": f.remediation,
            }
            for f in findings
        ],
        "summary": {
            "total": len(findings),
            "by_severity": _summary_counts(findings),
            "files_scanned": files_scanned,
        },
    }
    return json.dumps(document, indent=2) + "\n"


def format_sarif(findings: Sequence[Finding]) -> str:
    """SARIF 2.1.0 for GitHub code scanning.

    Severity is split between rule and result, as GitHub documents it ("SARIF support for code
    scanning"): `security-severity` is only read from the rule (reportingDescriptor), so it holds
    the rule's own severity, which is the highest a finding of that rule can have. A finding
    that is less severe than its rule (GW003 on an `actions/*` action is medium, not high) says
    so through the result's `level`, which GitHub documents as overriding the rule default.
    """
    rule_index = {rule.id: index for index, rule in enumerate(ALL_RULES)}
    rules = [
        {
            "id": rule.id,
            "name": rule.title,
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.description},
            "help": {"text": rule.remediation},
            "defaultConfiguration": {"level": _SARIF_LEVEL[rule.severity]},
            "properties": {
                "security-severity": _SECURITY_SEVERITY[rule.severity],
                "tags": ["security"],
            },
        }
        for rule in ALL_RULES
    ]
    results = [
        {
            "ruleId": f.rule_id,
            "ruleIndex": rule_index[f.rule_id],
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": f.line, "startColumn": f.column},
                    }
                }
            ],
        }
        for f in findings
    ]
    document = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "gha-warden",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"


def _escape_data(text: str) -> str:
    """Escape a workflow-command message the way actions/toolkit does."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(text: str) -> str:
    return _escape_data(text).replace(":", "%3A").replace(",", "%2C")


def format_github(findings: Sequence[Finding]) -> str:
    """One workflow-command annotation per finding."""
    titles = {rule.id: rule.title for rule in ALL_RULES}
    lines = []
    for f in findings:
        title = _escape_property(f"{f.rule_id} {titles.get(f.rule_id, '')}".strip())
        lines.append(
            f"::{_GITHUB_COMMAND[f.severity]} file={_escape_property(f.path)},line={f.line},"
            f"col={f.column},title={title}::{_escape_data(f.message)}\n"
        )
    return "".join(lines)


def _escape_cell(text: str) -> str:
    return neutralize(text.replace("|", r"\|").replace("\r", "").replace("\n", "<br>"))


def format_markdown(findings: Sequence[Finding], *, files_scanned: int) -> str:
    """Summary and findings tables for `$GITHUB_STEP_SUMMARY` or a pull request comment."""
    files = f"{files_scanned} file{'s' if files_scanned != 1 else ''}"
    out = ["## gha-warden", ""]
    if not findings:
        out.append(f"No findings in {files}.")
        return "\n".join(out) + "\n"
    out += [
        f"{len(findings)} finding{'s' if len(findings) != 1 else ''} in {files}.",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    out += [f"| {name.capitalize()} | {n} |" for name, n in _summary_counts(findings).items()]
    out += [
        "",
        "| Severity | Rule | Location | Message |",
        "|----------|------|----------|---------|",
    ]
    for f in findings:
        location = _escape_cell(f"{f.path}:{f.line}")
        out.append(
            f"| {f.severity.label.capitalize()} | {f.rule_id} | {location} "
            f"| {_escape_cell(f.message)} |"
        )
    return "\n".join(out) + "\n"
