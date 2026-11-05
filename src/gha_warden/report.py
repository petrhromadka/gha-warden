"""Output formatters: text, json, sarif."""

from __future__ import annotations

import itertools
import json
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
_COLORS = {
    Severity.LOW: "36",
    Severity.MEDIUM: "33",
    Severity.HIGH: "31",
    Severity.CRITICAL: "1;31",
}


def _summary_counts(findings: Sequence[Finding]) -> dict[str, int]:
    counts = Counter(f.severity for f in findings)
    return {s.label: counts[s] for s in sorted(Severity, reverse=True)}


def format_text(findings: Sequence[Finding], *, files_scanned: int, color: bool) -> str:
    def paint(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if color else text

    out: list[str] = []
    for path, group in itertools.groupby(findings, key=lambda f: f.path):
        out.append(paint(path, "1;4"))
        for f in group:
            label = paint(f"{f.severity.label:<8}", _COLORS[f.severity])
            out.append(f"  {f'{f.line}:{f.column}':<8}{label} {f.rule_id}  {f.message}")
            out.append(paint(f"      fix: {f.remediation}", "2"))
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
            "properties": {"security-severity": _SECURITY_SEVERITY[f.severity]},
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
