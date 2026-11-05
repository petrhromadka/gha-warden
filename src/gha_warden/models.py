"""Core data model: severities and findings."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, name: str) -> Severity:
        return cls[name.upper()]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    path: str
    line: int
    column: int
    remediation: str
