"""Rule base class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Sequence
from typing import ClassVar

from gha_warden.models import Finding, Severity
from gha_warden.workflow import PathPart, Workflow


class Rule(ABC):
    id: ClassVar[str]
    title: ClassVar[str]
    severity: ClassVar[Severity]
    description: ClassVar[str]
    remediation: ClassVar[str]

    @abstractmethod
    def check(self, workflow: Workflow) -> Iterable[Finding]:
        """Yield the findings this rule has in `workflow`."""

    def finding(
        self,
        workflow: Workflow,
        path: Sequence[PathPart],
        message: str,
        *,
        severity: Severity | None = None,
        key: bool = False,
        line_offset: int = 0,
    ) -> Finding:
        line, column = workflow.locate(path, key=key, line_offset=line_offset)
        return Finding(
            rule_id=self.id,
            severity=severity or self.severity,
            message=message,
            path=workflow.path,
            line=line,
            column=column,
            remediation=self.remediation,
        )
