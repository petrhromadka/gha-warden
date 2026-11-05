from __future__ import annotations

import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest

from gha_warden.models import Finding
from gha_warden.scan import scan_workflow
from gha_warden.workflow import Workflow

HEADER = "name: t\non: push\npermissions: read-all\n"


def parse(text: str) -> Workflow:
    return Workflow("wf.yml", textwrap.dedent(text).lstrip("\n"))


@pytest.fixture
def findings_for() -> Callable[[str, str], list[Finding]]:
    """Return the findings of one rule for an inline workflow."""

    def run(rule_id: str, text: str) -> list[Finding]:
        return [f for f in scan_workflow(parse(text)) if f.rule_id == rule_id]

    return run


@pytest.fixture
def write_workflow(tmp_path: Path) -> Callable[[str, str], Path]:
    def write(text: str, name: str = "wf.yml") -> Path:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
        return path

    return write


VULNERABLE = """
    name: vulnerable
    on: pull_request_target
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - uses: third-party/tool@main
          - run: echo "${{ github.event.pull_request.title }}"
"""
