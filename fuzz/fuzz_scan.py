"""Coverage-guided fuzz target for gha-warden (Atheris / libFuzzer).

Input bytes are decoded, split on `\\n---\\n` into one to three workflow files, parsed, linked
for `workflow_run` lookups, scanned, and rendered in every report format. Only the documented
parse-error path (`WorkflowError`) may be raised; any other exception is a crash.

Run on Linux: `uv sync --group fuzz && uv run python fuzz/fuzz_scan.py -dict=fuzz/yaml.dict
fuzz/work corpus examples` (see fuzz/README.md). `check_one` is plain Python so that
tests/test_fuzz.py can run it without Atheris.
"""

from __future__ import annotations

import json
import re
import sys

from gha_warden.report import (
    format_github,
    format_json,
    format_markdown,
    format_sarif,
    format_text,
)
from gha_warden.scan import scan_workflow
from gha_warden.workflow import Workflow, WorkflowError, link_workflows

SEPARATOR = "\n---\n"
MAX_FILES = 3


def _assert_no_workflow_command(report: str, fmt: str) -> None:
    """A report meant for a CI log must not let file content start a `::command::` line.

    Leading whitespace is stripped first: it would not stop the runner from reading the command.
    """
    for line in report.splitlines():
        if line.lstrip().startswith("::"):
            raise AssertionError(f"{fmt} report line is a workflow command: {line!r}")


def check_one(data: bytes) -> None:
    """Scan one fuzz input; raise on anything but a clean scan or a `WorkflowError`."""
    text = data.decode("utf-8", errors="replace")
    workflows: list[Workflow] = []
    for index, part in enumerate(text.split(SEPARATOR, MAX_FILES - 1)):
        try:
            workflows.append(Workflow(f".github/workflows/fuzz-{index}.yml", part))
        except WorkflowError:
            continue
    link_workflows(workflows)
    findings = [finding for workflow in workflows for finding in scan_workflow(workflow)]
    scanned = len(workflows)

    for color in (False, True):
        _assert_no_workflow_command(
            format_text(findings, files_scanned=scanned, color=color), "text"
        )
    _assert_no_workflow_command(format_markdown(findings, files_scanned=scanned), "markdown")
    json.loads(format_json(findings, files_scanned=scanned))
    json.loads(format_sarif(findings))
    # One annotation line per finding: a newline in a message must not start a second command.
    # The runner splits its log on CR and LF only, so `str.splitlines` would be too strict here.
    github = re.split("\r\n?|\n", format_github(findings))[:-1]
    if len(github) != len(findings) or not all(line.startswith("::") for line in github):
        raise AssertionError(f"github report has {len(github)} lines for {len(findings)} findings")


def main() -> None:
    import atheris  # ty: ignore[import-not-found]  # Linux-only `fuzz` dependency group

    # Instrument what is already imported (gha_warden, yaml) for coverage feedback.
    atheris.instrument_all()
    atheris.Setup(sys.argv, check_one)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
