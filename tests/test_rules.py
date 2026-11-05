"""One positive and one negative case per rule, plus exact line-number checks."""

from __future__ import annotations

import textwrap
from collections.abc import Callable

import pytest

from gha_warden.models import Finding, Severity
from tests.conftest import parse

FindingsFor = Callable[[str, str], list[Finding]]

# A trailing `# HERE` comment marks the line a finding must point at.
POSITIVE = {
    "GW001-inline": (
        "GW001",
        """
        on: issues
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.issue.title }}"  # HERE
        """,
    ),
    "GW001-block-script": (
        "GW001",
        """
        on: issue_comment
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo start
                  echo "${{ github.event.comment.body }}"  # HERE
                  echo "${{ github.head_ref }}"  # HERE
        """,
    ),
    "GW001-github-script": (
        "GW001",
        """
        on: pull_request
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/github-script@v7
                with:
                  script: |
                    console.log("${{ github.event.pull_request.head.ref }}")  # HERE
        """,
    ),
    "GW001-bracket-syntax": (
        "GW001",
        """
        on: push
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.commits[0].message }}"  # HERE
        """,
    ),
    "GW002-pull-request-target": (
        "GW002",
        """
        on: pull_request_target
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}  # HERE
        """,
    ),
    "GW002-workflow-run": (
        "GW002",
        """
        on:
          workflow_run:
            workflows: [CI]
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.workflow_run.head_branch }}  # HERE
        """,
    ),
    "GW003-tag": (
        "GW003",
        """
        on: push
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: some-org/some-action@v1  # HERE
        """,
    ),
    "GW003-docker-without-digest": (
        "GW003",
        """
        on: push
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: docker://alpine:3.20  # HERE
        """,
    ),
    "GW003-reusable-workflow": (
        "GW003",
        """
        on: push
        jobs:
          j:
            uses: some-org/repo/.github/workflows/ci.yml@main  # HERE
        """,
    ),
    "GW004-write-all": (
        "GW004",
        """
        on: push
        permissions: write-all  # HERE
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: echo hi
        """,
    ),
    "GW004-missing": (
        "GW004",
        """
        on: push
        jobs:
          j:  # HERE
            runs-on: ubuntu-latest
            steps:
              - run: echo hi
        """,
    ),
    "GW005": (
        "GW005",
        """
        on: push
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4  # HERE
        """,
    ),
    "GW006": (
        "GW006",
        """
        on: push
        jobs:
          j:
            uses: ./.github/workflows/reusable.yml
            secrets: inherit  # HERE
        """,
    ),
    "GW007": (
        "GW007",
        """
        on: pull_request
        jobs:
          j:
            runs-on: [self-hosted, linux]  # HERE
            steps:
              - run: echo hi
        """,
    ),
    "GW008-job-env": (
        "GW008",
        """
        on: push
        jobs:
          j:
            runs-on: ubuntu-latest
            env:
              ACTIONS_ALLOW_UNSECURE_COMMANDS: true  # HERE
            steps:
              - run: echo hi
        """,
    ),
    "GW008-workflow-env": (
        "GW008",
        """
        on: push
        env:
          ACTIONS_ALLOW_UNSECURE_COMMANDS: "true"  # HERE
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: echo hi
        """,
    ),
    "GW009-curl": (
        "GW009",
        """
        on: push
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo before
                  curl -fsSL https://example.invalid/install.sh | sudo bash  # HERE
        """,
    ),
    "GW009-wget": (
        "GW009",
        """
        on: push
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: wget -qO- https://example.invalid/install.sh | sh  # HERE
        """,
    ),
    "GW009-variants": (
        "GW009",
        """
        on: push
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  curl -fsSL https://example.invalid/i.sh | /bin/bash  # HERE
                  curl https://example.invalid/i.sh | tee i.sh | sh  # HERE
                  eval "$(curl -fsSL https://example.invalid/i.sh)"  # HERE
                  eval "$(wget -qO- https://example.invalid/i.sh)"  # HERE
                  curl -fsSL https://example.invalid/i.sh | sudo bash  # HERE
                  curl -fsSL https://example.invalid/i.sh | bash -s --  # HERE
        """,
    ),
    "GW010-env": (
        "GW010",
        """
        on: push
        jobs:
          j:
            runs-on: ubuntu-latest
            env:
              DB_PASSWORD: hunter2-not-real  # HERE
            steps:
              - run: echo hi
        """,
    ),
    "GW010-with": (
        "GW010",
        """
        on: push
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: some-org/deploy@v1
                with:
                  api_key: not-a-real-key-123  # HERE
        """,
    ),
}

NEGATIVE = {
    "GW001-safe-contexts": (
        "GW001",
        """
        on: pull_request
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.pull_request.number }} ${{ github.sha }}"
              - run: deploy --token "${{ secrets.DEPLOY_TOKEN }}"
        """,
    ),
    "GW001-env-indirection": (
        "GW001",
        """
        on: issues
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TITLE: ${{ github.event.issue.title }}
                run: echo "$TITLE"
        """,
    ),
    "GW001-boolean-call": (
        "GW001",
        """
        on: issues
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ contains(github.event.issue.title, 'bug') }}"
        """,
    ),
    "GW002-no-ref": (
        "GW002",
        """
        on: pull_request_target
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        """,
    ),
    "GW002-unprivileged-trigger": (
        "GW002",
        """
        on: pull_request
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
        """,
    ),
    "GW003-pinned-and-local": (
        "GW003",
        """
        on: push
        jobs:
          j:
            uses: ./.github/workflows/reusable.yml
          k:
            runs-on: ubuntu-latest
            steps:
              - uses: ./local-action
              - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567  # v4
              - uses: docker://alpine@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        """,
    ),
    "GW004-explicit": (
        "GW004",
        """
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            permissions: {contents: read}
            steps:
              - run: echo hi
          b:
            runs-on: ubuntu-latest
            permissions: read-all
            steps:
              - run: echo hi
        """,
    ),
    "GW004-top-level": (
        "GW004",
        """
        on: push
        permissions:
          contents: read
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: echo hi
        """,
    ),
    "GW005": (
        "GW005",
        """
        on: push
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  persist-credentials: false
        """,
    ),
    "GW006": (
        "GW006",
        """
        on: push
        jobs:
          j:
            uses: ./.github/workflows/reusable.yml
            secrets:
              TOKEN: ${{ secrets.TOKEN }}
        """,
    ),
    "GW007-hosted-runner": (
        "GW007",
        """
        on: pull_request
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: echo hi
        """,
    ),
    "GW007-trusted-trigger": (
        "GW007",
        """
        on: push
        jobs:
          j:
            runs-on: self-hosted
            steps:
              - run: echo hi
        """,
    ),
    "GW008": (
        "GW008",
        """
        on: push
        env:
          ACTIONS_ALLOW_UNSECURE_COMMANDS: false
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: echo hi
        """,
    ),
    "GW009-safe-pipes": (
        "GW009",
        """
        on: push
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  curl -fsSL https://example.invalid/data.json | jq .name
                  curl -fsSLo install.sh https://example.invalid/install.sh
                  # curl https://example.invalid/x.sh | bash
                  echo done | shellcheck -
                  curl -fsSL https://example.invalid/data.json | grep name
                  curl -fsSL https://example.invalid/i.sh | tee i.sh
                  curl -fsSL https://example.invalid/i.sh | tee i.sh | grep -c echo
                  eval "$(ssh-agent -s)"
        """,
    ),
    "GW010-expressions": (
        "GW010",
        """
        on: push
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: some-org/deploy@v1
                with:
                  password: ${{ secrets.DEPLOY_PASSWORD }}
                  token-file: ./token.txt
                  persist-credentials: "false"
        """,
    ),
}


def _marked_lines(text: str) -> list[int]:
    lines = textwrap.dedent(text).lstrip("\n").splitlines()
    return [number for number, line in enumerate(lines, start=1) if line.endswith("# HERE")]


@pytest.mark.parametrize(("rule_id", "text"), POSITIVE.values(), ids=POSITIVE.keys())
def test_rule_flags_at_marked_line(findings_for: FindingsFor, rule_id: str, text: str) -> None:
    found = findings_for(rule_id, text)
    assert [f.line for f in found] == _marked_lines(text)
    assert all(f.column >= 1 and f.remediation and f.message for f in found)


@pytest.mark.parametrize(("rule_id", "text"), NEGATIVE.values(), ids=NEGATIVE.keys())
def test_rule_stays_quiet(findings_for: FindingsFor, rule_id: str, text: str) -> None:
    assert findings_for(rule_id, text) == []


def test_every_rule_has_cases() -> None:
    from gha_warden.rules import ALL_RULES

    # Later rules keep their cases in their own test modules.
    covered_here = {f"GW{n:03d}" for n in range(1, 11)}
    assert covered_here <= {rule.id for rule in ALL_RULES}
    assert covered_here <= {case[0] for case in POSITIVE.values()}
    assert covered_here <= {case[0] for case in NEGATIVE.values()}


def test_gw001_exact_line_and_column(findings_for: FindingsFor) -> None:
    text = """\
name: t
on: issues
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo one
          echo "${{ github.event.issue.body }}"
"""
    (finding,) = findings_for("GW001", text)
    assert (finding.line, finding.column) == (9, 11)
    assert finding.severity is Severity.CRITICAL
    assert "github.event.issue.body" in finding.message


def test_gw003_exact_line_and_severity(findings_for: FindingsFor) -> None:
    text = """\
name: t
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: third party
        uses: evil-corp/thing@main
"""
    first, second = findings_for("GW003", text)
    assert (first.line, first.severity) == (7, Severity.MEDIUM)
    assert (second.line, second.column, second.severity) == (9, 15, Severity.HIGH)


def test_bare_on_key_is_normalized_to_triggers() -> None:
    workflow = parse("on:\n  push:\n  pull_request_target:\njobs: {}\n")
    assert workflow.triggers == {"push", "pull_request_target"}
    assert parse("on: [push, workflow_dispatch]\n").triggers == {"push", "workflow_dispatch"}


def test_composite_action_steps_are_checked(findings_for: FindingsFor) -> None:
    text = """\
name: composite
runs:
  using: composite
  steps:
    - uses: some-org/thing@v1
      shell: bash
"""
    (finding,) = findings_for("GW003", text)
    assert finding.line == 5
