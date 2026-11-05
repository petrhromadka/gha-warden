"""GW002 on issue_comment and run-step PR checkouts, and GW017 spoofable actor checks."""

from __future__ import annotations

import textwrap
from collections.abc import Callable

import pytest

from gha_warden.models import Finding, Severity

FindingsFor = Callable[[str, str], list[Finding]]

# A trailing `# HERE` comment marks the line a finding must point at.
POSITIVE = {
    "GW002-issue-comment-refs-pull": (
        "GW002",
        """
        on: issue_comment
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: refs/pull/${{ github.event.issue.number }}/head  # HERE
        """,
    ),
    "GW002-issue-comment-step-output": (
        "GW002",
        """
        on: issue_comment
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - id: pr
                uses: xt0rted/pull-request-comment-branch@v3
              - uses: actions/checkout@v4
                with:
                  ref: ${{ steps.pr.outputs.head_sha }}  # HERE
        """,
    ),
    "GW002-issue-comment-github-script-output": (
        "GW002",
        """
        on: issue_comment
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - id: pr
                uses: actions/github-script@v7
                with:
                  script: |
                    const { data } = await github.rest.pulls.get({ pull_number: 1 })
                    core.setOutput("sha", data.head.sha)
              - uses: actions/checkout@v4
                with:
                  ref: ${{ steps.pr.outputs.sha }}  # HERE
        """,
    ),
    "GW002-run-gh-pr-checkout": (
        "GW002",
        """
        on: issue_comment
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo start
                  gh pr checkout ${{ github.event.issue.number }}  # HERE
        """,
    ),
    "GW002-run-git-fetch-pull": (
        "GW002",
        """
        on: pull_request_target
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: git fetch origin pull/${{ github.event.number }}/head:pr  # HERE
        """,
    ),
    "GW002-run-git-checkout-head-sha": (
        "GW002",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: git checkout ${{ github.event.workflow_run.head_sha }}  # HERE
        """,
    ),
    "GW002-run-git-checkout-pr-head-sha": (
        "GW002",
        """
        on: pull_request_target
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: git checkout ${{ github.event.pull_request.head.sha }}  # HERE
        """,
    ),
    "GW002-run-git-C-fetch-pull": (
        "GW002",
        """
        on: pull_request_target
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: git -C src fetch origin refs/pull/7/merge  # HERE
        """,
    ),
    "GW002-run-git-c-option-fetch-pull": (
        "GW002",
        """
        on: pull_request_target
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: git -c protocol.version=2 fetch origin pull/7/head  # HERE
        """,
    ),
    "GW002-run-git-dir-option-checkout": (
        "GW002",
        """
        on: pull_request_target
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: git --git-dir .git --work-tree "my dir" checkout ${{ github.head_ref }}  # HERE
        """,
    ),
    "GW002-run-fetch-head-repo-continued": (
        "GW002",
        """
        on: pull_request_target
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  git fetch --depth=1 \\
                    ${{ github.event.pull_request.head.repo.clone_url }} \\
                    ${{ github.event.pull_request.head.sha }}
        """,
    ),
    "GW017-job-dependabot": (
        "GW017",
        """
        on: pull_request_target
        jobs:
          j:
            runs-on: ubuntu-latest
            if: github.actor == 'dependabot[bot]'  # HERE
            steps:
              - run: gh pr merge --auto "$PR_URL"
        """,
    ),
    "GW017-wrapped-or": (
        "GW017",
        """
        on: pull_request_target
        jobs:
          j:
            runs-on: ubuntu-latest
            if: ${{ github.actor == 'dependabot[bot]' || github.actor == 'renovate[bot]' }}  # HERE
            steps:
              - run: echo ok
        """,
    ),
    "GW017-step-reversed": (
        "GW017",
        """
        on: issue_comment
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: echo ok
                if: "'dependabot[bot]' == github.actor"  # HERE
        """,
    ),
    "GW017-triggering-actor": (
        "GW017",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            if: github.triggering_actor == 'dependabot[bot]'  # HERE
            steps:
              - run: echo ok
        """,
    ),
    "GW017-folded-condition": (
        "GW017",
        """
        on: pull_request_target
        jobs:
          j:
            runs-on: ubuntu-latest
            if: >
              github.repository_owner == 'example-org' &&
              startsWith(github.actor, 'dependabot')
            steps:
              - run: echo ok
        """,
    ),
}

NEGATIVE = {
    "GW002-issue-comment-no-ref": (
        "GW002",
        """
        on: issue_comment
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: gh issue comment ${{ github.event.issue.number }} --body hi
        """,
    ),
    "GW002-unrelated-step-output": (
        "GW002",
        """
        on: issue_comment
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - id: v
                run: echo "tag=v1" >> "$GITHUB_OUTPUT"
              - uses: actions/checkout@v4
                with:
                  ref: ${{ steps.v.outputs.tag }}
        """,
    ),
    "GW002-run-in-unprivileged-trigger": (
        "GW002",
        """
        on: pull_request
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: gh pr checkout 1
              - run: git checkout ${{ github.event.pull_request.head.sha }}
        """,
    ),
    "GW002-run-comment-and-plain-git": (
        "GW002",
        """
        on: issue_comment
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  # gh pr checkout 1
                  git fetch origin main
                  git pull --rebase origin main
                  git checkout main
        """,
    ),
    "GW002-run-pull-branch-name-from-origin": (
        "GW002",
        """
        on: pull_request_target
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: git pull origin ${{ github.head_ref || github.ref }}
        """,
    ),
    "GW002-run-git-C-fetch-branch": (
        "GW002",
        """
        on: pull_request_target
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: git -C src fetch origin main
        """,
    ),
    "GW017-actor-and-label-named-like-a-bot": (
        "GW017",
        """
        on: pull_request_target
        jobs:
          j:
            runs-on: ubuntu-latest
            if: >-
              github.actor == 'octocat' &&
              contains(github.event.pull_request.labels.*.name, 'renovate')
            steps:
              - run: echo ok
        """,
    ),
    "GW017-pr-author": (
        "GW017",
        """
        on: pull_request_target
        jobs:
          j:
            runs-on: ubuntu-latest
            if: github.event.pull_request.user.login == 'dependabot[bot]'
            steps:
              - run: echo ok
        """,
    ),
    "GW017-unprivileged-trigger": (
        "GW017",
        """
        on: pull_request
        jobs:
          j:
            runs-on: ubuntu-latest
            if: github.actor == 'dependabot[bot]'
            steps:
              - run: echo ok
        """,
    ),
    "GW017-actor-not-equal-and-human": (
        "GW017",
        """
        on: issue_comment
        jobs:
          j:
            runs-on: ubuntu-latest
            if: github.actor != 'dependabot[bot]'
            steps:
              - run: echo ok
                if: github.actor == 'octocat'
        """,
    ),
}


def _marked_lines(text: str) -> list[int]:
    lines = textwrap.dedent(text).lstrip("\n").splitlines()
    return [number for number, line in enumerate(lines, start=1) if line.endswith("# HERE")]


@pytest.mark.parametrize(("rule_id", "text"), POSITIVE.values(), ids=POSITIVE.keys())
def test_rule_flags(findings_for: FindingsFor, rule_id: str, text: str) -> None:
    found = findings_for(rule_id, text)
    marked = _marked_lines(text)
    if marked:
        assert [f.line for f in found] == marked
    else:
        assert len(found) == 1
    assert all(f.column >= 1 and f.remediation and f.message for f in found)


@pytest.mark.parametrize(("rule_id", "text"), NEGATIVE.values(), ids=NEGATIVE.keys())
def test_rule_stays_quiet(findings_for: FindingsFor, rule_id: str, text: str) -> None:
    assert findings_for(rule_id, text) == []


def test_gw017_severity_and_message(findings_for: FindingsFor) -> None:
    (finding,) = findings_for("GW017", POSITIVE["GW017-job-dependabot"][1])
    assert finding.severity is Severity.HIGH
    assert "github.actor" in finding.message
    assert "pull_request_target" in finding.message
    assert "pull_request.user.login" in finding.remediation
