"""GW011 (cache poisoning) and GW012 (artifact poisoning): positive, negative, exact lines."""

from __future__ import annotations

import textwrap
from collections.abc import Callable

import pytest

from gha_warden.models import Finding, Severity

FindingsFor = Callable[[str, str], list[Finding]]

# A trailing `# HERE` comment marks the line a finding must point at.
POSITIVE = {
    "GW011-actions-cache": (
        "GW011",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4  # HERE
                with:
                  path: ~/.npm
                  key: npm-${{ hashFiles('package-lock.json') }}
        """,
    ),
    "GW011-cache-restore-issue-comment": (
        "GW011",
        """
        on:
          issue_comment:
            types: [created]
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache/restore@v4  # HERE
                with:
                  path: build
                  key: build-fake
        """,
    ),
    "GW011-setup-actions": (
        "GW011",
        """
        on: pull_request_target
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/setup-node@v4  # HERE
                with:
                  cache: npm
              - uses: actions/setup-python@v5  # HERE
                with:
                  cache: pip
              - uses: actions/setup-java@v4  # HERE
                with:
                  cache: gradle
              - uses: astral-sh/setup-uv@v6  # HERE
                with:
                  enable-cache: true
        """,
    ),
    "GW011-setup-go-caches-by-default": (
        "GW011",
        """
        on: pull_request_target
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/setup-go@v5  # HERE
                with:
                  go-version: "1.23"
        """,
    ),
    "GW012-artifact-to-github-env": (
        "GW012",
        """
        on:
          workflow_run:
            workflows: [CI]
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4  # HERE
                with:
                  run-id: ${{ github.event.workflow_run.id }}
                  github-token: ${{ secrets.GITHUB_TOKEN }}
              - run: cat pr/env.txt >> "$GITHUB_ENV"
        """,
    ),
    "GW012-dawidd6-output-from-command-substitution": (
        "GW012",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: dawidd6/action-download-artifact@v6  # HERE
                with:
                  workflow: ci.yml
              - id: pr
                run: echo "number=$(cat pr-number.txt)" >> $GITHUB_OUTPUT
        """,
    ),
    "GW012-grep-not-digits-only": (
        "GW012",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4  # HERE
                with:
                  run-id: 1234
              - run: echo "NUMBER=$(grep -E '^[0-9]+' pr_number.txt)" >> "$GITHUB_OUTPUT"
        """,
    ),
    "GW012-gh-run-download-then-source": (
        "GW012",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  gh run download "$RUN_ID" --name result --dir out  # HERE
              - run: |
                  echo preparing
                  source out/env.sh
        """,
    ),
    "GW012-execute-downloaded-script": (
        "GW012",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4  # HERE
                with:
                  run-id: ${{ github.event.workflow_run.id }}
                  path: artifacts
              - run: bash artifacts/deploy.sh
        """,
    ),
    "GW012-build-in-artifact-dir": (
        "GW012",
        """
        on: pull_request_target
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4  # HERE
                with:
                  run-id: 1234
                  path: site
              - run: npm ci
                working-directory: site
        """,
    ),
    "GW012-cd-then-make": (
        "GW012",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4  # HERE
                with:
                  run-id: 1234
                  path: ./src-copy/
              - run: |
                  cd src-copy && make release
        """,
    ),
    "GW012-write-path-pwsh": (
        "GW012",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: windows-latest
            steps:
              - uses: dawidd6/action-download-artifact@v6  # HERE
                with:
                  name: tools
              - shell: pwsh
                run: Get-Content tools/path.txt | Out-File -Append $env:GITHUB_PATH
        """,
    ),
    "GW012-while-read-loop-from-artifact": (
        "GW012",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4  # HERE
                with:
                  run-id: 1234
                  path: artifact
              - run: |
                  while read -r line; do
                    echo "$line" >> "$GITHUB_ENV"
                  done < artifact/x
        """,
    ),
    "GW012-piped-loop-from-artifact": (
        "GW012",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4  # HERE
                with:
                  run-id: 1234
                  path: artifact
              - run: |
                  cat artifact/y | while read -r line; do
                    echo "$line" >> "$GITHUB_ENV"
                  done
        """,
    ),
    "GW012-variable-holds-artifact-path": (
        "GW012",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4  # HERE
                with:
                  run-id: 1234
                  path: artifact
              - run: |
                  F=artifact/env.txt
                  cat "$F" >> "$GITHUB_ENV"
        """,
    ),
    "GW012-env-from-download-path-output": (
        "GW012",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4  # HERE
                id: dl
                with:
                  run-id: 1234
                  path: ${{ runner.temp }}/pr
              - env:
                  INFO: ${{ steps.dl.outputs.download-path }}/info.json
                run: jq -r '.number' "$INFO" >> "$GITHUB_OUTPUT"
        """,
    ),
    "GW012-runner-temp-path": (
        "GW012",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4  # HERE
                with:
                  run-id: 1234
                  path: ${{ runner.temp }}/pr
              - run: echo "sha=$(cat "${RUNNER_TEMP}/pr/sha")" >> "$GITHUB_OUTPUT"
        """,
    ),
    "GW012-github-script-reads-artifact": (
        "GW012",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4  # HERE
                with:
                  run-id: 1234
                  path: artifact
              - uses: actions/github-script@v7
                with:
                  script: |
                    const fs = require('fs');
                    const body = fs.readFileSync('artifact/env.txt', 'utf8');
                    core.exportVariable('BODY', body);
        """,
    ),
    "GW012-source-after-root-download": (
        "GW012",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4  # HERE
                with:
                  run-id: 1234
                  name: artifact
              - run: source artifact/x.sh
          k:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4  # HERE
                with:
                  run-id: 1234
                  path: artifact
              - run: . ./artifact/x
        """,
    ),
    "GW012-same-step-gh-run-download": (
        "GW012",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  gh run download "$RUN_ID" -n pr -D pr  # HERE
                  echo "number=$(cat pr/number)" >> "$GITHUB_OUTPUT"
        """,
    ),
}

NEGATIVE = {
    "GW011-unprivileged-trigger": (
        "GW011",
        """
        on: [push, pull_request]
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with: {path: ~/.npm, key: k}
              - uses: actions/setup-node@v4
                with: {cache: npm}
        """,
    ),
    "GW011-no-restore": (
        "GW011",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache/save@v4
                with: {path: out, key: k}
              - uses: actions/setup-node@v4
                with:
                  node-version: 22
              - uses: actions/setup-python@v5
                with:
                  cache: ""
              - uses: actions/setup-go@v5
                with:
                  cache: false
              - uses: astral-sh/setup-uv@v6
                with:
                  enable-cache: false
              - uses: actions/checkout@v4
        """,
    ),
    "GW012-same-run-artifact": (
        "GW012",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4
                with:
                  name: local
              - run: cat local/env.txt >> "$GITHUB_ENV"
        """,
    ),
    "GW012-unprivileged-trigger": (
        "GW012",
        """
        on: pull_request
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: dawidd6/action-download-artifact@v6
                with: {workflow: ci.yml}
              - run: cat pr.txt >> "$GITHUB_ENV"
        """,
    ),
    "GW012-data-only-use": (
        "GW012",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4
                with:
                  run-id: 1234
                  path: artifacts
              - run: |
                  cat artifacts/report.txt
                  jq .total artifacts/summary.json
                  echo "sha=${{ github.event.workflow_run.head_sha }}" >> "$GITHUB_OUTPUT"
                  cat <<EOF >> "$GITHUB_ENV"
                  MODE=fixed
                  EOF
                  echo "$MESSAGE" | grep -c error >> "$GITHUB_OUTPUT"
                  ./scripts/notify.sh
                  make -C tools lint
        """,
    ),
    "GW012-grep-digits-only-line": (
        "GW012",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4
                with:
                  run-id: 1234
              - run: echo "NUMBER=$(grep -E '^[0-9]+$' pr_number.txt || true)" >> "$GITHUB_OUTPUT"
        """,
    ),
    "GW012-validated-and-before-download": (
        "GW012",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: cat VERSION >> "$GITHUB_ENV"
              - uses: actions/download-artifact@v4
                with:
                  run-id: 1234
                  path: artifacts
              - run: echo "pr=$(tr -cd '0-9' < artifacts/pr-number)" >> "$GITHUB_OUTPUT"
              - run: ./other-dir/build.sh
              - run: |
                  cd tools
                  make
        """,
    ),
    "GW012-file-made-by-the-job": (
        "GW012",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - run: gh run download "$RUN_ID" --name request --dir request
              - run: ./build.sh --out data.json
              - run: |
                  { printf 'data='; cat data.json; } >> "$GITHUB_OUTPUT"
                  F=out/list.txt
                  while read -r line; do
                    echo "$line" >> "$GITHUB_ENV"
                  done < "$F"
                  echo "n=$(tr -cd '0-9' < request/number)" >> "$GITHUB_OUTPUT"
        """,
    ),
    "GW012-github-script-validated-or-other-file": (
        "GW012",
        """
        on: workflow_run
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/download-artifact@v4
                with:
                  run-id: 1234
                  path: artifact
              - uses: actions/github-script@v7
                with:
                  script: |
                    const fs = require('fs');
                    const pr = Number(fs.readFileSync('artifact/pr', 'utf8'));
                    core.setOutput('pr', pr);
              - uses: actions/github-script@v7
                with:
                  script: |
                    const fs = require('fs');
                    core.setOutput('v', fs.readFileSync('VERSION', 'utf8'));
        """,
    ),
}


def _marked_lines(text: str) -> list[int]:
    lines = textwrap.dedent(text).lstrip("\n").splitlines()
    return [number for number, line in enumerate(lines, start=1) if "# HERE" in line]


@pytest.mark.parametrize(("rule_id", "text"), POSITIVE.values(), ids=POSITIVE.keys())
def test_rule_flags_at_marked_line(findings_for: FindingsFor, rule_id: str, text: str) -> None:
    found = findings_for(rule_id, text)
    assert [f.line for f in found] == _marked_lines(text)
    assert all(f.column >= 1 and f.remediation and f.message for f in found)


@pytest.mark.parametrize(("rule_id", "text"), NEGATIVE.values(), ids=NEGATIVE.keys())
def test_rule_stays_quiet(findings_for: FindingsFor, rule_id: str, text: str) -> None:
    assert findings_for(rule_id, text) == []


def test_every_new_rule_has_cases() -> None:
    ids = {"GW011", "GW012"}
    assert ids == {case[0] for case in POSITIVE.values()}
    assert ids == {case[0] for case in NEGATIVE.values()}


def test_gw011_line_column_severity_and_message(findings_for: FindingsFor) -> None:
    text = """\
name: t
on:
  workflow_run:
    workflows: [CI]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: restore
        uses: actions/cache@v4
        with:
          path: ~/.npm
          key: k
"""
    (finding,) = findings_for("GW011", text)
    assert (finding.line, finding.column, finding.severity) == (10, 15, Severity.MEDIUM)
    assert "workflow_run" in finding.message


def test_gw012_reports_download_line_and_names_the_unsafe_step(
    findings_for: FindingsFor,
) -> None:
    text = """\
name: t
on: workflow_run
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          run-id: 1
      - run: echo ok
      - run: cat data.txt >> "$GITHUB_ENV"
"""
    (finding,) = findings_for("GW012", text)
    assert (finding.line, finding.column, finding.severity) == (7, 15, Severity.HIGH)
    assert "GITHUB_ENV" in finding.message
    assert "line 11" in finding.message


def test_gw012_only_looks_at_steps_of_the_same_job(findings_for: FindingsFor) -> None:
    text = """\
name: t
on: workflow_run
jobs:
  download:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          run-id: 1
  other:
    runs-on: ubuntu-latest
    steps:
      - run: cat data.txt >> "$GITHUB_ENV"
"""
    assert findings_for("GW012", text) == []
