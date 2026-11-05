"""GW015 (entire secrets context exposed) and GW016 (secret interpolated into a run script)."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from gha_warden.models import Finding, Severity

FindingsFor = Callable[[str, str], list[Finding]]


def lines_of(findings: list[Finding]) -> list[int]:
    return [finding.line for finding in findings]


def test_gw015_whole_context_in_env_and_with(findings_for: FindingsFor) -> None:
    text = """\
name: t
on: push
env:
  ALL: ${{ toJSON(secrets) }}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/tool@v1
        with:
          creds: ${{ secrets }}
"""
    first, second = findings_for("GW015", text)
    assert (first.line, first.column, first.severity) == (4, 8, Severity.HIGH)
    assert second.line == 11
    assert "whole 'secrets' context" in first.message


@pytest.mark.parametrize(
    "expression",
    [
        "secrets[matrix.name]",
        "secrets[format('{0}_TOKEN', inputs.env)]",
        "SECRETS[ inputs.name ]",
    ],
)
def test_gw015_dynamic_index(findings_for: FindingsFor, expression: str) -> None:
    text = f"""\
name: t
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
        env:
          TOKEN: ${{{{ {expression} }}}}
"""
    (finding,) = findings_for("GW015", text)
    assert finding.line == 9
    assert "dynamic index" in finding.message


def test_gw015_reports_exact_script_line(findings_for: FindingsFor) -> None:
    text = """\
name: t
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            const a = 1;
            const all = ${{ toJSON(secrets) }};
"""
    (finding,) = findings_for("GW015", text)
    assert (finding.line, finding.column) == (11, 13)


def test_gw015_tojson_github_event_in_run(findings_for: FindingsFor) -> None:
    text = """\
name: t
on: issues
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo start
          echo '${{ toJSON(github.event) }}'
          echo '${{ toJSON( github ) }}'
"""
    first, second = findings_for("GW015", text)
    assert (first.line, second.line) == (9, 10)
    assert first.message.startswith("toJSON(github.event) pastes")
    assert second.message.startswith("toJSON(github) pastes")


def test_gw015_tojson_github_event_in_env_is_the_safe_pattern(findings_for: FindingsFor) -> None:
    text = """\
name: t
on: issues
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "$EVENT" | jq .action
        env:
          EVENT: ${{ toJSON(github.event) }}
"""
    assert findings_for("GW015", text) == []


@pytest.mark.parametrize(
    "expression",
    [
        "secrets.NPM_TOKEN",
        "secrets['NPM_TOKEN']",
        "secrets.NPM_TOKEN || secrets.FALLBACK",
        "toJSON(secrets.NPM_TOKEN)",
        "format('{0}', 'toJSON(secrets) and secrets[x]')",
        "github.event.repository.secrets",
        "inputs.secrets",
        "vars.secrets_name",
        "toJSON(github.event_name)",
        "toJSON(github.event.issue.number)",
    ],
)
def test_gw015_named_secrets_and_lookalikes_are_fine(
    findings_for: FindingsFor, expression: str
) -> None:
    text = f"""\
name: t
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "$VALUE"
        env:
          VALUE: ${{{{ {expression} }}}}
"""
    assert findings_for("GW015", text) == []


def test_gw015_secrets_inherit_is_left_to_gw006(findings_for: FindingsFor) -> None:
    text = """\
name: t
on: push
jobs:
  call:
    uses: some-org/shared/.github/workflows/x.yml@main
    secrets: inherit
"""
    assert findings_for("GW015", text) == []


def test_gw016_exact_line_in_block_script(findings_for: FindingsFor) -> None:
    text = """\
name: t
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo start
          curl -H "Authorization: Bearer ${{ secrets.API_TOKEN }}" https://example.invalid
          gh api /user --header "x: ${{ github.token }}"
"""
    first, second = findings_for("GW016", text)
    assert (first.line, first.column, first.severity) == (9, 11, Severity.LOW)
    assert "secrets.API_TOKEN" in first.message
    assert (second.line, "github.token" in second.message) == (10, True)


def test_gw016_inline_run_and_bracket_syntax(findings_for: FindingsFor) -> None:
    text = """\
name: t
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ secrets['API_TOKEN'] }}"
      - run: echo "${{ SECRETS.other-token }} ${{ secrets.A }}"
"""
    findings = findings_for("GW016", text)
    assert lines_of(findings) == [7, 8, 8]
    assert "secrets.API_TOKEN" in findings[0].message


def test_gw016_one_finding_per_secret_per_line(findings_for: FindingsFor) -> None:
    text = """\
name: t
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ secrets.A }}${{ secrets.A }}"
"""
    assert len(findings_for("GW016", text)) == 1


def test_gw016_composite_action_step(findings_for: FindingsFor) -> None:
    text = """\
name: composite
runs:
  using: composite
  steps:
    - run: echo "${{ github.token }}"
      shell: bash
"""
    (finding,) = findings_for("GW016", text)
    assert finding.line == 5


def test_gw016_env_and_with_are_the_safe_pattern(findings_for: FindingsFor) -> None:
    text = """\
name: t
on: push
env:
  TOP: ${{ secrets.TOP }}
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      JOB: ${{ github.token }}
    steps:
      - run: curl --oauth2-bearer "$STEP" https://example.invalid
        env:
          STEP: ${{ secrets.STEP }}
      - uses: actions/github-script@v7
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          script: console.log(process.env.TOP)
"""
    assert findings_for("GW016", text) == []


@pytest.mark.parametrize(
    "script",
    [
        'echo "${{ github.event.pull_request.number }}"',
        'echo "${{ vars.NAME }} ${{ inputs.token }}"',
        "if [ \"${{ secrets.TOKEN != '' }}\" = true ]; then echo set; fi",
        "echo \"${{ secrets.TOKEN == '' }}\"",
        "echo \"${{ contains(secrets.TOKEN, 'abc') }}\"",
        "echo \"${{ format('{0}', 'secrets.TOKEN github.token') }}\"",
        'echo "secrets.TOKEN and github.token are not expressions"',
        'echo "${{ steps.token.outputs.value }} ${{ github.token_expires }}"',
        'echo "${{ x.github.token }}"',
    ],
)
def test_gw016_non_secret_expressions_are_fine(findings_for: FindingsFor, script: str) -> None:
    text = f"""\
name: t
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          {script}
"""
    assert findings_for("GW016", text) == []


def test_gw016_ignores_dynamic_index_left_to_gw015(findings_for: FindingsFor) -> None:
    text = """\
name: t
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ secrets[matrix.name] }}"
"""
    assert findings_for("GW016", text) == []
    assert lines_of(findings_for("GW015", text)) == [7]
