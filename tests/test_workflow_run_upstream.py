"""Cross-workflow analysis: a `workflow_run` workflow whose upstream workflows are all known."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from gha_warden.cli import main
from gha_warden.models import Finding
from gha_warden.scan import scan_workflow
from gha_warden.workflow import Workflow, link_workflows

PUBLISH = """
name: Publish
on:
  workflow_run:
    workflows: [Release]
    types: [completed]
jobs:
  publish:
    if: github.actor == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.workflow_run.head_sha }}
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: npm
      - uses: actions/download-artifact@v4
        with:
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
      - run: cat out/env.txt >> "$GITHUB_ENV"
"""
RULES = ("GW002", "GW011", "GW012", "GW017")
JOBS = "jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"


def workflow(name: str, text: str) -> Workflow:
    return Workflow(f".github/workflows/{name}", textwrap.dedent(text).lstrip("\n"))


def release(on: str, name: str = "Release") -> Workflow:
    header = f"name: {name}\n" if name else ""
    return workflow(f"{name or 'unnamed'}.yml", f"{header}on:\n{on}\n{JOBS}")


def rules_hit(*workflows: Workflow) -> set[str]:
    link_workflows(workflows)
    findings: list[Finding] = scan_workflow(workflows[-1])
    return {f.rule_id for f in findings} & set(RULES)


def publish(workflows_line: str = "[Release]") -> Workflow:
    return workflow("publish.yml", PUBLISH.replace("[Release]", workflows_line))


def test_upstream_without_untrusted_trigger_is_not_exploitable() -> None:
    upstream = release("  push:\n    branches: [master]\n  workflow_dispatch:")
    assert rules_hit(upstream, publish()) == set()


@pytest.mark.parametrize("trigger", ["pull_request", "pull_request_target", "issues", "watch"])
def test_upstream_with_untrusted_trigger_is_reported(trigger: str) -> None:
    upstream = release(f"  push:\n  {trigger}:")
    assert rules_hit(upstream, publish()) == set(RULES)


def test_missing_upstream_keeps_the_report() -> None:
    assert rules_hit(publish()) == set(RULES)
    other = release("  push:", name="Other")
    assert rules_hit(other, publish()) == set(RULES)


def test_one_missing_upstream_among_several_keeps_the_report() -> None:
    upstream = release("  push:")
    assert rules_hit(upstream, publish("[Release, Missing]")) == set(RULES)


def test_glob_in_upstream_name_keeps_the_report() -> None:
    upstream = release("  push:", name="Release 1")
    assert rules_hit(upstream, publish("['Release *']")) == set(RULES)


def test_other_privileged_trigger_keeps_the_report() -> None:
    upstream = release("  push:")
    mixed = workflow(
        "publish.yml",
        PUBLISH.replace("workflow_run:", "pull_request_target:\n  workflow_run:"),
    )
    assert rules_hit(upstream, mixed) == set(RULES)


def test_unnamed_upstream_is_matched_by_its_file_path() -> None:
    upstream = release("  push:", name="")
    assert upstream.name == ".github/workflows/unnamed.yml"
    assert rules_hit(upstream, publish("[.github/workflows/unnamed.yml]")) == set()


def test_transitive_chain_is_safe_when_every_link_is_trusted() -> None:
    build = release("  push:", name="Build")
    release_wf = release("  workflow_run:\n    workflows: [Build]")
    assert rules_hit(build, release_wf, publish()) == set()


def test_transitive_chain_is_reported_when_a_distant_upstream_is_untrusted() -> None:
    build = release("  pull_request:", name="Build")
    release_wf = release("  workflow_run:\n    workflows: [Build]")
    assert rules_hit(build, release_wf, publish()) == set(RULES)


def test_transitive_chain_with_missing_link_is_reported() -> None:
    release_wf = release("  workflow_run:\n    workflows: [Build]")
    assert rules_hit(release_wf, publish()) == set(RULES)


def test_cycle_of_trusted_workflows_terminates_and_is_safe() -> None:
    release_wf = release("  push:\n  workflow_run:\n    workflows: [Publish]")
    assert rules_hit(release_wf, publish()) == set()


def test_cycle_that_reaches_an_untrusted_workflow_is_reported() -> None:
    release_wf = release("  workflow_run:\n    workflows: [Publish, Build]")
    build = release("  pull_request:", name="Build")
    assert rules_hit(build, release_wf, publish()) == set(RULES)


def test_cli_links_the_files_scanned_together(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True)
    (directory / "release.yml").write_text(
        f"name: Release\non:\n  push:\n{JOBS}", encoding="utf-8", newline="\n"
    )
    (directory / "publish.yml").write_text(PUBLISH.lstrip("\n"), encoding="utf-8", newline="\n")
    main(["--format", "json", str(directory)])
    both = json.loads(capsys.readouterr().out)
    main(["--format", "json", str(directory / "publish.yml")])
    alone = json.loads(capsys.readouterr().out)
    assert {f["rule_id"] for f in both["findings"]} & set(RULES) == set()
    assert {f["rule_id"] for f in alone["findings"]} >= set(RULES)
