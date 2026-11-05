"""CLI behavior: exit codes, filters, suppression and output formats."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from gha_warden.cli import main
from gha_warden.rules import ALL_RULES
from tests.conftest import VULNERABLE

WriteWorkflow = Callable[..., Path]

CLEAN = """
    name: clean
    on: push
    permissions:
      contents: read
    jobs:
      j:
        runs-on: ubuntu-latest
        steps:
          - run: echo hi
"""


def run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    code = main([*args])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_clean_workflow_exits_zero(
    write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = run(capsys, str(write_workflow(CLEAN)))
    assert code == 0
    assert "No findings in 1 file" in out


def test_findings_exit_one_and_text_report(
    write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_workflow(VULNERABLE)
    code, out, _ = run(capsys, "--no-color", str(path))
    assert code == 1
    assert "GW001" in out
    assert "\033[" not in out
    assert out.rstrip().splitlines()[-1].startswith("5 findings (")


def test_directory_is_scanned_recursively(
    write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str]
) -> None:
    write_workflow(VULNERABLE, "nested/a.yaml")
    write_workflow(CLEAN, "b.yml")
    write_workflow("not: a workflow file", "notes.txt")
    path = write_workflow(CLEAN, "c.yml").parent
    code, out, _ = run(capsys, "--format", "json", str(path))
    document = json.loads(out)
    assert code == 1
    assert document["summary"]["files_scanned"] == 3
    assert {f["path"].rsplit("/", 1)[-1] for f in document["findings"]} == {"a.yaml"}


def test_json_format(write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "--format", "json", str(write_workflow(VULNERABLE)))
    document = json.loads(out)
    assert code == 1
    assert document["summary"]["total"] == len(document["findings"]) == 5
    assert document["summary"]["by_severity"] == {"critical": 1, "high": 1, "medium": 2, "low": 1}
    first = document["findings"][0]
    assert set(first) == {
        "rule_id",
        "severity",
        "message",
        "path",
        "line",
        "column",
        "remediation",
    }


def test_sarif_format(write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "--format", "sarif", str(write_workflow(VULNERABLE)))
    sarif = json.loads(out)
    assert code == 1
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    (sarif_run,) = sarif["runs"]
    driver = sarif_run["tool"]["driver"]
    assert driver["name"] == "gha-warden"
    rules = {rule["id"]: rule for rule in driver["rules"]}
    assert sorted(rules) == sorted(rule.id for rule in ALL_RULES)
    assert rules["GW001"]["properties"]["security-severity"] == "9.5"
    assert rules["GW005"]["properties"]["security-severity"] == "3.0"
    assert rules["GW001"]["help"]["text"]
    levels = {"error", "warning", "note"}
    assert sarif_run["results"]
    for result in sarif_run["results"]:
        assert result["ruleId"] in rules
        assert driver["rules"][result["ruleIndex"]]["id"] == result["ruleId"]
        assert result["level"] in levels
        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"].endswith("wf.yml")
        assert location["region"]["startLine"] >= 1


def test_sarif_keeps_per_finding_severity_in_result_level(
    write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str]
) -> None:
    _, out, _ = run(capsys, "--format", "sarif", str(write_workflow(VULNERABLE)))
    results = json.loads(out)["runs"][0]["results"]
    # GitHub reads `security-severity` from the rule only, so results must not carry one.
    assert all("security-severity" not in result.get("properties", {}) for result in results)
    gw003 = sorted(
        (r["locations"][0]["physicalLocation"]["region"]["startLine"], r["level"])
        for r in results
        if r["ruleId"] == "GW003"
    )
    assert gw003 == [(7, "warning"), (8, "error")]


def test_sarif_without_findings_is_valid(
    write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = run(capsys, "--format", "sarif", str(write_workflow(CLEAN)))
    sarif = json.loads(out)
    assert code == 0
    assert sarif["runs"][0]["results"] == []
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == len(ALL_RULES)


def test_min_severity_filters_findings(
    write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str]
) -> None:
    path = str(write_workflow(VULNERABLE))
    _, out, _ = run(capsys, "--format", "json", "--min-severity", "high", path)
    assert {f["severity"] for f in json.loads(out)["findings"]} == {"critical", "high"}
    code, out, _ = run(capsys, "--format", "json", "--min-severity", "critical", path)
    assert [f["rule_id"] for f in json.loads(out)["findings"]] == ["GW001"]
    assert code == 1


def test_min_severity_can_make_the_run_clean(
    write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_workflow("on: push\njobs:\n  j:\n    uses: ./r.yml\n    secrets: inherit\n")
    assert run(capsys, "--min-severity", "high", str(path))[0] == 0
    assert run(capsys, "--min-severity", "medium", str(path))[0] == 1


def test_ignore_rules(write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str]) -> None:
    path = str(write_workflow(VULNERABLE))
    _, out, _ = run(capsys, "--format", "json", "--ignore", "GW001", "--ignore", "gw005", path)
    ids = {f["rule_id"] for f in json.loads(out)["findings"]}
    assert ids.isdisjoint({"GW001", "GW005"})
    assert ids
    code, out, _ = run(capsys, "--ignore", "GW001,GW003,GW004,GW005", path)
    assert code == 0
    assert "No findings" in out


def test_unknown_ignore_id_is_a_usage_error(
    write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--ignore", "GW999", str(write_workflow(CLEAN))])
    assert excinfo.value.code == 2
    assert "unknown rule id 'GW999'" in capsys.readouterr().err


def test_inline_suppression(
    write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str]
) -> None:
    text = """
        on: push
        permissions: read-all
        jobs:
          j:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4  # gha-warden: ignore[GW003]
              - uses: other/one@v1  # gha-warden: ignore
              - uses: other/two@v1  # gha-warden: ignore[GW005]
              - uses: other/three@v1
    """
    _, out, _ = run(capsys, "--format", "json", str(write_workflow(text)))
    flagged = [(f["rule_id"], f["line"]) for f in json.loads(out)["findings"]]
    assert sorted(flagged) == [("GW003", 9), ("GW003", 10), ("GW005", 7)]


def test_malformed_yaml_exits_two_without_traceback(
    write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_workflow("on: push\njobs:\n  j: [unclosed\n    runs-on: x\n", "broken.yml")
    code, _, err = run(capsys, str(path))
    assert code == 2
    assert "Traceback" not in err
    assert err.startswith("gha-warden: error: ")
    assert "broken.yml: invalid YAML at line" in err


def test_non_mapping_document_exits_two(
    write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _, err = run(capsys, str(write_workflow("- just\n- a list\n")))
    assert code == 2
    assert "expected a mapping at the top level" in err


def test_one_bad_file_does_not_hide_findings_in_others(
    write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str]
) -> None:
    write_workflow("a: [", "bad.yml")
    path = write_workflow(VULNERABLE, "good.yml").parent
    code, out, err = run(capsys, "--format", "json", str(path))
    assert code == 2
    assert "bad.yml" in err
    assert json.loads(out)["findings"]


def test_missing_path_exits_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, str(tmp_path / "nope"))
    assert code == 2
    assert "no such file or directory" in err


def test_default_path_is_github_workflows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    write_workflow: WriteWorkflow,
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_workflow(VULNERABLE, ".github/workflows/ci.yml")
    monkeypatch.chdir(tmp_path)
    code, out, _ = run(capsys, "--format", "json")
    assert code == 1
    assert json.loads(out)["findings"][0]["path"] == ".github/workflows/ci.yml"


def test_output_file(
    write_workflow: WriteWorkflow, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "out" / "report.sarif"
    target.parent.mkdir()
    code, out, _ = run(
        capsys, "--format", "sarif", "--output", str(target), str(write_workflow(VULNERABLE))
    )
    assert code == 1
    assert out == ""
    assert json.loads(target.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert b"\r\n" not in target.read_bytes()


def test_directory_scan_skips_yaml_that_is_not_a_workflow(
    write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str]
) -> None:
    write_workflow("- id: hook\n  entry: x\n", ".pre-commit-hooks.yaml")
    write_workflow("version: 2\nupdates: []\n", ".github/dependabot.yml")
    write_workflow("name: Bug\nbody: []\n", ".github/ISSUE_TEMPLATE/bug.yml")
    write_workflow(CLEAN, "ci.yml")
    write_workflow("name: a\nruns:\n  using: node20\n  main: x.js\n", "tool/action.yml")
    path = write_workflow(CLEAN, "other.yml").parent
    code, out, _ = run(capsys, "--format", "json", str(path))
    assert code == 0
    assert json.loads(out)["summary"]["files_scanned"] == 3


def test_explicit_non_workflow_file_is_still_an_error(
    write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _, err = run(capsys, str(write_workflow("- id: hook\n", ".pre-commit-hooks.yaml")))
    assert code == 2
    assert "expected a mapping at the top level" in err


@pytest.mark.parametrize(
    "content",
    ["version: 2\nupdates: []\n", "", "# only a comment\n"],
    ids=["mapping", "empty", "comment"],
)
def test_explicit_file_without_jobs_or_runs_exits_two(
    write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str], content: str
) -> None:
    path = write_workflow(content, ".github/dependabot.yml")
    code, _, err = run(capsys, str(path))
    assert code == 2
    assert "dependabot.yml: not a GitHub Actions workflow or action file" in err


def test_report_paths_are_relative_to_the_repository_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    write_workflow: WriteWorkflow,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    write_workflow(VULNERABLE, "repo/.github/workflows/ci.yml")
    monkeypatch.chdir(tmp_path / "repo" / ".github")
    _, out, _ = run(capsys, "--format", "json", "workflows/ci.yml")
    assert {f["path"] for f in json.loads(out)["findings"]} == {".github/workflows/ci.yml"}


def test_report_paths_outside_a_repository_are_relative_to_the_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    write_workflow: WriteWorkflow,
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_workflow(VULNERABLE, "sub/ci.yml")
    monkeypatch.chdir(tmp_path)
    _, out, _ = run(capsys, "--format", "json", "sub/ci.yml")
    assert {f["path"] for f in json.loads(out)["findings"]} == {"sub/ci.yml"}


def test_error_messages_use_forward_slashes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, _, err = run(capsys, str(tmp_path / "missing" / "wf.yml"))
    assert "\\" not in err


@pytest.mark.parametrize(
    ("isatty", "no_color", "args", "colored"),
    [
        (True, None, [], True),
        (False, None, [], False),
        (True, "1", [], False),
        (True, "", [], True),
        (True, None, ["--no-color"], False),
    ],
    ids=["tty", "pipe", "NO_COLOR-set", "NO_COLOR-empty", "flag"],
)
def test_color_follows_tty_and_no_color(
    monkeypatch: pytest.MonkeyPatch,
    write_workflow: WriteWorkflow,
    capsys: pytest.CaptureFixture[str],
    *,
    isatty: bool,
    no_color: str | None,
    args: list[str],
    colored: bool,
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    if no_color is not None:
        monkeypatch.setenv("NO_COLOR", no_color)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: isatty)
    _, out, _ = run(capsys, *args, str(write_workflow(VULNERABLE)))
    assert ("\033[" in out) is colored
