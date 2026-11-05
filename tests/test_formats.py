"""The github and markdown formats, and the config file."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from gha_warden.cli import main
from gha_warden.models import Finding, Severity
from gha_warden.report import format_github, format_markdown, format_text
from tests.conftest import VULNERABLE

WriteWorkflow = Callable[..., Path]


def finding(
    severity: Severity = Severity.HIGH, message: str = "msg", path: str = "a.yml"
) -> Finding:
    return Finding("GW003", severity, message, path, 7, 3, "fix it")


def run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    code = main([*args])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_github_annotation_levels_and_location() -> None:
    out = format_github(
        [finding(s) for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)]
    )
    commands = [line.split(" ", 1)[0] for line in out.splitlines()]
    assert commands == ["::error", "::error", "::warning", "::notice"]
    assert out.splitlines()[0].startswith("::error file=a.yml,line=7,col=3,title=GW003 ")
    assert out.splitlines()[0].endswith("::msg")


def test_github_escaping() -> None:
    out = format_github([finding(message="100%, a: b\r\nnext", path="dir,x:y/a.yml")])
    assert out.count("\n") == 1
    assert "file=dir%2Cx%3Ay/a.yml," in out
    assert out.endswith("::100%25, a: b%0D%0Anext\n")


def test_markdown_tables_and_pipe_escaping() -> None:
    out = format_markdown(
        [finding(Severity.CRITICAL, "curl a | bash\nsecond", "x|y.yml"), finding()],
        files_scanned=2,
    )
    assert "2 findings in 2 files." in out
    assert "| Critical | 1 |" in out
    assert "| Low | 0 |" in out
    assert "| Critical | GW003 | x\\|y.yml:7 | curl a \\| bash<br>second |" in out
    assert format_markdown([], files_scanned=1).endswith("No findings in 1 file.\n")


def test_cli_github_and_markdown(
    write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str]
) -> None:
    path = str(write_workflow(VULNERABLE))
    code, out, _ = run(capsys, "--format", "github", path)
    assert code == 1
    assert "::error file=" in out
    code, out, _ = run(capsys, "--format", "markdown", path)
    assert code == 1
    assert out.startswith("## gha-warden\n")


def test_config_applies_and_cli_overrides(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    write_workflow: WriteWorkflow,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = str(write_workflow(VULNERABLE))
    (tmp_path / ".gha-warden.toml").write_text('ignore = ["GW001"]\nmin-severity = "high"\n')
    monkeypatch.chdir(tmp_path)

    _, out, _ = run(capsys, "--format", "json", path)
    from_config = {f["rule_id"] for f in json.loads(out)["findings"]}
    assert from_config == {"GW003"}

    # --ignore replaces the config list; --min-severity wins over the config value.
    _, out, _ = run(capsys, "--format", "json", "--ignore", "GW003", "--min-severity", "low", path)
    ids = {f["rule_id"] for f in json.loads(out)["findings"]}
    assert "GW001" in ids
    assert "GW003" not in ids


def test_config_exclude_and_explicit_path(
    tmp_path: Path, write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str]
) -> None:
    # Patterns match the path as shown in the report: relative to the repository root, not the cwd.
    (tmp_path / ".git").mkdir()
    write_workflow(VULNERABLE, "keep.yml")
    write_workflow(VULNERABLE, "skip/bad.yml")
    config = tmp_path / "custom.toml"
    config.write_text('exclude = ["skip/*"]\n')
    code, out, _ = run(capsys, "--config", str(config), "--format", "github", str(tmp_path))
    assert code == 1
    assert "file=keep.yml" in out
    assert "skip" not in out


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("ignore = [", "invalid TOML"),
        ('ignore = ["GW999"]', "unknown rule id 'GW999'"),
        ('min-severity = "urgent"', "'min-severity' must be one of"),
        ("exclude = 3", "'exclude' must be a list of strings"),
        ("ignroe = []", "unknown key 'ignroe'"),
    ],
)
def test_invalid_config_exits_two(
    tmp_path: Path,
    write_workflow: WriteWorkflow,
    capsys: pytest.CaptureFixture[str],
    content: str,
    message: str,
) -> None:
    config = tmp_path / "bad.toml"
    config.write_text(content)
    code, out, err = run(capsys, "--config", str(config), str(write_workflow(VULNERABLE)))
    assert code == 2
    assert out == ""
    assert err.startswith("gha-warden: error: ")
    assert "bad.toml" in err
    assert message in err


def test_missing_explicit_config_exits_two(
    tmp_path: Path, write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _, err = run(
        capsys, "--config", str(tmp_path / "nope.toml"), str(write_workflow(VULNERABLE))
    )
    assert code == 2
    assert "cannot read config" in err


INJECTING_CONTAINER = (
    "name: t\non: push\njobs:\n  a:\n    runs-on: x\n"
    '    container: "x\\n::error title=pwned::injected\\n"\n    steps: []\n'
)


@pytest.mark.parametrize("fmt", ["text", "markdown", "github"])
def test_file_content_cannot_start_a_workflow_command(
    write_workflow: WriteWorkflow, capsys: pytest.CaptureFixture[str], fmt: str
) -> None:
    path = str(write_workflow(INJECTING_CONTAINER))
    code, out, _ = run(capsys, "--format", fmt, "--no-color", path)
    assert code == 1
    assert "pwned" in out
    if fmt == "github":
        # The annotation format is meant to be read as commands: file content is escaped inside.
        assert all(
            line.startswith(("::warning file=", "::error file=")) for line in out.splitlines()
        )
        assert "%0A::error title=pwned" in out
    else:
        assert not any(line.startswith("::") for line in out.splitlines())
        assert ("<br>" if fmt == "markdown" else "\\n") + "::error title=pwned" in out


def test_control_characters_are_escaped_in_text_output() -> None:
    out = format_text(
        [finding(message="a\r\nb\tc\x1b[2Jd\x85e\u2028f")], files_scanned=1, color=False
    )
    assert "a\\r\\nb\\tc\\x1b[2Jd\\x85e\\u2028f" in out
    assert len(out.splitlines()) == 5


def test_error_messages_cannot_start_a_workflow_command(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, _, err = run(capsys, "evil\n::error::x.yml")
    assert code == 2
    assert not any(line.startswith("::") for line in err.splitlines())
