"""Property-based fuzzing: odd-but-valid workflow YAML must never crash the scanner."""

from __future__ import annotations

import importlib.util
import json
import random
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gha_warden.cli import main
from gha_warden.report import format_json, format_sarif, format_text
from gha_warden.scan import scan_workflow
from gha_warden.workflow import Workflow, WorkflowError

SNIPPETS = [
    "push",
    "pull_request",
    "pull_request_target",
    "workflow_run",
    "actions/checkout@v4",
    "actions/checkout@" + "a" * 40,
    "actions/github-script@v7",
    "third-party/tool@main",
    "./local",
    "docker://alpine@sha256:" + "b" * 64,
    "org/repo/.github/workflows/x.yml@main",
    "${{ github.event.pull_request.title }}",
    "${{ github.head_ref }}",
    "${{ secrets.TOKEN }}",
    "echo ${{ github.event.issue.body }}",
    "curl -sSL https://example.invalid/x.sh | bash",
    "wget -O- https://example.invalid/x.sh | sh",
    "ubuntu-latest",
    "self-hosted",
    "write-all",
    "read-all",
    "inherit",
    "false",
    "hunter2-not-real",
    "ACTIONS_ALLOW_UNSECURE_COMMANDS",
    "# gha-warden: ignore[GW001]",
    "multi\nline\nvalue",
    "",
]

scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(),
    st.sampled_from(SNIPPETS),
    st.text(max_size=20),
)
odd_values = st.recursive(
    scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.one_of(st.sampled_from(SNIPPETS), st.integers(), st.none()), children),
    ),
    max_leaves=6,
)
text_or_odd = st.one_of(st.sampled_from(SNIPPETS), odd_values)


def mapping(
    required: dict[str, st.SearchStrategy[Any]] | None = None,
    /,
    **fields: st.SearchStrategy[Any],
) -> st.SearchStrategy[dict[str, Any]]:
    """A dict with the `required` keys and a random subset of the optional `fields`."""
    return st.fixed_dictionaries(required or {}, optional=fields)


def mostly[T](valid: st.SearchStrategy[T], odd: st.SearchStrategy[Any]) -> st.SearchStrategy[Any]:
    """Mostly the well-shaped strategy, sometimes an arbitrary value of the wrong type."""
    return st.one_of(valid, valid, valid, odd)


env_blocks = mostly(
    st.dictionaries(
        st.sampled_from(["API_TOKEN", "password", "ACTIONS_ALLOW_UNSECURE_COMMANDS", "X"]),
        text_or_odd,
        max_size=3,
    ),
    odd_values,
)
step_inputs = mostly(
    st.dictionaries(
        st.sampled_from(["ref", "script", "persist-credentials", "token", "api_key", "x"]),
        text_or_odd,
        max_size=3,
    ),
    odd_values,
)
step_fields: dict[str, st.SearchStrategy[Any]] = {
    "name": text_or_odd,
    "env": env_blocks,
    "permissions": odd_values,
    "with": step_inputs,
}
step_mapping = st.one_of(
    mapping({"uses": text_or_odd}, run=text_or_odd, **step_fields),
    mapping({"run": text_or_odd}, uses=text_or_odd, **step_fields),
)
step_list = st.lists(mostly(step_mapping, odd_values), min_size=1, max_size=4)
steps = mostly(step_list, odd_values)
job_mapping = mapping(
    {"steps": steps},
    **{
        "runs-on": text_or_odd,
        "uses": text_or_odd,
        "secrets": text_or_odd,
        "permissions": odd_values,
        "env": env_blocks,
        "with": step_inputs,
        "needs": odd_values,
    },
)
jobs = mostly(
    st.dictionaries(
        mostly(st.sampled_from(["build", "test"]), st.one_of(st.integers(), st.none())),
        mostly(job_mapping, odd_values),
        min_size=1,
        max_size=3,
    ),
    odd_values,
)
on_forms = st.one_of(
    st.sampled_from(["push", "pull_request_target", "workflow_run"]),
    st.lists(st.sampled_from(SNIPPETS[:4]), max_size=3),
    st.dictionaries(st.sampled_from(SNIPPETS[:4]), odd_values, max_size=3),
    odd_values,
)
workflows = mapping(
    {"jobs": jobs},
    name=text_or_odd,
    on=on_forms,
    permissions=odd_values,
    env=env_blocks,
    runs=mostly(mapping(using=text_or_odd, steps=steps), odd_values),
)


def scan_text(text: str) -> None:
    """Scan `text`; only the documented WorkflowError parse-error path may be raised."""
    try:
        workflow = Workflow("wf.yml", text)
    except WorkflowError:
        return
    findings = scan_workflow(workflow)
    format_text(findings, files_scanned=1, color=False)
    format_json(findings, files_scanned=1)
    json.loads(format_sarif(findings))


@settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
@given(data=workflows, bare_on=st.sampled_from(["no", "key", "text"]))
def test_random_workflow_shaped_documents_do_not_crash(data: dict[str, Any], bare_on: str) -> None:
    """`key` dumps `on` as boolean True (how PyYAML reads a bare `on:`); `text` hand-writes it."""
    if bare_on == "key":
        document: dict[Any, Any] = {True: data.pop("on", "push"), **data}
        scan_text(yaml.safe_dump(document, sort_keys=False, allow_unicode=True))
    elif bare_on == "text":
        data.pop("on", None)
        scan_text("on: push\n" + yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
    else:
        scan_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))


# Crashes found by fuzzing: each used to escape as a raw traceback instead of a parse error.
UNPARSEABLE = {
    "control-character": 'on: push\njobs: {b: {steps: [{run: "\0"}]}}\n',
    "lone-surrogate": 'on: push\nname: "\ud800"\n',
    "integer-over-digit-limit": "on: push\nname: 1" + "0" * 5000 + "\n",
    "nesting-too-deep": "on: push\njobs: " + "[" * 1000 + "]" * 1000 + "\n",
    # PyYAML raises KeyError and AttributeError for these explicit tags.
    "bool-tag-on-non-boolean": "on: push\nname: !!bool steps\n",
    "timestamp-tag-on-non-date": "on: push\nname: !!timestamp x\n",
}


@pytest.mark.parametrize("text", UNPARSEABLE.values(), ids=UNPARSEABLE.keys())
def test_unparseable_input_is_a_workflow_error(text: str) -> None:
    with pytest.raises(WorkflowError):
        Workflow("wf.yml", text)


def test_control_character_exits_two_without_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "binary.yml"
    path.write_bytes(b"on: push\nname: \x00\n")
    assert main([str(path)]) == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert "binary.yml: invalid YAML" in err


def test_bad_tag_in_walked_directory_exits_two_without_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A directory walk parses YAML outside .github/workflows to decide if it is a workflow."""
    (tmp_path / "other.yml").write_text("jobs: !!bool steps\n", encoding="utf-8")
    assert main([str(tmp_path)]) == 2
    assert "other.yml: invalid YAML" in capsys.readouterr().err


# Valid but unusual YAML that scans cleanly.
ODD_VALID = {
    "recursive-alias": "on: push\njobs: &a [*a]\n",
    "self-referencing-step": "on: push\njobs: {b: {steps: [&s {uses: x@v1, run: *s, with: *s}]}}\n",
    "set-tag": "on: !!set {push, pull_request}\njobs: !!set {a, b}\n",
    "timestamps": "on: 2001-12-14\njobs: {b: {steps: [{run: 2001-12-14, uses: 2001-12-14}]}}\n",
    "complex-keys": "? [a, b]\n: c\n",
    "duplicate-keys": "on: push\non: workflow_run\njobs: {a: {steps: []}, a: {}}\n",
    "non-string-job-ids": "on: push\njobs: {1.5: {steps: [{run: x}]}, null: {}}\n",
    "empty-document": "",
}


@pytest.mark.parametrize("text", ODD_VALID.values(), ids=ODD_VALID.keys())
def test_odd_but_valid_yaml_does_not_crash(text: str) -> None:
    scan_text(text)


# The Atheris harness in fuzz/ (run in CI on Linux); its check is plain Python and runs here.
ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("fuzz_scan", ROOT / "fuzz" / "fuzz_scan.py")
assert _spec is not None and _spec.loader is not None
fuzz_scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fuzz_scan)

SEEDS = sorted([*ROOT.glob("corpus/*.yml"), *ROOT.glob("examples/**/*.yml")])
_DICT_ESCAPE = r'\\(?:[\\"]|x[0-9A-Fa-f]{2})'
_DICT_ENTRY = re.compile(rf'"((?:[^"\\]|{_DICT_ESCAPE})*)"')


def dictionary_tokens() -> list[bytes]:
    """Parse fuzz/yaml.dict the way libFuzzer does; a malformed line fails the test."""
    tokens = []
    for line in (ROOT / "fuzz" / "yaml.dict").read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        match = _DICT_ENTRY.fullmatch(line)
        assert match, f"malformed dictionary line: {line!r}"
        raw = re.sub(
            _DICT_ESCAPE,
            lambda m: chr(int(m[0][2:], 16)) if m[0][1] == "x" else m[0][1],
            match[1],
        )
        tokens.append(raw.encode("latin-1"))
    return tokens


def mutate(rng: random.Random, data: bytes, tokens: list[bytes], seeds: list[bytes]) -> bytes:
    """A few libFuzzer-style edits: flip, insert, delete, insert a token, splice another seed."""
    buf = bytearray(data)
    for _ in range(rng.randint(1, 8)):
        pos = rng.randint(0, len(buf))
        match rng.randrange(5):
            case 0 if buf:
                buf[min(pos, len(buf) - 1)] = rng.randrange(256)
            case 1:
                buf[pos:pos] = bytes([rng.randrange(256)])
            case 2:
                del buf[pos : pos + rng.randint(1, 16)]
            case 3:
                buf[pos:pos] = rng.choice(tokens)
            case _:
                other = rng.choice(seeds)
                start = rng.randint(0, len(other))
                buf[pos:pos] = other[start : start + rng.randint(1, 200)]
    return bytes(buf)


def test_fuzz_harness_accepts_every_seed() -> None:
    assert len(SEEDS) >= 20
    for seed in SEEDS:
        fuzz_scan.check_one(seed.read_bytes())
    # Two and three workflows in one input exercise `link_workflows`.
    joined = fuzz_scan.SEPARATOR.encode().join(seed.read_bytes() for seed in SEEDS[:3])
    fuzz_scan.check_one(joined)


def test_fuzz_harness_on_mutated_seeds() -> None:
    rng = random.Random(20261105)  # noqa: S311 - reproducible test input, not cryptography
    tokens = dictionary_tokens()
    seeds = [seed.read_bytes() for seed in SEEDS]
    for _ in range(400):
        data = mutate(rng, rng.choice(seeds), tokens, seeds)
        fuzz_scan.check_one(data)


def test_fuzz_harness_flags_a_workflow_command_line() -> None:
    with pytest.raises(AssertionError, match="workflow command"):
        fuzz_scan._assert_no_workflow_command("ok\n  ::add-mask::x\n", "text")
