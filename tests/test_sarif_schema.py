"""Validate SARIF output against the official OASIS SARIF 2.1.0 JSON schema."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft4Validator

from gha_warden.cli import main

# Schema vendored unchanged from
# https://raw.githubusercontent.com/oasis-tcs/sarif-spec/a560296ca8c921f3bdb8d4a8db57ab83dae968a7/sarif-2.1/schema/sarif-schema-2.1.0.json
# (oasis-tcs/sarif-spec, last commit touching the file: a560296ca8c921f3bdb8d4a8db57ab83dae968a7,
# 2024-05-02). The schema declares JSON Schema draft-04.
SCHEMA = json.loads(
    (Path(__file__).parent / "data" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8")
)
ROOT = Path(__file__).resolve().parent.parent


def _sarif(capsys: pytest.CaptureFixture[str], *paths: Path) -> dict[str, Any]:
    main(["--format", "sarif", *map(str, paths)])
    return json.loads(capsys.readouterr().out)


def test_schema_itself_is_valid() -> None:
    Draft4Validator.check_schema(SCHEMA)


def test_sarif_for_vulnerable_examples_matches_schema(
    capsys: pytest.CaptureFixture[str],
) -> None:
    sarif = _sarif(capsys, ROOT / "examples" / "vulnerable")
    assert sarif["runs"][0]["results"], "expected findings so results are actually validated"
    Draft4Validator(SCHEMA).validate(sarif)


def test_sarif_without_findings_matches_schema(capsys: pytest.CaptureFixture[str]) -> None:
    sarif = _sarif(capsys, ROOT / "examples" / "safe")
    assert sarif["runs"][0]["results"] == []
    Draft4Validator(SCHEMA).validate(sarif)


def test_schema_rejects_a_malformed_document(capsys: pytest.CaptureFixture[str]) -> None:
    sarif = _sarif(capsys, ROOT / "examples" / "vulnerable")
    sarif["runs"][0]["results"][0]["level"] = "catastrophic"
    assert not Draft4Validator(SCHEMA).is_valid(sarif)
