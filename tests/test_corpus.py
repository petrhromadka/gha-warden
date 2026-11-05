"""Regression corpus: every file in corpus/ must trigger exactly the rules in manifest.json."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from gha_warden.scan import scan_workflow
from gha_warden.workflow import Workflow

CORPUS = Path(__file__).resolve().parent.parent / "corpus"
ENTRIES: list[dict[str, Any]] = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("entry", ENTRIES, ids=[entry["file"] for entry in ENTRIES])
def test_corpus_file_triggers_exactly_the_expected_rules(entry: dict[str, Any]) -> None:
    path = CORPUS / entry["file"]
    workflow = Workflow(path.name, path.read_text(encoding="utf-8"))
    actual = {finding.rule_id for finding in scan_workflow(workflow)}
    expected = set(entry["expected_rules"])
    assert actual == expected, (
        f"{entry['file']}: expected rules {sorted(expected)}, got {sorted(actual)}. "
        f"Missing: {sorted(expected - actual)}; unexpected: {sorted(actual - expected)}. "
        "If a newly added rule legitimately fires on this file, add its ID to "
        "'expected_rules' in corpus/manifest.json (and the table in corpus/README.md); "
        "otherwise fix the rule."
    )


def test_manifest_lists_every_corpus_file() -> None:
    on_disk = {path.name for path in CORPUS.glob("*.yml")}
    listed = {entry["file"] for entry in ENTRIES}
    assert on_disk == listed, (
        f"corpus/manifest.json out of sync with corpus/: "
        f"unlisted files {sorted(on_disk - listed)}, missing files {sorted(listed - on_disk)}"
    )
