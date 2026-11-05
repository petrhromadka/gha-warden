"""GW013 (container images) and GW014 (known-compromised actions)."""

from __future__ import annotations

import json
from collections.abc import Callable
from importlib import resources

import pytest

from gha_warden.models import Finding, Severity
from gha_warden.rules import ALL_RULES
from gha_warden.rules.images import load_denylist

FindingsFor = Callable[[str, str], list[Finding]]

DIGEST = "sha256:" + "a" * 64


def _workflow(job_body: str) -> str:
    return f"name: t\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n{job_body}"


def test_gw013_flags_container_and_services(findings_for: FindingsFor) -> None:
    text = _workflow(
        "    container: node:22\n"
        "    services:\n"
        "      db:\n"
        "        image: postgres:17\n"
        "      cache:\n"
        "        image: redis\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    found = findings_for("GW013", text)
    assert [f.line for f in found] == [6, 9, 11]
    assert found[0].severity is Severity.MEDIUM
    assert "node:22" in found[0].message


def test_gw013_flags_container_image_key(findings_for: FindingsFor) -> None:
    text = _workflow(
        "    container:\n"
        "      image: ghcr.io/example-org/builder:latest\n"
        "      options: --user 1000\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    (finding,) = findings_for("GW013", text)
    assert (finding.line, finding.column) == (7, 14)


def test_gw013_flags_digest_that_is_not_64_hex(findings_for: FindingsFor) -> None:
    text = _workflow("    container: node:22@sha256:abc123\n    steps:\n      - run: echo hi\n")
    assert [f.line for f in findings_for("GW013", text)] == [6]


def test_gw013_accepts_digest_pinned_and_expressions(findings_for: FindingsFor) -> None:
    text = _workflow(
        f"    container: node:22@{DIGEST}\n"
        "    services:\n"
        "      db:\n"
        f"        image: postgres@{DIGEST}\n"
        "      cache:\n"
        "        image: ${{ vars.CACHE_IMAGE }}\n"
        "      other:\n"
        "        ports: ['80:80']\n"
        "      disabled:\n"
        "        image: ''\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    assert findings_for("GW013", text) == []


def test_gw013_ignores_job_without_container(findings_for: FindingsFor) -> None:
    assert findings_for("GW013", _workflow("    steps:\n      - run: echo hi\n")) == []


def _uses(ref: str) -> str:
    return _workflow(f"    steps:\n      - uses: {ref}\n")


@pytest.mark.parametrize(
    ("ref", "advisory_id"),
    [
        ("tj-actions/changed-files@v44", "CVE-2025-30066"),
        ("tj-actions/changed-files@v45.0.7", "CVE-2025-30066"),
        ("tj-actions/changed-files@v35.7.7-sec", "CVE-2025-30066"),
        ("TJ-Actions/Changed-Files@v1", "CVE-2025-30066"),
        ("tj-actions/changed-files/sub@v44", "CVE-2025-30066"),
        ("tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67", "CVE-2025-30066"),
        ("reviewdog/action-setup@f0d342d" + "0" * 33, "GHSA-qmg3-hpqr-gqvc"),
        ("aquasecurity/trivy-action@0.34.2", "CVE-2026-33634"),
        ("aquasecurity/trivy-action@v0.20.0", "CVE-2026-33634"),
        ("aquasecurity/setup-trivy@v0.2.0", "CVE-2026-33634"),
        ("xygeni/xygeni-action@v5", "GHSA-f8q5-h5qh-33mh"),
        ("xygeni/xygeni-action@4bf1d4e19ad81a3e8d4063755ae0f482dd3baf12", "GHSA-f8q5-h5qh-33mh"),
    ],
)
def test_gw014_flags_compromised_refs(
    findings_for: FindingsFor, ref: str, advisory_id: str
) -> None:
    (finding,) = findings_for("GW014", _uses(ref))
    assert (finding.line, finding.severity) == (7, Severity.CRITICAL)
    assert advisory_id in finding.message
    assert finding.message.rsplit("Advisory: ", 1)[1].startswith("https://github.com/")


@pytest.mark.parametrize(
    "ref",
    [
        "tj-actions/changed-files@v46",
        "tj-actions/changed-files@v46.0.1",
        "tj-actions/changed-files@main",
        "tj-actions/changed-files@" + "1" * 40,
        "tj-actions/changed-files-extra@v1",
        "tj-actions/changed-files-v2/changed@v1",
        "my-tj-actions/changed-files@v1",
        "tj-actions/other@v1",
        "reviewdog/action-setup@v1",
        "reviewdog/action-setup-extra@f0d342d" + "0" * 33,
        "reviewdog/action-shellcheck@v1",
        "aquasecurity/trivy-action@0.35.0",
        "aquasecurity/trivy-action@v0.35",
        "aquasecurity/trivy-action@" + "2" * 40,
        "aquasecurity/trivy@v0.20.0",
        "xygeni/xygeni-action@v6",
        "xygeni/xygeni-action@v5.1",
        "./tj-actions/changed-files@v1",
        "docker://tj-actions/changed-files@v1",
    ],
)
def test_gw014_ignores_safe_refs(findings_for: FindingsFor, ref: str) -> None:
    assert findings_for("GW014", _uses(ref)) == []


def test_gw014_checks_reusable_workflow_jobs(findings_for: FindingsFor) -> None:
    text = (
        "on: push\njobs:\n  call:\n    uses: xygeni/xygeni-action/.github/workflows/scan.yml@v5\n"
    )
    (finding,) = findings_for("GW014", text)
    assert finding.line == 4


def test_denylist_ships_complete_entries() -> None:
    raw = json.loads(
        resources.files("gha_warden").joinpath("data/compromised.json").read_text("utf-8")
    )
    assert len(raw) >= 5
    for entry in raw:
        assert entry["advisory"].startswith("https://")
        assert entry["compromised_on"][:2] == "20"
        assert entry["guidance"]
        assert entry["affected_refs"] or entry["affected_below"] or entry["malicious_shas"]
    assert "tj-actions/changed-files" in load_denylist()


def test_new_rules_are_registered() -> None:
    assert {"GW013", "GW014"} <= {rule.id for rule in ALL_RULES}
