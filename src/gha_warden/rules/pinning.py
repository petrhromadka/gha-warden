"""Supply-chain rules about how actions are referenced: GW003, GW005."""

from __future__ import annotations

import re
from collections.abc import Iterable

from gha_warden.models import Finding, Severity
from gha_warden.rules.base import Rule
from gha_warden.workflow import Workflow

_FULL_SHA = re.compile(r"[^@]+@[0-9a-f]{40}", re.IGNORECASE)
_DOCKER_DIGEST = re.compile(r"docker://[^@]+@sha256:[0-9a-f]{64}", re.IGNORECASE)
_FIRST_PARTY_OWNERS = frozenset({"actions", "github"})


class UnpinnedAction(Rule):
    id = "GW003"
    title = "Action not pinned to a full commit SHA"
    severity = Severity.HIGH
    description = (
        "Tags and branches can be moved by the action's owner (or an attacker who compromises "
        "the owner), silently changing the code that runs with your secrets."
    )
    remediation = (
        "Pin the action to the full 40-character commit SHA and keep the version as a comment, "
        "e.g. uses: owner/repo@<sha> # v4."
    )

    def check(self, workflow: Workflow) -> Iterable[Finding]:
        uses_nodes = [(step.path, step.uses) for step in workflow.steps()]
        uses_nodes += [(job.path, job.data.get("uses")) for job in workflow.jobs()]
        for path, uses in uses_nodes:
            if not isinstance(uses, str) or uses.startswith(("./", "../")):
                continue
            if _FULL_SHA.fullmatch(uses) or _DOCKER_DIGEST.fullmatch(uses):
                continue
            first_party = (
                not uses.startswith("docker://")
                and uses.split("/", 1)[0].lower() in _FIRST_PARTY_OWNERS
            )
            yield self.finding(
                workflow,
                (*path, "uses"),
                f"'{uses}' is not pinned to a full commit SHA",
                severity=Severity.MEDIUM if first_party else Severity.HIGH,
            )


class CheckoutPersistsCredentials(Rule):
    id = "GW005"
    title = "Checkout persists credentials"
    severity = Severity.LOW
    description = (
        "actions/checkout leaves the GITHUB_TOKEN in .git/config by default, where later steps "
        "and uploaded artifacts can read it."
    )
    remediation = "Set 'persist-credentials: false' in the checkout step's with: block."

    def check(self, workflow: Workflow) -> Iterable[Finding]:
        for step in workflow.steps():
            if not (step.uses or "").lower().startswith("actions/checkout@"):
                continue
            value = step.inputs.get("persist-credentials")
            if value is False or str(value).strip().lower() == "false":
                continue
            yield self.finding(
                workflow,
                (*step.path, "uses"),
                "actions/checkout without 'persist-credentials: false'",
            )
