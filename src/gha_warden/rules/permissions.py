"""Rules about privileges granted to jobs: GW004, GW006, GW007."""

from __future__ import annotations

from collections.abc import Iterable

from gha_warden.models import Finding, Severity
from gha_warden.rules.base import Rule
from gha_warden.workflow import Workflow


class ExcessivePermissions(Rule):
    id = "GW004"
    title = "Excessive permissions"
    severity = Severity.MEDIUM
    description = (
        "The GITHUB_TOKEN gets broad write access: either 'write-all' is requested, or no "
        "permissions are declared and the repository default (often read-write) applies."
    )
    remediation = (
        "Declare 'permissions: contents: read' at the top level and grant extra scopes only to "
        "the jobs that need them."
    )

    def check(self, workflow: Workflow) -> Iterable[Finding]:
        top = workflow.data.get("permissions")
        if top == "write-all":
            yield self.finding(workflow, ("permissions",), "Top-level 'permissions: write-all'")
        for job in workflow.jobs():
            own = job.data.get("permissions")
            if own == "write-all":
                yield self.finding(
                    workflow, (*job.path, "permissions"), f"Job '{job.id}' uses write-all"
                )
            elif own is None and top is None:
                yield self.finding(
                    workflow,
                    job.path,
                    f"Job '{job.id}' has no 'permissions:' and the workflow declares none",
                    key=True,
                )


class SecretsInherit(Rule):
    id = "GW006"
    title = "Reusable workflow called with 'secrets: inherit'"
    severity = Severity.MEDIUM
    description = (
        "'secrets: inherit' hands every secret of the caller to the called workflow, "
        "far more than it usually needs."
    )
    remediation = "Pass only the required secrets explicitly under 'secrets:'."

    def check(self, workflow: Workflow) -> Iterable[Finding]:
        for job in workflow.jobs():
            if job.data.get("secrets") == "inherit":
                yield self.finding(
                    workflow,
                    (*job.path, "secrets"),
                    f"Job '{job.id}' calls a reusable workflow with 'secrets: inherit'",
                )


def _is_self_hosted(runs_on: object) -> bool:
    if isinstance(runs_on, str):
        return runs_on.strip().lower() == "self-hosted"
    if isinstance(runs_on, list):
        return any(_is_self_hosted(item) for item in runs_on)
    if isinstance(runs_on, dict):
        return _is_self_hosted(runs_on.get("labels"))
    return False


class SelfHostedOnPullRequest(Rule):
    id = "GW007"
    title = "Self-hosted runner on a pull request workflow"
    severity = Severity.HIGH
    description = (
        "Pull requests (especially from forks) can run code on a self-hosted runner, which "
        "is often persistent and has access to internal networks."
    )
    remediation = (
        "Use GitHub-hosted runners for pull request workflows, or restrict the trigger to "
        "trusted contributors and use ephemeral runners."
    )

    def check(self, workflow: Workflow) -> Iterable[Finding]:
        trigger = sorted(workflow.triggers & {"pull_request", "pull_request_target"})
        if not trigger:
            return
        for job in workflow.jobs():
            if _is_self_hosted(job.data.get("runs-on")):
                yield self.finding(
                    workflow,
                    (*job.path, "runs-on"),
                    f"Job '{job.id}' runs on a self-hosted runner in a '{trigger[0]}' workflow",
                )
