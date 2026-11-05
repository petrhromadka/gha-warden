"""Rules about trusting the identity of whoever triggered a privileged workflow: GW017."""

from __future__ import annotations

import re
from collections.abc import Iterable

from gha_warden.models import Finding, Severity
from gha_warden.rules.base import Rule
from gha_warden.workflow import NodePath, Workflow

_PRIVILEGED_TRIGGERS = frozenset({"pull_request_target", "workflow_run", "issue_comment"})
_TRIGGERING_ACTOR = re.compile(r"(?<![\w.-])github\.triggering_actor(?![\w-])", re.IGNORECASE)
_ACTOR_CONTEXT = r"\(?\s*(?<![\w.-])github\.actor(?![\w.-])\s*\)?"
_ACTOR_NOT_EQUAL = re.compile(
    r"github\.actor\s*!=\s*(?:'[^']*'|\"[^\"]*\")|(?:'[^']*'|\"[^\"]*\")\s*!=\s*github\.actor",
    re.IGNORECASE,
)
_BOT_WORD = r"(?:\[bot\]|dependabot|renovate)"
# A single-quoted literal may contain double quotes, as in fromJSON('["dependabot[bot]"]').
_BOT_LITERAL = rf"(?:'[^']*{_BOT_WORD}[^']*'|\"[^\"]*{_BOT_WORD}[^\"]*\")"
# The actor compared with, or searched for, a bot-like literal. A bot name elsewhere in the
# condition (a label, a branch) is not an actor check.
_ACTOR_IS_BOT = re.compile(
    rf"{_ACTOR_CONTEXT}\s*==\s*{_BOT_LITERAL}"
    rf"|{_BOT_LITERAL}\s*==\s*{_ACTOR_CONTEXT}"
    rf"|\b(?:startsWith|endsWith|contains)\(\s*{_ACTOR_CONTEXT}\s*,\s*{_BOT_LITERAL}"
    rf"|\bcontains\(\s*(?:fromJSON\(\s*)?{_BOT_LITERAL}\s*\)?\s*,\s*{_ACTOR_CONTEXT}",
    re.IGNORECASE,
)
_QUOTED_INDEX = re.compile(r"\[\s*['\"]([^'\"]+)['\"]\s*\]")


def spoofable_actor_checks(condition: str) -> list[str]:
    """Return the actor contexts in an `if:` condition that are spoofable gates."""
    # Rewrite github['actor'] as github.actor, but leave the '[bot]' literal alone.
    expression = _QUOTED_INDEX.sub(
        lambda m: m.group(0) if m.group(1) == "bot" else f".{m.group(1)}", condition
    )
    found: list[str] = []
    if _TRIGGERING_ACTOR.search(expression):
        found.append("github.triggering_actor")
    # `github.actor != 'x'` excludes an identity; it does not authorize one.
    positive = _ACTOR_NOT_EQUAL.sub("", expression)
    if _ACTOR_IS_BOT.search(positive):
        found.append("github.actor")
    return found


class SpoofableActorCheck(Rule):
    id = "GW017"
    title = "Spoofable actor check in a privileged workflow"
    severity = Severity.HIGH
    description = (
        "A job or step of a pull_request_target, workflow_run or issue_comment workflow is "
        "gated on github.actor being a bot (such as dependabot[bot]) or on "
        "github.triggering_actor. The actor is whoever performed the last action on the pull "
        "request, not its author, so an attacker can become the bot, for example by asking "
        "Dependabot to rebase a pull request they control."
    )
    remediation = (
        "Check the author of the pull request instead: github.event.pull_request.user.login "
        "== 'dependabot[bot]'. Better, use dependabot/fetch-metadata, which verifies the "
        "author, and never check out or run pull request code in the gated job."
    )

    def check(self, workflow: Workflow) -> Iterable[Finding]:
        triggers = workflow.triggers & _PRIVILEGED_TRIGGERS
        if not triggers:
            return
        trigger = sorted(triggers)[0]
        scopes: list[tuple[NodePath, dict[str, object]]] = [
            (job.path, job.data) for job in workflow.jobs()
        ]
        scopes += [(step.path, step.data) for step in workflow.steps()]
        for base, data in scopes:
            condition = data.get("if")
            if not isinstance(condition, str):
                continue
            for context in spoofable_actor_checks(condition):
                yield self.finding(
                    workflow,
                    (*base, "if"),
                    f"'if:' gates on '{context}' in a '{trigger}' workflow, which an attacker "
                    "can spoof",
                )
