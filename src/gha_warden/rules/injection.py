"""Rules about attacker-controlled input reaching code execution: GW001, GW002, GW009."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from gha_warden.models import Finding, Severity
from gha_warden.rules.base import Rule
from gha_warden.workflow import NodePath, Workflow

_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
_AUTHOR = r"(?:message|author(?:\.(?:name|email))?|committer(?:\.(?:name|email))?)"
_UNTRUSTED = re.compile(
    r"(?<![\w.-])(?:"
    r"github\.event\.issue\.(?:title|body)"
    r"|github\.event\.pull_request\.(?:title|body|head\.ref|head\.label)"
    r"|github\.event\.comment\.body"
    r"|github\.event\.review\.body"
    r"|github\.event\.review_comment\.body"
    r"|github\.event\.pages\.[^.\s]+\.page_name"
    rf"|github\.event\.commits\.[^.\s]+\.{_AUTHOR}"
    rf"|github\.event\.head_commit\.{_AUTHOR}"
    r"|github\.head_ref"
    r"|github\.event\.discussion\.(?:title|body)"
    rf"|github\.event\.workflow_run\.(?:head_branch|head_commit\.{_AUTHOR})"
    r")(?![\w-])",
    re.IGNORECASE,
)
# An expression that is a single boolean-returning call cannot smuggle text into a script.
_BOOLEAN_CALL = re.compile(
    r"\s*(?:contains|startsWith|endsWith)\((?:[^()]|\([^()]*\))*\)\s*", re.IGNORECASE
)
_QUOTED_INDEX = re.compile(r"\[\s*['\"]([^'\"]+)['\"]\s*\]")
_INDEX = re.compile(r"\[[^\]]*\]")


def _normalize(expression: str) -> str:
    """Turn `a['b']` into `a.b` and `a[0]` into `a.*` so one pattern covers all spellings."""
    return _INDEX.sub(".*", _QUOTED_INDEX.sub(r".\1", expression))


def untrusted_contexts(script: str) -> Iterator[tuple[int, str]]:
    """Yield (line offset, context) for each untrusted context interpolated in `script`."""
    for match in _EXPRESSION.finditer(script):
        expression = _normalize(match.group(1))
        if _BOOLEAN_CALL.fullmatch(expression):
            continue
        line_offset = script.count("\n", 0, match.start())
        seen: set[str] = set()
        for untrusted in _UNTRUSTED.finditer(expression):
            context = untrusted.group(0)
            if context.lower() not in seen:
                seen.add(context.lower())
                yield line_offset, context


class ScriptInjection(Rule):
    id = "GW001"
    title = "Script injection via untrusted context"
    severity = Severity.CRITICAL
    description = (
        "An attacker-controlled value (issue or PR title/body, branch name, commit message, "
        "...) is expanded with ${{ }} directly into a shell script or an "
        "actions/github-script script, so it can inject arbitrary commands."
    )
    remediation = (
        "Pass the value through an environment variable (env: NAME: ${{ ... }}) and read it as "
        "$NAME in the script, or as process.env.NAME in github-script."
    )

    def check(self, workflow: Workflow) -> Iterable[Finding]:
        for step in workflow.steps():
            if step.run is not None:
                yield from self._scan(workflow, (*step.path, "run"), step.run, "a run script")
            uses = (step.uses or "").lower()
            script = step.inputs.get("script")
            if uses.startswith("actions/github-script@") and isinstance(script, str):
                yield from self._scan(
                    workflow, (*step.path, "with", "script"), script, "a github-script script"
                )

    def _scan(
        self, workflow: Workflow, path: NodePath, script: str, where: str
    ) -> Iterator[Finding]:
        for line_offset, context in untrusted_contexts(script):
            yield self.finding(
                workflow,
                path,
                f"Untrusted input '{context}' is interpolated into {where}",
                line_offset=line_offset,
            )


_UNTRUSTED_CHECKOUT = re.compile(
    r"github\.event\.pull_request\.head\.|github\.head_ref|github\.event\.workflow_run\.head_"
    r"|refs/pull/",
    re.IGNORECASE,
)


class PwnRequest(Rule):
    id = "GW002"
    title = "Untrusted pull request code checked out in a privileged workflow"
    severity = Severity.CRITICAL
    description = (
        "A workflow triggered by pull_request_target or workflow_run runs with a write token "
        "and secrets, but checks out the code of the pull request, which the attacker controls."
    )
    remediation = (
        "Use the pull_request trigger for workflows that build or test PR code, or split the "
        "privileged part into a separate workflow that never checks out untrusted code."
    )

    def check(self, workflow: Workflow) -> Iterable[Finding]:
        triggers = workflow.triggers & {"pull_request_target", "workflow_run"}
        if not triggers:
            return
        trigger = sorted(triggers)[0]
        for step in workflow.steps():
            if not (step.uses or "").lower().startswith("actions/checkout@"):
                continue
            for name in ("ref", "repository"):
                value = step.inputs.get(name)
                if isinstance(value, str) and _UNTRUSTED_CHECKOUT.search(value):
                    yield self.finding(
                        workflow,
                        (*step.path, "with", name),
                        f"actions/checkout of untrusted pull request code in a '{trigger}' "
                        "workflow",
                    )


_SHELL = r"(?:ba|z|da|k)?sh"
_REMOTE_FETCH = r"(?:curl|wget)\b"
_PIPE_TO_SHELL = re.compile(
    rf"\b{_REMOTE_FETCH}(?:[^\n|]|\\\n)*\|\s*(?:sudo\s+(?:-\S+\s+)*)?{_SHELL}\b"
    rf"|\b{_SHELL}\s+<\(\s*{_REMOTE_FETCH}"
    rf"|\b{_SHELL}\s+-c\s+[\"']?\$\(\s*{_REMOTE_FETCH}"
)


class RemoteScriptPipe(Rule):
    id = "GW009"
    title = "Remote script piped to a shell"
    severity = Severity.MEDIUM
    description = (
        "A script downloaded with curl or wget is executed without being inspected or "
        "verified; a compromised server or a MITM attacker gets code execution in the runner."
    )
    remediation = (
        "Download the script to a file, verify its checksum or signature, then run it; or use "
        "a pinned action or package instead."
    )

    def check(self, workflow: Workflow) -> Iterable[Finding]:
        for step in workflow.steps():
            script = step.run
            if script is None:
                continue
            for match in _PIPE_TO_SHELL.finditer(script):
                line_start = script.rfind("\n", 0, match.start()) + 1
                if script[line_start : match.start()].lstrip().startswith("#"):
                    continue
                yield self.finding(
                    workflow,
                    (*step.path, "run"),
                    "Remote script is piped into a shell",
                    line_offset=script.count("\n", 0, match.start()),
                )
