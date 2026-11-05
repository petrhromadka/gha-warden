"""Rules about secrets reaching more code than they need to: GW015, GW016."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from gha_warden.models import Finding, Severity
from gha_warden.rules.base import Rule
from gha_warden.workflow import NodePath, Workflow

_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
_QUOTED_NAME_INDEX = re.compile(r"\[\s*'([\w-]+)'\s*\]")
_STRING_LITERAL = re.compile(r"'(?:[^']|'')*'|\"[^\"]*\"")
_BOOLEAN_CALL = re.compile(
    r"\s*(?:contains|startsWith|endsWith)\((?:[^()]|\([^()]*\))*\)\s*", re.IGNORECASE
)
_START = r"(?<![\w.-])"
_END = r"(?![\w-])"
_WHOLE_SECRETS = re.compile(rf"{_START}secrets{_END}(?!\s*[.\[])", re.IGNORECASE)
_DYNAMIC_SECRET = re.compile(rf"{_START}secrets\s*\[", re.IGNORECASE)
_NAMED_SECRET = re.compile(rf"{_START}secrets\s*\.\s*([\w-]+)", re.IGNORECASE)
_GITHUB_TOKEN = re.compile(rf"{_START}github\s*\.\s*token{_END}", re.IGNORECASE)
_DUMPED_GITHUB = re.compile(rf"{_START}toJSON\(\s*github(?:\s*\.\s*event)?\s*\)", re.IGNORECASE)
_EXPOSURES = (
    (_WHOLE_SECRETS, "The whole 'secrets' context is exposed to the step"),
    (_DYNAMIC_SECRET, "A secret is selected with a dynamic index 'secrets[...]'"),
)


def _expressions(text: str) -> Iterator[tuple[int, str]]:
    """Yield (character offset, expression) for each `${{ }}` in `text`.

    `secrets['NAME']` is rewritten to `secrets.NAME` and string literals are blanked, so the
    patterns see one spelling and never match text inside a quoted string.
    """
    for match in _EXPRESSION.finditer(text):
        expression = _QUOTED_NAME_INDEX.sub(r".\1", match.group(1))
        yield match.start(), _STRING_LITERAL.sub("''", expression)


def _yields_boolean(expression: str) -> bool:
    """True if the expression evaluates to true/false, so no value is pasted into a script."""
    if _BOOLEAN_CALL.fullmatch(expression):
        return True
    return (
        ("==" in expression or "!=" in expression)
        and "&&" not in expression
        and ("||" not in expression)
    )


def _strings(
    node: object, path: NodePath, ancestors: frozenset[int] = frozenset()
) -> Iterator[tuple[NodePath, str]]:
    if isinstance(node, str):
        yield path, node
        return
    # YAML aliases can make a container contain itself; skip a node already on this path.
    if id(node) in ancestors:
        return
    if isinstance(node, dict):
        inner = ancestors | {id(node)}
        for key, value in node.items():
            yield from _strings(value, (*path, key), inner)
    elif isinstance(node, list):
        inner = ancestors | {id(node)}
        for index, value in enumerate(node):
            yield from _strings(value, (*path, index), inner)


class SecretsContextExposed(Rule):
    id = "GW015"
    title = "Entire secrets context exposed"
    severity = Severity.HIGH
    description = (
        "The whole secrets context is handed to a step (toJSON(secrets), ${{ secrets }}) or a "
        "secret is picked with a computed name (secrets[...]), so one step gets every secret "
        "instead of the ones it needs. toJSON(github) and toJSON(github.event) in a run script "
        "paste the whole event payload, including attacker-controlled text, into the shell."
    )
    remediation = (
        "Reference each secret the step needs by name (${{ secrets.NAME }}) in env: or with:. "
        "Read event data through env: variables, selecting only the fields you need."
    )

    def check(self, workflow: Workflow) -> Iterable[Finding]:
        for path, text in _strings(workflow.data, ()):
            reported: set[tuple[int, str]] = set()
            for offset, expression in _expressions(text):
                line = workflow.locate(path, offset=offset)[0]
                for pattern, message in _EXPOSURES:
                    if pattern.search(expression) and (line, message) not in reported:
                        reported.add((line, message))
                        yield self.finding(workflow, path, message, offset=offset)
        for step in workflow.steps():
            if step.run is None:
                continue
            for offset, expression in _expressions(step.run):
                if match := _DUMPED_GITHUB.search(expression):
                    dumped = "".join(match.group(0).split())
                    yield self.finding(
                        workflow,
                        (*step.path, "run"),
                        f"{dumped} pastes attacker-controlled event data into a run script",
                        offset=offset,
                    )


class SecretInRunScript(Rule):
    id = "GW016"
    title = "Secret interpolated into run script"
    severity = Severity.LOW
    description = (
        "A secret or github.token is expanded with ${{ }} straight into a run script. The value "
        "is written into the generated script file, can show up in process listings and error "
        "traces, and breaks the script when it contains quotes or other special characters."
    )
    remediation = (
        "Set the secret in env: (NAME: ${{ secrets.NAME }}) and read it as $NAME in the script."
    )

    def check(self, workflow: Workflow) -> Iterable[Finding]:
        for step in workflow.steps():
            if step.run is None:
                continue
            reported: set[tuple[int, str]] = set()
            for offset, expression in _expressions(step.run):
                if _yields_boolean(expression):
                    continue
                line = workflow.locate((*step.path, "run"), offset=offset)[0]
                refs = [f"secrets.{m.group(1)}" for m in _NAMED_SECRET.finditer(expression)]
                if _GITHUB_TOKEN.search(expression):
                    refs.append("github.token")
                for ref in refs:
                    if (line, ref.lower()) in reported:
                        continue
                    reported.add((line, ref.lower()))
                    yield self.finding(
                        workflow,
                        (*step.path, "run"),
                        f"'{ref}' is interpolated into a run script instead of passed via env:",
                        offset=offset,
                    )
