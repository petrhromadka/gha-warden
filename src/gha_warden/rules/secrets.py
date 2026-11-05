"""Rules about unsafe configuration and credentials: GW008, GW010."""

from __future__ import annotations

import re
from collections.abc import Iterable

from gha_warden.models import Finding, Severity
from gha_warden.rules.base import Rule
from gha_warden.workflow import Workflow

_DISABLED = frozenset({"", "false", "0", "no", "off"})


class UnsecureCommands(Rule):
    id = "GW008"
    title = "ACTIONS_ALLOW_UNSECURE_COMMANDS enabled"
    severity = Severity.HIGH
    description = (
        "Re-enables the deprecated set-env and add-path workflow commands, which let any logged "
        "text (for example untrusted input) change environment variables and PATH."
    )
    remediation = "Remove the variable and use the $GITHUB_ENV and $GITHUB_PATH files instead."

    def check(self, workflow: Workflow) -> Iterable[Finding]:
        for path, env in workflow.blocks("env"):
            value = env.get("ACTIONS_ALLOW_UNSECURE_COMMANDS")
            if value is None or str(value).strip().lower() in _DISABLED:
                continue
            yield self.finding(
                workflow,
                (*path, "ACTIONS_ALLOW_UNSECURE_COMMANDS"),
                "ACTIONS_ALLOW_UNSECURE_COMMANDS is enabled",
                key=True,
            )


_CREDENTIAL_KEY = re.compile(
    r"token|password|passwd|secret|api[_-]?key|private[_-]?key|access[_-]?key|credential",
    re.IGNORECASE,
)
# Keys such as `token-file` or `secret_name` hold a reference to a credential, not the credential.
_REFERENCE_SUFFIXES = frozenset({"file", "path", "url", "name", "type", "id", "dir", "location"})
_NOT_A_SECRET = frozenset({"true", "false", "null", "none"})


def _is_credential_literal(key: str, value: object) -> bool:
    if not isinstance(value, str) or not _CREDENTIAL_KEY.search(key):
        return False
    if re.split(r"[-_]", key.lower())[-1] in _REFERENCE_SUFFIXES:
        return False
    text = value.strip()
    return (
        bool(text)
        and "${{" not in text
        and not text.startswith("$")
        and (text.lower() not in _NOT_A_SECRET)
    )


class HardcodedCredential(Rule):
    id = "GW010"
    title = "Hardcoded credential in env or with"
    severity = Severity.HIGH
    description = (
        "A key named like a token, password or secret has a literal value in the workflow "
        "file, so anyone who can read the repository can read the credential."
    )
    remediation = (
        "Store the value as an encrypted secret and reference it with ${{ secrets.NAME }}; "
        "rotate the exposed credential."
    )

    def check(self, workflow: Workflow) -> Iterable[Finding]:
        for path, block in workflow.blocks("env", "with"):
            for key, value in block.items():
                if _is_credential_literal(str(key), value):
                    yield self.finding(
                        workflow,
                        (*path, key),
                        f"'{key}' is set to a literal value; the value looks like a credential",
                    )
