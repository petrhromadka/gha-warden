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


# A key is credential-like only if it ENDS with a credential word, as a whole segment
# (`DB_PASSWORD`, `githubToken`, `AWS_SECRET_ACCESS_KEY`). `TOKEN_USAGE_TITLE`, `max-tokens`
# and `secret-scanning` merely mention one.
_CREDENTIAL_ENDING = re.compile(
    r"(?:^|-)(?:token|passwords?|passwd|secrets?|credentials?|apikey|accesskey|privatekey"
    r"|(?:api|access|private|secret)-key)$"
)
_PASSWORD_ENDING = re.compile(r"(?:^|-)(?:passwords?|passwd)$")
_NOT_A_SECRET = frozenset(
    {"true", "false", "null", "none", "yes", "no", "on", "off", "enabled", "disabled", "auto"}
)
_MIN_LENGTH = 8  # shorter values are not credentials, except for password-like keys
# `CI_DEPLOY_PASSWORD` or `A_NAME,B_NAME`: the name of an environment variable (or a list of
# names), which tells a tool where to look and is not the credential itself.
_ENV_NAME = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")
_NAME_LIST = re.compile(r"[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)+")


def _is_credential_literal(key: str, value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, str | int | float):
        return False
    # Split camelCase, then treat `_` and `.` like `-` so each credential word is a whole segment.
    normalized = (
        re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "-", key).lower().replace("_", "-").replace(".", "-")
    )
    if not _CREDENTIAL_ENDING.search(normalized):
        return False
    text = str(value)
    if "\n" in text:
        return False  # a multi-line value is a block of text, not a single credential
    text = text.strip()
    if (
        not text
        or "${{" in text
        or text.startswith("$")
        or text.lower() in _NOT_A_SECRET
        # A multi-line value or one with spaces is prose or a mapping of names, not a credential.
        or any(char.isspace() for char in text)
        or _ENV_NAME.fullmatch(text)
        or _NAME_LIST.fullmatch(text)
    ):
        return False
    return len(text) >= _MIN_LENGTH or bool(_PASSWORD_ENDING.search(normalized))


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
