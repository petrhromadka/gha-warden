"""Rule registry."""

from gha_warden.rules.base import Rule
from gha_warden.rules.injection import PwnRequest, RemoteScriptPipe, ScriptInjection
from gha_warden.rules.permissions import (
    ExcessivePermissions,
    SecretsInherit,
    SelfHostedOnPullRequest,
)
from gha_warden.rules.pinning import CheckoutPersistsCredentials, UnpinnedAction
from gha_warden.rules.secrets import HardcodedCredential, UnsecureCommands

ALL_RULES: list[Rule] = [
    ScriptInjection(),
    PwnRequest(),
    UnpinnedAction(),
    ExcessivePermissions(),
    CheckoutPersistsCredentials(),
    SecretsInherit(),
    SelfHostedOnPullRequest(),
    UnsecureCommands(),
    RemoteScriptPipe(),
    HardcodedCredential(),
]

__all__ = ["ALL_RULES", "Rule"]
