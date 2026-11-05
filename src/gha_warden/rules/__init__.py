"""Rule registry."""

from gha_warden.rules.actor import SpoofableActorCheck
from gha_warden.rules.base import Rule
from gha_warden.rules.images import KnownCompromisedAction, UnpinnedContainerImage
from gha_warden.rules.injection import PwnRequest, RemoteScriptPipe, ScriptInjection
from gha_warden.rules.permissions import (
    ExcessivePermissions,
    SecretsInherit,
    SelfHostedOnPullRequest,
)
from gha_warden.rules.pinning import CheckoutPersistsCredentials, UnpinnedAction
from gha_warden.rules.poisoning import ArtifactPoisoning, CachePoisoning
from gha_warden.rules.secret_exposure import SecretInRunScript, SecretsContextExposed
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
    CachePoisoning(),
    ArtifactPoisoning(),
    UnpinnedContainerImage(),
    KnownCompromisedAction(),
    SecretsContextExposed(),
    SecretInRunScript(),
    SpoofableActorCheck(),
]

__all__ = ["ALL_RULES", "Rule"]
