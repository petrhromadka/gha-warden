"""Supply-chain rules about container images and known-bad actions: GW013, GW014."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cache
from importlib import resources

from gha_warden.models import Finding, Severity
from gha_warden.rules.base import Rule
from gha_warden.workflow import NodePath, Workflow

_IMAGE_DIGEST = re.compile(r".+@sha256:[0-9a-f]{64}", re.IGNORECASE)
_FULL_SHA = re.compile(r"[0-9a-f]{40}", re.IGNORECASE)
_VERSION = re.compile(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", re.IGNORECASE)
# A floating tag such as `v45` resolves to the newest 45.x.y, so its missing parts count as high.
_OPEN_END = 10**9


class UnpinnedContainerImage(Rule):
    id = "GW013"
    title = "Container image not pinned by digest"
    severity = Severity.MEDIUM
    description = (
        "Image tags are mutable: whoever controls the registry repository can push different "
        "content under the same tag, and it runs inside your job with its secrets."
    )
    remediation = (
        "Pin the image to its digest and keep the tag as a comment, "
        "e.g. image: node:22@sha256:<64 hex digits> # 22.11."
    )

    def check(self, workflow: Workflow) -> Iterable[Finding]:
        for job in workflow.jobs():
            container = job.data.get("container")
            if isinstance(container, str):
                yield from self._check_image(workflow, (*job.path, "container"), container)
            elif isinstance(container, dict):
                path = (*job.path, "container", "image")
                yield from self._check_image(workflow, path, container.get("image"))
            services = job.data.get("services")
            if not isinstance(services, dict):
                continue
            for name, service in services.items():
                # An empty image disables the service (GitHub docs), so there is nothing to pin.
                if isinstance(service, dict) and service.get("image") != "":
                    path = (*job.path, "services", name, "image")
                    yield from self._check_image(workflow, path, service.get("image"))

    def _check_image(self, workflow: Workflow, path: NodePath, image: object) -> Iterable[Finding]:
        if not isinstance(image, str) or _IMAGE_DIGEST.fullmatch(image.strip()):
            return
        if "${{" in image:
            # Only report it when the literal text before the expression already ends in a
            # tag (`name:${{ ... }}`) and there is no `@`, so no value can turn it into a digest.
            literal = image.split("${{", 1)[0]
            if "@" in image or ":" not in literal.rsplit("/", 1)[-1]:
                return
        yield self.finding(workflow, path, f"Container image '{image}' is not pinned by digest")


@dataclass(frozen=True)
class Compromise:
    action: str
    advisory_id: str
    advisory: str
    compromised_on: str
    affected_refs: tuple[str, ...]
    affected_below: tuple[int, ...] | None
    malicious_shas: tuple[str, ...]
    guidance: str

    def matches(self, ref: str) -> bool:
        if _FULL_SHA.fullmatch(ref):
            return any(ref.lower().startswith(sha.lower()) for sha in self.malicious_shas)
        if ref in self.affected_refs:
            return True
        version = _parse_version(ref)
        return (
            self.affected_below is not None
            and version is not None
            and version < self.affected_below
        )


def _parse_version(ref: str) -> tuple[int, ...] | None:
    match = _VERSION.fullmatch(ref)
    if match is None:
        return None
    return tuple(_OPEN_END if part is None else int(part) for part in match.groups())


@cache
def load_denylist() -> dict[str, tuple[Compromise, ...]]:
    """Known-compromised actions from the packaged data file, keyed by lowercase `owner/repo`."""
    text = resources.files("gha_warden").joinpath("data/compromised.json").read_text("utf-8")
    result: dict[str, list[Compromise]] = {}
    for entry in json.loads(text):
        below = entry["affected_below"]
        item = Compromise(
            action=entry["action"],
            advisory_id=entry["advisory_id"],
            advisory=entry["advisory"],
            compromised_on=entry["compromised_on"],
            affected_refs=tuple(entry["affected_refs"]),
            affected_below=None if below is None else tuple(int(p) for p in below.split(".")),
            malicious_shas=tuple(entry["malicious_shas"]),
            guidance=entry["guidance"],
        )
        result.setdefault(item.action.lower(), []).append(item)
    return {action: tuple(items) for action, items in result.items()}


class KnownCompromisedAction(Rule):
    id = "GW014"
    title = "Known-compromised action"
    severity = Severity.CRITICAL
    description = (
        "The referenced action version matches a publicly documented supply-chain compromise: "
        "it ran attacker code in the workflows that used it."
    )
    remediation = (
        "Move to a fixed release pinned by full commit SHA, then rotate every secret the "
        "workflow could read while the compromised version was in use."
    )

    def check(self, workflow: Workflow) -> Iterable[Finding]:
        uses_nodes = [(step.path, step.uses) for step in workflow.steps()]
        uses_nodes += [(job.path, job.data.get("uses")) for job in workflow.jobs()]
        denylist = load_denylist()
        for path, uses in uses_nodes:
            if not isinstance(uses, str) or uses.startswith(("./", "../", "docker://")):
                continue
            name, _, ref = uses.rpartition("@")
            repo = "/".join(name.split("/")[:2]).lower()
            for entry in denylist.get(repo, ()):
                if entry.matches(ref):
                    yield self.finding(
                        workflow,
                        (*path, "uses"),
                        f"'{uses}' is a known-compromised action version "
                        f"({entry.advisory_id}, {entry.compromised_on}): {entry.guidance} "
                        f"Advisory: {entry.advisory}",
                    )
