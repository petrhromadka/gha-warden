"""Rules about attacker-controlled data crossing a trust boundary: GW011, GW012."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from gha_warden.models import Finding, Severity
from gha_warden.rules.base import Rule
from gha_warden.workflow import Step, Workflow

_PRIVILEGED_CACHE_TRIGGERS = frozenset({"pull_request_target", "workflow_run", "issue_comment"})
_FALSY = {"", "false", "0", "no", "off"}

# Setup actions whose `cache` input turns on a cache restore. setup-go caches unless told not to.
_CACHE_INPUT_ACTIONS = {
    "actions/setup-node": False,
    "actions/setup-python": False,
    "actions/setup-java": False,
    "actions/setup-go": True,
}


def _action(step: Step) -> str:
    """The lowercase `owner/repo[/path]` of a `uses:` reference, without the version."""
    return (step.uses or "").lower().partition("@")[0]


def _enabled(value: object, *, default: bool = False) -> bool:
    """Whether an action input switches a feature on; unset means `default`."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in _FALSY


def _restores_cache(step: Step) -> str | None:
    """Name the cache a step restores, or None."""
    action = _action(step)
    if action in {"actions/cache", "actions/cache/restore"}:
        return action
    if action in _CACHE_INPUT_ACTIONS:
        if _enabled(step.inputs.get("cache"), default=_CACHE_INPUT_ACTIONS[action]):
            return f"{action} with caching enabled"
    elif action == "astral-sh/setup-uv" and _enabled(step.inputs.get("enable-cache")):
        return f"{action} with enable-cache"
    return None


class CachePoisoning(Rule):
    id = "GW011"
    title = "Cache poisoning in privileged workflow"
    severity = Severity.MEDIUM
    description = (
        "A workflow triggered by pull_request_target, workflow_run or issue_comment restores a "
        "cache. These workflows run in the context of the default branch, so a cache entry "
        "written by attacker-controlled code (for example from a pull request) can be restored "
        "by a job that has a write token or secrets."
    )
    remediation = (
        "Do not restore caches in workflows that run with write permissions or secrets: remove "
        "the cache step or turn caching off. If the cache is needed, use a key that untrusted "
        "workflows cannot write, or run the build in an unprivileged pull_request workflow."
    )

    def check(self, workflow: Workflow) -> Iterable[Finding]:
        triggers = workflow.privileged_triggers(_PRIVILEGED_CACHE_TRIGGERS)
        if not triggers:
            return
        trigger = sorted(triggers)[0]
        for step in workflow.steps():
            restored = _restores_cache(step)
            if restored is not None:
                yield self.finding(
                    workflow,
                    (*step.path, "uses"),
                    f"{restored} restores a cache in a '{trigger}' workflow, where an "
                    "attacker-written cache entry can be restored with elevated privileges",
                )


_ARTIFACT_TRIGGERS = frozenset({"workflow_run", "pull_request_target"})
_GH_RUN_DOWNLOAD = re.compile(r"(?<![\w-])gh\s+run\s+download\b")
_GH_DIR_FLAG = re.compile(r"(?:^|\s)(?:-D|--dir)(?:\s+|=)([\"']?)([^\s\"']+)\1")

_ENV_SINK = re.compile(
    r"(?:>>?|\btee\b(?:\s+-a)?|\bOut-File\b[^\n]*?|\bAdd-Content\b[^\n]*?)\s*[\"']?"
    r"\$(?:env:)?\{?GITHUB_(ENV|OUTPUT|PATH|STATE)\b",
    re.IGNORECASE,
)
_READERS = r"cat|jq|head|tail|sed|awk|cut|grep|Get-Content|gc|type"
# A command that reads a file: first in a pipeline, in `$(...)`, or in backticks; or `< file`.
_FILE_READ = re.compile(
    rf"(?:^|[(`;&]|\$\()\s*(?:{_READERS})\s+(?!<)\S|\$\(\s*<|(?<![<\d])<\s*[^\s<(&]",
    re.IGNORECASE,
)
# Reducing the content to digits makes it harmless to put in the environment or an output:
# `tr -cd 0-9`, `| tonumber`, or `grep` keeping only lines that are entirely digits.
_SANITIZED = re.compile(
    r"\btr\s+-(?:cd|dc)\s+[\"']?\[?(?:0-9|:digit:)|\|\s*tonumber\b"
    r"|\bgrep\s+(?:-[^\sv]+\s+)*[\"']\^(?:\[0-9\]|\\d)\+\$[\"']",
    re.IGNORECASE,
)
# The webhook payload is not an artifact.
_EVENT_PAYLOAD = re.compile(r"GITHUB_EVENT_PATH")

_RUNNERS = frozenset(
    {"source", ".", "bash", "sh", "zsh", "dash", "python", "python3", "node", "ruby", "perl"}
    | {"pwsh"}
)
_BUILD = re.compile(
    r"^(?:npm\s+(?:install|i|ci|run|test|start|exec)|yarn|pnpm|bun\s+(?:install|run)"
    r"|make|cmake|pip3?\s+install|python3?\s+setup\.py|cargo\s+(?:build|run|test)|mvn|gradle"
    r"|\./gradlew|docker\s+build|dotnet\s+(?:build|run|test)|go\s+(?:build|run|generate)"
    r"|bundle\s+(?:install|exec))\b",
    re.IGNORECASE,
)
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_]\w*=\S*$")
_SEGMENT_SPLIT = re.compile(r"&&|\|\||[;|\n]|\$\(|`")


def _normalize_dir(value: str) -> str:
    value = value.strip().strip("\"'").replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    return value.rstrip("/")


def _artifact_dir(value: object) -> str | None:
    """Normalized download directory, or None when it is the workspace root or unknown."""
    if not isinstance(value, str):
        return None
    normalized = _normalize_dir(value)
    return None if normalized in {"", ".", "~"} else normalized


def _in_dir(path: str, directory: str) -> bool:
    path = _normalize_dir(path)
    return path == directory or path.startswith(f"{directory}/")


def _logical_lines(script: str) -> Iterator[tuple[int, str]]:
    """Yield (character offset, text) per shell command line, joining backslash continuations."""
    offset = 0
    position = 0
    pending: list[str] = []
    for line in script.split("\n"):
        if not pending:
            offset = position
        position += len(line) + 1
        if line.endswith("\\"):
            pending.append(line[:-1])
            continue
        pending.append(line)
        yield offset, " ".join(part.strip() for part in pending)
        pending = []
    if pending:
        yield offset, " ".join(part.strip() for part in pending)


def _download(step: Step) -> tuple[bool, str | None, int]:
    """Whether `step` downloads artifacts from another run, into which directory, and where.

    The last item is the character offset inside a `run:` script; it is 0 for `uses:` steps.
    """
    action = _action(step)
    if action == "actions/download-artifact":
        inputs = step.inputs
        if "run-id" in inputs or "github-token" in inputs:
            return True, _artifact_dir(inputs.get("path")), 0
    elif action == "dawidd6/action-download-artifact":
        return True, _artifact_dir(step.inputs.get("path")), 0
    script = step.run
    if script is not None:
        for offset, line in _logical_lines(script):
            if _GH_RUN_DOWNLOAD.search(line) and not line.lstrip().startswith("#"):
                flag = _GH_DIR_FLAG.search(line)
                return True, _artifact_dir(flag.group(2)) if flag else None, offset
    return False, None, 0


def _words(segment: str) -> list[str]:
    words = segment.split()
    while words and _ENV_ASSIGNMENT.match(words[0]):
        words.pop(0)
    if words and words[0] == "sudo":
        words.pop(0)
    return words


def _first_operand(words: list[str]) -> str | None:
    return next((word for word in words if not word.startswith("-")), None)


def _script_misuse(script: str, directory: str | None, working: bool) -> str | None:
    """Describe the first unsafe use of downloaded content in a shell script."""
    cwd_in_dir = working
    for _, line in _logical_lines(script):
        if line.lstrip().startswith("#"):
            continue
        sink = _ENV_SINK.search(line)
        if (
            sink
            and _FILE_READ.search(line)
            and not _SANITIZED.search(line)
            and not _EVENT_PAYLOAD.search(line)
        ):
            return f"file content is written to GITHUB_{sink.group(1).upper()}"
        if directory is None and not cwd_in_dir:
            continue
        for segment in _SEGMENT_SPLIT.split(line):
            words = _words(segment.strip())
            if not words:
                continue
            command = words[0]
            if command == "cd" and len(words) > 1:
                cwd_in_dir = directory is not None and _in_dir(words[1], directory)
                continue
            if misuse := _segment_misuse(words, segment, directory, cwd_in_dir):
                return misuse
    return None


def _segment_misuse(
    words: list[str], segment: str, directory: str | None, cwd_in_dir: bool
) -> str | None:
    def inside(path: str) -> bool:
        if directory is not None and _in_dir(path, directory):
            return True
        return cwd_in_dir and not path.startswith(("/", "~", "$", "..", "-"))

    command = words[0]
    if command in _RUNNERS:
        target = _first_operand(words[1:])
        if target is not None and inside(target):
            return f"the downloaded file '{target}' is executed"
    elif ("/" in command or command.startswith(".")) and inside(command):
        return f"the downloaded file '{command}' is executed"
    elif command == "chmod" and any(inside(word) for word in words[1:] if "/" in word):
        return "a downloaded file is made executable"
    if _BUILD.match(" ".join(words)):
        in_dir = cwd_in_dir or (
            directory is not None and any(_in_dir(word, directory) for word in words[1:])
        )
        if in_dir:
            return f"a build ('{segment.strip()}') runs on downloaded content"
    return None


def _misuse(step: Step, directory: str | None) -> str | None:
    script = step.run
    if script is None:
        return None
    working = step.data.get("working-directory")
    working_in_dir = (
        isinstance(working, str) and directory is not None and _in_dir(working, directory)
    )
    return _script_misuse(script, directory, working_in_dir)


def _step_index(step: Step) -> int:
    index = step.path[-1]
    return index if isinstance(index, int) else -1


class ArtifactPoisoning(Rule):
    id = "GW012"
    title = "Artifact poisoning"
    severity = Severity.HIGH
    description = (
        "A workflow_run or pull_request_target workflow downloads artifacts produced by another "
        "run and then writes their content to GITHUB_ENV, GITHUB_OUTPUT or GITHUB_PATH, runs a "
        "downloaded file, or builds in the download directory. Artifacts from pull request "
        "workflows are attacker-controlled, so this gives them code execution with the "
        "privileges of the downloading workflow."
    )
    remediation = (
        "Treat downloaded artifacts as untrusted data: extract them to a temporary directory, "
        "never execute or build them, and validate any value (for example that it is a number) "
        "before writing it to GITHUB_ENV or GITHUB_OUTPUT."
    )

    def check(self, workflow: Workflow) -> Iterable[Finding]:
        triggers = workflow.privileged_triggers(_ARTIFACT_TRIGGERS)
        if not triggers:
            return
        trigger = sorted(triggers)[0]
        steps_by_job: dict[str, list[Step]] = {}
        for step in workflow.steps():
            if step.job is not None:
                steps_by_job.setdefault(step.job.id, []).append(step)
        for steps in steps_by_job.values():
            for position, step in enumerate(steps):
                downloads, directory, offset = _download(step)
                if not downloads:
                    continue
                for later in steps[position + 1 :]:
                    misuse = _misuse(later, directory)
                    if misuse is None:
                        continue
                    line = workflow.locate(later.path)[0]
                    yield self.finding(
                        workflow,
                        (*step.path, "uses" if step.uses else "run"),
                        f"Artifact downloaded in a '{trigger}' workflow is used unsafely: "
                        f"{misuse} (step at line {line})",
                        offset=offset,
                    )
                    break
