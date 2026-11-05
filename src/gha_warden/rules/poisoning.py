"""Rules about attacker-controlled data crossing a trust boundary: GW011, GW012."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

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

# Data flow inside a script: `NAME=path` (also with export/local/readonly) and `for NAME in path`.
_PATH_ASSIGNMENT = re.compile(
    r"^(?:(?:export|local|readonly|declare(?:\s+-\w+)*)\s+)?([A-Za-z_]\w*)=(\S*)$"
)
_FOR_LOOP = re.compile(r"^for\s+([A-Za-z_]\w*)\s+in\s+(\S+)")
_VARIABLE = re.compile(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)")
_WHILE_READ = re.compile(r"\bwhile\b[^\n]*\bread\b")
_DONE = re.compile(r"(?:^|[;&]\s*)done\b(.*)$")
_TOKEN_SPLIT = re.compile(r"[\s\"'(){};|&<>`=,]+")
_RUNNER_TEMP = re.compile(
    r"\$\{\{\s*runner\.temp\s*\}\}|\$\{RUNNER_TEMP\}|\$env:RUNNER_TEMP", re.IGNORECASE
)
_WORKSPACE = re.compile(
    r"\$\{\{\s*github\.workspace\s*\}\}/?|\$\{?GITHUB_WORKSPACE\}?/?|\$env:GITHUB_WORKSPACE/?",
    re.IGNORECASE,
)
# A runner's operand that names a file, not inline code (`-c`/`-e` are skipped) or a module.
_FILE_LIKE = re.compile(r"/|\.\w+[\"']?$")
_DOWNLOAD_PATH_OUTPUT = re.compile(r"\$\{\{\s*steps\.([\w-]+)\.outputs\.download-path\s*\}\}")

# actions/github-script: reading a file and handing its content to a workflow command.
_JS_READ = re.compile(r"\b(?:readFileSync|readFile|createReadStream)\s*\(")
_JS_REQUIRE = re.compile(r"\brequire\s*\(\s*([\"'`])([^\"'`]+)\1\s*\)")
_JS_SINK = re.compile(r"\bcore\.(exportVariable|setOutput|addPath)\s*\(")
_JS_SINK_FILES = {"exportVariable": "ENV", "setOutput": "OUTPUT", "addPath": "PATH"}
_JS_STRING = re.compile(r"([\"'`])((?:(?!\1)[^\\\n]|\\.)*)\1")
_JS_SANITIZED = re.compile(
    r"\b(?:parseInt|parseFloat|Number)\s*\(|/\^(?:\\d|\[0-9\])\+\$/", re.IGNORECASE
)


def _normalize_dir(value: str) -> str:
    value = _RUNNER_TEMP.sub("$RUNNER_TEMP", value.strip().strip("\"'"))
    value = _WORKSPACE.sub("", value).replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    return value.rstrip("/")


def _artifact_dir(value: object) -> str | None:
    """Normalized download directory, or None when it is the workspace root or unknown."""
    if not isinstance(value, str):
        return None
    normalized = _normalize_dir(value)
    if normalized in {"", ".", "~"} or "${{" in normalized:
        return None
    return normalized


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


@dataclass(frozen=True)
class _Download:
    """Where a step puts artifacts of another run.

    `directory` is None when the download goes to the workspace root or to a place that is not
    known, so any file the job reads may come from the artifact.
    """

    directory: str | None
    offset: int  # of the download line in a `run:` script; 0 for `uses:` steps
    rest: str  # the part of a `run:` script after the download line


def _download(step: Step) -> _Download | None:
    """The artifact download `step` performs, if any."""
    action = _action(step)
    if action == "actions/download-artifact":
        inputs = step.inputs
        if "run-id" in inputs or "github-token" in inputs:
            return _Download(_artifact_dir(inputs.get("path")), 0, "")
    elif action == "dawidd6/action-download-artifact":
        return _Download(_artifact_dir(step.inputs.get("path")), 0, "")
    script = step.run
    if script is not None:
        lines = list(_logical_lines(script))
        for index, (offset, line) in enumerate(lines):
            if _GH_RUN_DOWNLOAD.search(line) and not line.lstrip().startswith("#"):
                flag = _GH_DIR_FLAG.search(line)
                rest = script[lines[index + 1][0] :] if index + 1 < len(lines) else ""
                return _Download(_artifact_dir(flag.group(2)) if flag else None, offset, rest)
    return None


class _Flow:
    """What a script knows about the download: its directory and variables holding paths."""

    def __init__(self, directory: str | None, variables: dict[str, str]) -> None:
        self.directory = directory
        self.variables = dict(variables)

    def expand(self, text: str) -> str:
        """Substitute known variables and spell runner.temp and the workspace one way."""

        def value(match: re.Match[str]) -> str:
            name = match.group(1) or match.group(2)
            return self.variables.get(name, match.group(0))

        return _normalize_dir(_VARIABLE.sub(value, _RUNNER_TEMP.sub("$RUNNER_TEMP", text)))

    def is_artifact(self, path: str) -> bool:
        """Whether `path` (a word of the script) is in the download directory."""
        return self.directory is not None and _in_dir(self.expand(path), self.directory)

    def reads_artifact(self, text: str) -> bool:
        """Whether `text` reads a file that may come from the download."""
        read = _FILE_READ.search(text)
        if read is None or _EVENT_PAYLOAD.search(text):
            return False
        if self.directory is None:
            return True
        region = _ENV_SINK.sub(" ", self.expand(text[read.start() :]))
        return any(_in_dir(token, self.directory) for token in _TOKEN_SPLIT.split(region) if token)

    def assign(self, segment: str) -> None:
        """Track `NAME=value` and `for NAME in value`; forget names set to anything else."""
        if match := _FOR_LOOP.match(segment):
            self.variables[match.group(1)] = self.expand(match.group(2))
        elif match := _PATH_ASSIGNMENT.match(segment):
            name, value = match.groups()
            if value and not value.startswith(("$(", "`")):
                self.variables[name] = self.expand(value)
            else:
                self.variables.pop(name, None)


def _sink(line: str) -> str | None:
    sink = _ENV_SINK.search(line)
    return sink.group(1).upper() if sink else None


def _script_misuse(script: str, flow: _Flow, working: bool) -> str | None:
    """Describe the first unsafe use of downloaded content in a shell script."""
    directory = flow.directory
    cwd_in_dir = working
    loops: list[tuple[int, bool]] = []  # open `while read` loops: body start, input tainted
    lines = [line for _, line in _logical_lines(script)]
    for index, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            continue
        sink = _sink(line)
        if sink and not _SANITIZED.search(line) and flow.reads_artifact(line):
            return f"file content is written to GITHUB_{sink}"
        loop = _WHILE_READ.search(line)
        if (done := _DONE.search(line)) and loops and not loop:
            start, piped = loops.pop()
            if piped or flow.reads_artifact(done.group(1)):
                body = lines[start : index + 1]
                written = next((name for name in map(_sink, body) if name), None)
                if written and not any(_SANITIZED.search(part) for part in body):
                    return f"file content is written to GITHUB_{written} in a loop"
        elif loop and not done:
            loops.append((index, flow.reads_artifact(line[: loop.start()])))
        for segment in _SEGMENT_SPLIT.split(line):
            words = _words(segment.strip())
            if not words:
                continue
            flow.assign(" ".join(words))
            command = words[0]
            if command == "cd" and len(words) > 1:
                target = flow.expand(words[1])
                cwd_in_dir = (
                    _in_dir(target, directory)
                    if directory is not None
                    else not target.startswith(("/", "~", "$", ".."))
                )
                continue
            if misuse := _segment_misuse(words, segment, flow, cwd_in_dir):
                return misuse
    return None


def _words(segment: str) -> list[str]:
    words = segment.split()
    while len(words) > 1 and _ENV_ASSIGNMENT.match(words[0]):
        words.pop(0)
    if words and words[0] == "sudo":
        words.pop(0)
    return words


def _first_operand(words: list[str]) -> str | None:
    return next((word for word in words if not word.startswith("-")), None)


def _segment_misuse(words: list[str], segment: str, flow: _Flow, cwd_in_dir: bool) -> str | None:
    def inside(path: str) -> bool:
        if flow.is_artifact(path):
            return True
        return cwd_in_dir and not flow.expand(path).startswith(("/", "~", "$", "..", "-"))

    command = words[0]
    if _ENV_ASSIGNMENT.match(command):
        return None
    if command in _RUNNERS:
        target = _first_operand(words[1:])
        if target is not None and _FILE_LIKE.search(target) and inside(target):
            return f"the downloaded file '{target}' is executed"
    elif ("/" in command or command.startswith(".")) and inside(command):
        return f"the downloaded file '{command}' is executed"
    elif command == "chmod" and any(inside(word) for word in words[1:] if "/" in word):
        return "a downloaded file is made executable"
    if _BUILD.match(" ".join(words)):
        in_dir = cwd_in_dir or any(flow.is_artifact(word) for word in words[1:])
        if in_dir:
            return f"a build ('{segment.strip()}') runs on downloaded content"
    return None


def _github_script_misuse(script: str, flow: _Flow) -> str | None:
    """Describe an actions/github-script that loads or exports a downloaded file."""
    for match in _JS_REQUIRE.finditer(script):
        path = match.group(2)
        local = path.startswith((".", "/"))
        if flow.is_artifact(path) or (flow.directory is None and local):
            return f"the downloaded file '{path}' is loaded with require()"
    sink = _JS_SINK.search(script)
    if sink is None or not _JS_READ.search(script) or _JS_SANITIZED.search(script):
        return None
    if flow.directory is None or any(
        flow.is_artifact(literal.group(2)) for literal in _JS_STRING.finditer(script)
    ):
        method = sink.group(1)
        return f"file content is written to GITHUB_{_JS_SINK_FILES[method]} (core.{method})"
    return None


def _env(*sources: object) -> dict[str, str]:
    merged: dict[str, str] = {}
    for source in sources:
        if isinstance(source, dict):
            merged.update(
                {str(k): str(v) for k, v in source.items() if isinstance(v, (str, int, float))}
            )
    return merged


def _flow(workflow: Workflow, download_step: Step, download: _Download, step: Step) -> _Flow:
    """The data-flow state at the start of `step`: download directory and env variables."""
    job = step.job.data if step.job is not None else {}
    download_id = download_step.data.get("id")
    replacement = download.directory if download.directory is not None else "."

    def resolve(value: str) -> str:
        def output(match: re.Match[str]) -> str:
            return replacement if match.group(1) == download_id else match.group(0)

        return _DOWNLOAD_PATH_OUTPUT.sub(output, value)

    env = _env(workflow.data.get("env"), job.get("env"), step.data.get("env"))
    flow = _Flow(download.directory, {})
    flow.variables = {name: flow.expand(resolve(value)) for name, value in env.items()}
    return flow


def _misuse(flow: _Flow, step: Step, script: str | None = None) -> str | None:
    if _action(step) == "actions/github-script":
        code = step.inputs.get("script")
        return _github_script_misuse(code, flow) if isinstance(code, str) else None
    script = step.run if script is None else script
    if script is None:
        return None
    working = step.data.get("working-directory")
    if flow.directory is None:
        working_in_dir = not (
            isinstance(working, str) and flow.expand(working).startswith(("/", "~", "$", ".."))
        )
    else:
        working_in_dir = isinstance(working, str) and flow.is_artifact(working)
    return _script_misuse(script, flow, working_in_dir)


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
                download = _download(step)
                if download is None:
                    continue
                uses: list[tuple[Step, str | None]] = [(step, download.rest)]
                uses += [(later, None) for later in steps[position + 1 :]]
                for later, script in uses:
                    if later is step and not script:
                        continue
                    misuse = _misuse(_flow(workflow, step, download, later), later, script)
                    if misuse is None:
                        continue
                    line = workflow.locate(later.path)[0]
                    yield self.finding(
                        workflow,
                        (*step.path, "uses" if step.uses else "run"),
                        f"Artifact downloaded in a '{trigger}' workflow is used unsafely: "
                        f"{misuse} (step at line {line})",
                        offset=download.offset,
                    )
                    break
