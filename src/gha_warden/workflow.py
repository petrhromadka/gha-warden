"""Workflow wrapper: parsed data plus line numbers for any node."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

type PathPart = str | int
type NodePath = tuple[PathPart, ...]


class WorkflowError(Exception):
    """The file could not be parsed as a workflow."""


@dataclass(frozen=True)
class Job:
    id: str
    path: NodePath
    data: dict[str, Any]


@dataclass(frozen=True)
class Step:
    job: Job | None
    path: NodePath
    data: dict[str, Any]

    @property
    def uses(self) -> str | None:
        value = self.data.get("uses")
        return value if isinstance(value, str) else None

    @property
    def run(self) -> str | None:
        value = self.data.get("run")
        return value if isinstance(value, str) else None

    @property
    def inputs(self) -> dict[str, Any]:
        value = self.data.get("with")
        return value if isinstance(value, dict) else {}


def _triggers(on: object) -> frozenset[str]:
    if isinstance(on, str):
        return frozenset({on})
    if isinstance(on, list):
        return frozenset(str(item) for item in on)
    if isinstance(on, dict):
        return frozenset(str(key) for key in on)
    return frozenset()


# Events that a stranger can cause: a fork pull request, an issue, a comment, a star or a fork.
UNTRUSTED_TRIGGERS = frozenset(
    {
        "pull_request",
        "pull_request_target",
        "issue_comment",
        "pull_request_review",
        "pull_request_review_comment",
        "issues",
        "discussion",
        "discussion_comment",
        "fork",
        "watch",
        # Anyone can edit an open wiki; outside apps can send check and status events;
        # a merge queue runs pull request code.
        "gollum",
        "check_run",
        "check_suite",
        "status",
        "merge_group",
    }
)
# GitHub filter-pattern syntax: a name containing any of these is a pattern, not a literal.
_PATTERN_CHARS = frozenset("*?+![]\\")


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


class Workflow:
    """A parsed workflow (or composite action) file."""

    def __init__(self, path: str, text: str) -> None:
        self.path = path
        self.lines = text.splitlines()
        loader = None
        try:
            # The constructor already rejects control characters, so it belongs inside the try.
            loader = yaml.SafeLoader(text)
            node = loader.get_single_node()
            data = loader.construct_document(node) if node is not None else {}
        except yaml.YAMLError as exc:
            raise WorkflowError(_describe_yaml_error(exc)) from exc
        except RecursionError as exc:
            raise WorkflowError("invalid YAML: nesting too deep") from exc
        except ValueError as exc:  # e.g. an integer literal over Python's digit limit
            raise WorkflowError(f"invalid YAML: {exc}") from exc
        finally:
            if loader is not None:
                loader.dispose()
        if not isinstance(data, dict):
            raise WorkflowError("expected a mapping at the top level")
        # PyYAML (YAML 1.1) parses a bare `on` key as boolean True.
        if True in data and "on" not in data:
            data["on"] = data.pop(True)
        self.data: dict[str, Any] = data
        self.root: Node | None = node
        self.triggers = _triggers(data.get("on"))
        self.name = _run_name(data.get("name"), path)
        # Workflows scanned together, by name; set by `link_workflows`.
        self.scanned: dict[str, list[Workflow]] = {}

    def privileged_triggers(self, candidates: frozenset[str]) -> frozenset[str]:
        """The triggers in `candidates` that give untrusted input a privileged run of this file.

        `workflow_run` is dropped when every upstream workflow it names was scanned together with
        this one and none of them can be started by untrusted input, so no fork can reach it.
        """
        triggers = self.triggers & candidates
        if "workflow_run" in triggers and not self._started_by_untrusted(set()):
            triggers -= {"workflow_run"}
        return triggers

    def _started_by_untrusted(self, visiting: set[int]) -> bool:
        """Whether untrusted input can start this workflow, or this is not known.

        Only the `workflow_run` trigger is followed upstream. A workflow that is already being
        visited adds nothing new (a cycle), so it counts as not reachable.
        """
        if self.triggers & UNTRUSTED_TRIGGERS:
            return True
        if "workflow_run" not in self.triggers or id(self) in visiting:
            return False
        visiting.add(id(self))
        names = _as_dict(_as_dict(self.data.get("on")).get("workflow_run")).get("workflows")
        if not isinstance(names, list) or not names:
            return True
        for name in names:
            upstream = self.scanned.get(name.casefold()) if isinstance(name, str) else None
            if not upstream or _PATTERN_CHARS & set(str(name)):
                return True
            if any(workflow._started_by_untrusted(visiting) for workflow in upstream):
                return True
        return False

    def jobs(self) -> list[Job]:
        return [
            Job(str(job_id), ("jobs", job_id), job)
            for job_id, job in _as_dict(self.data.get("jobs")).items()
            if isinstance(job, dict)
        ]

    def steps(self) -> list[Step]:
        """All steps of all jobs, plus the steps of a composite action."""
        result: list[Step] = []
        for job in self.jobs():
            result.extend(self._steps_at(job, job.data.get("steps"), (*job.path, "steps")))
        runs = _as_dict(self.data.get("runs"))
        result.extend(self._steps_at(None, runs.get("steps"), ("runs", "steps")))
        return result

    @staticmethod
    def _steps_at(job: Job | None, steps: object, path: NodePath) -> Iterator[Step]:
        if not isinstance(steps, list):
            return
        for index, step in enumerate(steps):
            if isinstance(step, dict):
                yield Step(job, (*path, index), step)

    def blocks(self, *names: str) -> Iterator[tuple[NodePath, dict[str, Any]]]:
        """Mappings named `names` at workflow, job and step level, with their paths."""
        scopes: list[tuple[NodePath, dict[str, Any]]] = [((), self.data)]
        scopes += [(job.path, job.data) for job in self.jobs()]
        scopes += [(step.path, step.data) for step in self.steps()]
        for base, scope in scopes:
            for name in names:
                block = scope.get(name)
                if isinstance(block, dict):
                    yield (*base, name), block

    def locate(
        self, path: Sequence[PathPart], *, key: bool = False, offset: int = 0
    ) -> tuple[int, int]:
        """1-based (line, column) of the node at `path`.

        With `key=True` the position of the mapping key is returned. `offset` is a character
        index into the node's string value; it selects the line inside a multi-line scalar
        (`run: |`, `run: >`, or a quoted or plain scalar that spans lines). A path that does
        not exist falls back to its nearest existing ancestor.
        """
        parts = tuple(path)
        found = self._resolve(parts)
        while found is None and parts:
            parts = parts[:-1]
            found = self._resolve(parts)
        if found is None:
            return 1, 1
        key_node, value_node = found
        if key and key_node is not None:
            row, column = _start(key_node)
            return row + 1, column + 1
        if isinstance(value_node, ScalarNode):
            inside = self._locate_in_scalar(value_node, offset)
            if inside is not None:
                return inside
        row, column = _start(value_node)
        return row + 1, column + 1

    def _indent_of(self, line: int) -> tuple[int, int]:
        """Clamp 1-based `line` to the file and return it with its indentation column."""
        line = min(line, max(len(self.lines), 1))
        source = self.lines[line - 1] if self.lines else ""
        return line, len(source) - len(source.lstrip()) + 1

    def _locate_in_scalar(self, node: ScalarNode, offset: int) -> tuple[int, int] | None:
        """Position of character `offset` of a multi-line scalar's value, if it can be found."""
        row, column = _start(node)
        end_row = node.end_mark.line if node.end_mark else row
        text = node.value
        if node.style == "|":
            # Literal blocks keep their line breaks, so the value line is the source line.
            return self._indent_of(row + 2 + text.count("\n", 0, offset))
        block = node.style == ">"
        if end_row == row and not block:
            return None
        # Folded, quoted and plain scalars fold line breaks into spaces, so the value line says
        # nothing about the source line. Find the n-th occurrence of the word at `offset` in the
        # source lines of the scalar instead, n being how often the word occurs before it.
        start = offset
        while start < len(text) and text[start].isspace():
            start += 1
        end = start
        while end < len(text) and not text[end].isspace():
            end += 1
        word = text[start:end]
        if word:
            remaining = text.count(word, 0, start)
            first = row + 1 if block else row
            for index in range(first, min(end_row, len(self.lines) - 1) + 1):
                source = self.lines[index]
                at = column if index == row else 0
                while (at := source.find(word, at)) != -1:
                    if remaining == 0:
                        if index == row:
                            return row + 1, at + 1
                        return self._indent_of(index + 1)
                    remaining -= 1
                    at += len(word)
        return self._indent_of(row + 2) if block else None

    def _resolve(self, path: NodePath) -> tuple[Node | None, Node] | None:
        node = self.root
        if node is None:
            return None
        key_node: Node | None = None
        for part in path:
            if isinstance(node, MappingNode):
                for candidate, value in node.value:
                    if isinstance(candidate, ScalarNode) and candidate.value == str(part):
                        key_node, node = candidate, value
                        break
                else:
                    return None
            elif isinstance(node, SequenceNode) and isinstance(part, int):
                if part >= len(node.value):
                    return None
                key_node, node = None, node.value[part]
            else:
                return None
        return key_node, node


def _run_name(name: object, path: str) -> str:
    """The name GitHub shows for a run and matches in `workflow_run.workflows`.

    A workflow without a `name:` is known by its file path in the repository.
    """
    if isinstance(name, str) and name:
        return name
    posix = path.replace("\\", "/")
    marker = ".github/workflows/"
    return posix[posix.rfind(marker) :] if marker in posix else posix


def link_workflows(workflows: Sequence[Workflow]) -> None:
    """Let each workflow see the others scanned with it, for `workflow_run` upstream lookups."""
    scanned: dict[str, list[Workflow]] = {}
    for workflow in workflows:
        if "on" in workflow.data:
            # Grouped case-insensitively: whether GitHub folds case is undocumented, and treating
            # 'CI' and 'ci' as one workflow can only keep a finding, never hide one.
            scanned.setdefault(workflow.name.casefold(), []).append(workflow)
    for workflow in workflows:
        workflow.scanned = scanned


def _start(node: Node) -> tuple[int, int]:
    mark = node.start_mark
    return (mark.line, mark.column) if mark else (0, 0)


def _describe_yaml_error(exc: yaml.YAMLError) -> str:
    if isinstance(exc, yaml.MarkedYAMLError):
        problem = exc.problem or "invalid YAML"
        mark = exc.problem_mark
        if mark is not None:
            return f"invalid YAML at line {mark.line + 1}, column {mark.column + 1}: {problem}"
        return f"invalid YAML: {problem}"
    return f"invalid YAML: {exc}"
