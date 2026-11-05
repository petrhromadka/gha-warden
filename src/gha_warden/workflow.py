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


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


class Workflow:
    """A parsed workflow (or composite action) file."""

    def __init__(self, path: str, text: str) -> None:
        self.path = path
        self.lines = text.splitlines()
        loader = yaml.SafeLoader(text)
        try:
            node = loader.get_single_node()
            data = loader.construct_document(node) if node is not None else {}
        except yaml.YAMLError as exc:
            raise WorkflowError(_describe_yaml_error(exc)) from exc
        finally:
            loader.dispose()
        if not isinstance(data, dict):
            raise WorkflowError("expected a mapping at the top level")
        # PyYAML (YAML 1.1) parses a bare `on` key as boolean True.
        if True in data and "on" not in data:
            data["on"] = data.pop(True)
        self.data: dict[str, Any] = data
        self.root: Node | None = node
        self.triggers = _triggers(data.get("on"))

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
        self, path: Sequence[PathPart], *, key: bool = False, line_offset: int = 0
    ) -> tuple[int, int]:
        """1-based (line, column) of the node at `path`.

        With `key=True` the position of the mapping key is returned. `line_offset` selects a
        line inside a literal block scalar (`run: |`). A path that does not exist falls back to
        its nearest existing ancestor.
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
        row, column = _start(value_node)
        if isinstance(value_node, ScalarNode) and value_node.style in ("|", ">"):
            offset = line_offset if value_node.style == "|" else 0
            line = min(row + 2 + offset, max(len(self.lines), 1))
            source = self.lines[line - 1] if self.lines else ""
            return line, len(source) - len(source.lstrip()) + 1
        return row + 1, column + 1

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
