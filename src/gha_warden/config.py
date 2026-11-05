"""Config file: `.gha-warden.toml` in the current directory, or the file given by `--config`."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

from gha_warden.models import Severity
from gha_warden.rules import ALL_RULES

CONFIG_FILENAME = ".gha-warden.toml"
_KEYS = ("ignore", "min-severity", "exclude")


class ConfigError(Exception):
    """The config file is missing, unreadable or invalid."""


@dataclass(frozen=True)
class Config:
    ignore: tuple[str, ...] = ()
    min_severity: Severity | None = None
    exclude: tuple[str, ...] = ()

    def is_excluded(self, path: str) -> bool:
        """Match a display path (forward slashes); `*` also matches across directories."""
        return any(fnmatchcase(path, pattern) for pattern in self.exclude)


def _string_list(data: dict[str, object], key: str) -> tuple[str, ...]:
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"'{key}' must be a list of strings")
    return tuple(value)


def parse_config(text: str) -> Config:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML: {exc}") from exc
    unknown = sorted(set(data) - set(_KEYS))
    if unknown:
        raise ConfigError(f"unknown key '{unknown[0]}' (allowed: {', '.join(_KEYS)})")

    ignore = tuple(item.strip().upper() for item in _string_list(data, "ignore"))
    known = {rule.id for rule in ALL_RULES}
    for rule_id in ignore:
        if rule_id not in known:
            raise ConfigError(f"unknown rule id '{rule_id}' in 'ignore'")

    min_severity = None
    if "min-severity" in data:
        name = data["min-severity"]
        labels = [s.label for s in Severity]
        if not isinstance(name, str) or name.lower() not in labels:
            raise ConfigError(f"'min-severity' must be one of: {', '.join(labels)}")
        min_severity = Severity.parse(name)

    return Config(ignore, min_severity, _string_list(data, "exclude"))


def load_config(explicit: Path | None) -> Config:
    """Load `explicit`, else `.gha-warden.toml` from the current directory if it exists."""
    path = explicit if explicit is not None else Path(CONFIG_FILENAME)
    if explicit is None and not path.is_file():
        return Config()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{path}: cannot read config: {exc}") from exc
    try:
        return parse_config(text)
    except ConfigError as exc:
        raise ConfigError(f"{path}: {exc}") from exc
