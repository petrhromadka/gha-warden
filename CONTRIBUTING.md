# Contributing

## Development setup

You need [uv](https://docs.astral.sh/uv/) and Python 3.12 or newer.

```sh
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run ty check
```

All checks must pass with zero warnings. CI also runs `uv run gha-warden .github/workflows action.yml` against this repository's own workflows, and that scan must stay clean.

## Adding a rule

1. Add a module under `src/gha_warden/` with the rule's `id`, `title`, `severity`, `description`, `remediation` and a `check(workflow)` that yields `Finding` objects, and register it in the rule list.
2. Add fixtures: at least one workflow that triggers the rule and one that must not, including near misses.
3. Add tests that load both fixtures and assert the rule ID, line number and severity.
4. Add a row to the rules table in `README.md`, and extend a file in `examples/vulnerable/` so the demos still trigger every rule.
5. Check that `examples/safe/` still reports nothing.

Use obviously fake values in fixtures (for example `hunter2-not-real`); never commit real credentials.

## Commits and pull requests

- One logical change per commit.
- Imperative subject line of at most 72 characters ("Add GW011 rule", not "Added" or "Adds").
- Describe in the pull request what the diff does.
