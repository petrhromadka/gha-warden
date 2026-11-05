# gha-warden — spec

Static security auditor for GitHub Actions workflow files. Finds supply-chain and
injection risks before they ship. Pure static analysis: no network, no tokens.

## Stack

- Python >= 3.12, managed with `uv` (`uv init --package`, src layout, package `gha_warden`).
- Runtime dependency: `pyyaml` only (YAML parsing; `yaml.compose` gives node line numbers).
- Dev: `pytest`, `ruff` (lint + format), `ty` (type check). Zero warnings.
- Console script: `gha-warden`.

## CLI

```
gha-warden [PATHS...] [--format text|json|sarif] [--min-severity low|medium|high|critical]
           [--ignore RULE_ID ...] [--output FILE] [--no-color]
```

- PATHS: files or directories; default `.github/workflows`. Directories are scanned for
  `*.yml` / `*.yaml` recursively. Also scans composite `action.yml` / `action.yaml` if passed.
- Exit codes: 0 = no findings at/above min severity, 1 = findings, 2 = usage/parse error.
- Inline suppression: a YAML comment `# gha-warden: ignore[GW001]` on the finding's line
  (or `ignore` with no list = all rules) suppresses it.

## Core model

```python
class Severity(IntEnum): LOW=1; MEDIUM=2; HIGH=3; CRITICAL=4

@dataclass(frozen=True)
class Finding:
    rule_id: str; severity: Severity; message: str
    path: str; line: int; column: int; remediation: str
```

A `Workflow` wrapper gives rules: the parsed data, the triggers (`on:` normalized to a set
of event names — note PyYAML parses bare `on` as boolean `True`, handle it), jobs, steps,
and line numbers for any node. Rules are small classes/functions registered in one list;
each has `id`, `title`, `severity`, `description`, `remediation`, `check(workflow) -> Iterable[Finding]`.

## Rules (each with positive + negative test fixtures)

| ID | Title | Severity |
|----|-------|----------|
| GW001 | Script injection: untrusted `${{ }}` context in `run:` or `actions/github-script` `script:` (github.event.issue.title/body, pull_request.title/body/head.ref/head.label, comment.body, review.body, review_comment.body, pages.*.page_name, commits.*.message/author, head_commit.message/author, github.head_ref, discussion.title/body, workflow_run.head_branch/head_commit.*) | critical |
| GW002 | Pwn request: `pull_request_target` or `workflow_run` workflow checks out untrusted PR code (`actions/checkout` with `ref:` using github.event.pull_request.head.*, github.head_ref, or workflow_run.head_*) | critical |
| GW003 | Third-party action not pinned to a full 40-char commit SHA (skip `./local` and `docker://` with digest; `actions/*` and `github/*` owners are MEDIUM, others HIGH) | high |
| GW004 | Excessive permissions: `permissions: write-all`, or no top-level `permissions:` and a job lacks its own | medium |
| GW005 | `actions/checkout` without `persist-credentials: false` (token left in .git/config, readable by later steps / uploaded artifacts) | low |
| GW006 | Reusable workflow call with `secrets: inherit` | medium |
| GW007 | Self-hosted runner used by a job in a workflow triggered by `pull_request`/`pull_request_target` | high |
| GW008 | `ACTIONS_ALLOW_UNSECURE_COMMANDS` enabled in env (workflow/job/step) | high |
| GW009 | Remote script piped to a shell in `run:` (`curl ... \| bash`, `wget -O- ... \| sh`, etc.) | medium |
| GW010 | Hardcoded credential-looking literal in `env:` or `with:` (keys named like token/password/secret/api_key with a non-expression literal value) | high |

## Output formats

- text: grouped by file, colored severity (respect `--no-color` and `NO_COLOR`), summary line.
- json: list of findings + summary counts.
- sarif: SARIF 2.1.0 with `tool.driver.rules` populated from rule metadata
  (`help.text` = remediation, `properties.security-severity` as string: low 3.0, medium 5.0,
  high 7.5, critical 9.5), so GitHub code scanning shows it.

## Repo extras

- `action.yml` (composite) so others can `uses: petrhromadka/gha-warden@<sha>`; uploads SARIF optionally.
- CI: ruff, ty, pytest on Linux + Windows; gha-warden scans its own workflows (dogfood) — must be clean.
- `examples/vulnerable/*.yml` demo workflows that trigger every rule, `examples/safe/` that trigger none.
- README with badges, demo output, rule table, quick start; LICENSE (MIT); SECURITY.md; CONTRIBUTING.md.
- Never commit secrets: fixtures use obviously fake values like `hunter2-not-real`.
