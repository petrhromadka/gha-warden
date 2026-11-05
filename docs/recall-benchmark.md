# Recall benchmark against zizmor

Date: 2026-11-05. gha-warden at the commit before this page (v0.1.2 code
plus the fixes listed below); zizmor 1.32.0 (the current release on PyPI on
that date), run with `uvx zizmor@1.32.0`.

This page measures missed detections (recall) of gha-warden by comparing it
with [zizmor](https://docs.zizmor.sh/), a mature static auditor for GitHub
Actions. zizmor is used as a reference, not as ground truth: where the two
disagree, the finding was read and classified by hand. **This is not a
judgment of zizmor.** The two tools have different goals and personas, and a
difference below often means a deliberate difference in scope. Repositories
and files are not named; numbers are aggregate.

## Method

1. Inputs: the same 1068 workflow files from 42 popular public repositories
   used in the [real-world scan](real-world-scan.md), plus the incident
   corpus in `corpus/` and `examples/vulnerable/`, plus one hand-built file
   with 20 candidate injection contexts. Nothing from the downloaded data was
   executed.
2. zizmor: `zizmor --offline --no-config --no-ignores --format json`, once
   with the default `regular` persona and once with `--persona auditor`. The
   data was laid out as `<repo>/.github/workflows/*.yml` so zizmor collects it.
   zizmor stopped with an internal error (`unexpected node: comment` in the
   `artipacked` audit) on one file; it was run per repository and per file so
   that only that one file is missing from its results. `--offline` disables
   zizmor's online audits, including `known-vulnerable-actions`, so GW014 could
   not be compared.
3. gha-warden: `python -m gha_warden --format json` on the same tree.
4. Matching: a zizmor finding and a gha-warden finding of a mapped pair match
   when they are in the same file within 2 lines of each other (zizmor rows
   are 0-based and were converted). File-level agreement is reported too,
   because the tools often point at different lines of the same construct.
5. Triage: for each mapped rule, up to 10 zizmor-only findings (or classes of
   findings, where hundreds share one shape) were read in context and
   classified as: real miss in gha-warden, likely zizmor false positive, out of
   gha-warden's documented scope, or semantic difference. gha-warden-only
   findings were classified briefly.

## Mapping

Checked against zizmor's audit documentation (docs.zizmor.sh/audits).

| zizmor audit | gha-warden | Semantic difference |
|---|---|---|
| `template-injection` | GW001 | zizmor treats almost every expression in a code context as a potential injection, graded by severity and confidence (`env.*`, step outputs and `inputs.*` included). GW001 reports only a fixed list of contexts that an outside attacker controls. |
| `dangerous-triggers` | GW002 | zizmor reports the trigger itself (`pull_request_target`, `workflow_run`, `issue_comment`). GW002 needs such a trigger *and* a checkout or fetch of pull request code. |
| `unpinned-uses` | GW003 | Same intent. zizmor reports `docker://` references under `unpinned-images`; GW003 reports them itself. |
| `excessive-permissions` | GW004 | zizmor also reports individual write scopes at the workflow level and `read-all`. GW004 reports only `write-all` and missing permissions. |
| `artipacked` | GW005 | Same intent. |
| `secrets-inherit` | GW006 | Same intent; zizmor points at the `uses:` line, GW006 at `secrets:`. |
| `self-hosted-runner` (auditor only) | GW007 | zizmor reports self-hosted labels and runner groups on any trigger. GW007 reports the `self-hosted` label on `pull_request` / `pull_request_target` only. |
| `insecure-commands` | GW008 | Same intent. |
| `hardcoded-container-credentials` | GW010 | zizmor covers container and service credentials only; GW010 covers credentials in `env:` and `with:`. |
| `cache-poisoning` | GW011 | Opposite direction: zizmor reports cache *reads in release workflows*; GW011 reports cache restores in privileged-trigger workflows and documents release workflows as out of scope. |
| `unpinned-images` | GW013 | zizmor's regular persona reports only missing or `latest` tags; the auditor persona reports any image without a digest, like GW013. |
| `known-vulnerable-actions` | GW014 | Online audit (GitHub advisories); not run. GW014 uses a bundled list of compromises. |
| `overprovisioned-secrets` | GW015 | Same intent. |
| `bot-conditions` | GW017 | Same intent. |

No zizmor counterpart: GW009 (remote script piped to a shell), GW012
(artifact poisoning), GW016 (secret in `run:`). zizmor's `github-env` is
related to GW012 but checks writes to `GITHUB_ENV`/`GITHUB_PATH`, not
artifacts.

## Results on the real-world data

Counts before the fixes below. "Matched" counts zizmor findings that have a
gha-warden finding within 2 lines. Regular persona unless marked.

| Rule | zizmor | gha-warden | Matched | zizmor only | gha-warden only | Files z / g / both |
|---|--:|--:|--:|--:|--:|---|
| GW001 | 492 | 0 | 0 | 492 | 0 | 119 / 0 / 0 |
| GW002 | 126 | 4 | 0 | 126 | 4 | 119 / 4 / 4 |
| GW003 | 1410 | 1530 | 1410 | 0 | 119 | 389 / 420 / 389 |
| GW004 | 442 | 364 | 283 | 159 | 81 | 199 / 147 / 111 |
| GW005 | 678 | 724 | 672 | 6 | 49 | 338 / 365 / 338 |
| GW006 | 427 | 427 | 45 | 382 | 382 | 121 / 121 / 121 |
| GW007 (auditor) | 55 | 15 | 15 | 40 | 0 | 30 / 8 / 8 |
| GW008 | 0 | 0 | - | - | - | - |
| GW010 | 0 | 5 | - | 0 | 5 | - |
| GW011 | 104 | 10 | 0 | 104 | 10 | 23 / 8 / 0 |
| GW013 | 68 | 56 | 20 | 48 | 36 | 44 / 33 / 15 |
| GW013 (auditor) | 145 | 56 | 55 | 90 | 1 | 80 / 33 / 33 |
| GW015 | 0 | 0 | - | - | - | - |
| GW017 | 1 | 1 | 1 | 0 | 0 | 1 / 1 / 1 |

On the corpus and `examples/vulnerable/` (21 files), every zizmor
`template-injection` finding (10) had a GW001 finding within 2 lines, and
every zizmor finding of the mapped pairs GW003, GW005, GW006, GW008, GW015 and
GW017 matched as well. The only zizmor-only findings there were
`dangerous-triggers` on the trigger lines (semantic difference) and two
workflow-level write scopes (GW004 scope).

## Triage

### GW001

None of the 492 zizmor findings in the real-world data involves a context on
GW001's list, so the real-world data has no GW001 miss. The high-severity
classes were all read:

| Class (zizmor high severity) | Verdict |
|---|---|
| `github.ref_name`, `github.ref` | Out of scope: on `push` the ref is created by someone with write access; on pull request events it is not the fork's branch name. |
| `inputs.*`, `github.event.inputs.*` | Out of scope: set by a caller or a user who can dispatch the workflow (write access). |
| `github.event.workflow_run.head_sha` | Likely zizmor false positive: a 40-character hex value. |
| `github.actor`, `github.event.repository.name` | Likely zizmor false positive: GitHub restricts the characters of user and repository names. |
| `github.event.pull_request.base.ref`, `github.base_ref` | Out of scope: a branch of the base repository. |

Lower-severity classes (`env.*`, `matrix.*`, `steps.*.outputs.*`,
`needs.*.outputs.*`) are indirect values outside GW001's documented scope.

Because the real-world data had no in-scope cases, recall was tested with a
hand-built file of 20 contexts, each in its own `run:` step. zizmor reported
all 20; gha-warden reported 2. Classification of the other 18:

| Context | Verdict |
|---|---|
| `github.event.workflow_run.display_title` | Real miss (the title of the triggering pull request). Fixed. |
| `github.event.changes.title.from` | Real miss (old title in `edited` events). Fixed, together with `changes.body.from`. |
| `github.event.pull_request.head.repo.default_branch`, `.description`, `.homepage`; `github.event.workflow_run.head_repository.description` | Real miss (set by the fork owner). Fixed. |
| `github.event.merge_group.head_commit.message` | Real miss, consistent with the existing `head_commit.message` entry. Fixed. |
| `toJSON(github.event)`, `toJSON(github.event.issue)` | Real miss: JSON escaping does not neutralise `$(...)` or backticks. Fixed for whole event objects that contain listed fields. |
| `github.event.workflow_run.pull_requests[0].head.ref` | Not fixed: this list is understood to be empty for pull requests from forks; not verified in this run. |
| `github.event.check_suite.head_branch`, `check_run.check_suite.head_branch` | Not fixed: who controls the branch for these events was not verified. |
| `github.event.issue.user.login` | Likely zizmor false positive (restricted characters). |
| `github.event.pull_request.labels[0].name`, `.milestone.title`, `github.event.release.body` | Out of scope: set by maintainers or writers. |
| `github.event.issue.pull_request.html_url` | Likely zizmor false positive (generated by GitHub). |
| `github.event.discussion_comment.body` | Likely zizmor false positive: not a payload field; the comment is in `github.event.comment.body`, which GW001 covers. |

### GW002

zizmor reports 119 files with a privileged trigger; GW002 reported 4 of them.
Of the 115 others, 20 check out a ref or repository other than the default,
or run `git fetch` / `checkout` commands. Ten of them were read in context:

| Class | Files | Verdict |
|---|--:|---|
| Checkout of the default branch, `github.base_ref` or `github.sha` | 5 | Semantic difference: no pull request code. |
| `ref: ${{ needs.<job>.outputs.<name> }}` where a job in the same file resolves the pull request head | 1 | Real miss. Fixed; after the fix the rule also found a second file of this class that was not in the sample. |
| The same, but the job resolves it in a local composite action or is a reusable workflow call | 2 | Not visible to a per-file scan; not fixed. |
| `git fetch` / `git checkout "$VAR"` where `VAR` is set in `env:` to a pull request head value | 2 | Real miss, not fixed (see below). |

### Other rules

- GW003: all 1410 zizmor findings matched. gha-warden-only: 106 findings on
  `uses: $/...` self-repository references and 12 on `docker://` images
  (zizmor reports those under `unpinned-images`). GitHub's changelog of
  2026-07-30 confirms that `$/` resolves to the running commit, so these 106
  were gha-warden false positives. They are fixed (GW003 now skips `$/`), and
  the real-world GW003 count went from 1530 to 1424.
- GW004: of 159 zizmor-only findings, 63 are the same missing-permissions
  condition reported at the top of the file instead of at each job (every one
  of those files has GW004 findings); 91 are individual write scopes at the
  workflow level and 5 are `read-all`, both outside GW004's documented scope.
  No real miss.
- GW005: the 6 zizmor-only findings are the same steps reported more than 2
  lines apart, or steps reused through YAML aliases, which gha-warden reports
  at the anchor's line. No real miss.
- GW006: same 121 files and same total (427); only the reported line differs.
- GW007: the 40 zizmor-only findings (auditor persona) are runner groups or
  self-hosted labels in workflows without a pull request trigger, outside
  GW007's scope. One is a runner group in an `issue_comment` workflow; a
  runner group is not necessarily self-hosted, so it was not counted as a
  miss.
- GW011: all 104 zizmor-only findings are cache reads in release or tag-push
  workflows, which GW011 documents as out of scope.
- GW013: 28 of the auditor persona's 90 zizmor-only findings had a literal tag
  before an expression (`name:${{ ... }}`). Real miss: GW013 skipped every
  image containing `${{`. Fixed. Not fixed: images whose repository part is an
  expression (an expression there could also supply a digest), and
  `docker://` references (reported by GW003).
- GW017: the single finding matched.

## Fixes

| Rule | Repro test | Real-world count before → after |
|---|---|--:|
| GW001 | `GW001-recall-contexts` in `tests/test_rules.py` (negative case `GW001-trusted-object-fields`) | 0 → 0 |
| GW002 | `GW002-issue-comment-job-output` in `tests/test_rules_triggers.py` (negative case `GW002-unrelated-job-output`) | 4 → 6 |
| GW013 | `test_gw013_flags_tag_built_from_expression` in `tests/test_rules_images.py` | 56 → 84 |

The full real-world scan was re-run after the fixes. Only GW002 and GW013
changed; every other rule kept its count. The 2 new GW002 findings are
checkouts of a pull request head taken from another job's output, in an
`issue_comment` and a `workflow_run` workflow. The 28 new GW013 findings are
job containers and services with a literal repository and a tag built from a
matrix value or a job output; all are mutable tags, which is what the rule
reports. The corpus test still passes without changes to `corpus/`.

## Misses not fixed

- GW002 through shell variables: `env: HEAD_SHA: ${{ ... head ... }}` followed
  by `git checkout "$HEAD_SHA"`. Catching it needs data flow from `env:` into
  the script; left for a separate change with its own precision check.
- GW002 resolvers inside local composite actions or reusable workflows: not
  visible in a per-file scan.
- GW001 `workflow_run.pull_requests[*].head.ref` and `check_suite` branch
  names: attacker control not verified.

## Limitations

- One reviewer, one snapshot of each repository, samples of up to 10 per
  rule. A verdict says whether a pattern matches a rule's intent, not whether
  a workflow is exploitable.
- zizmor ran offline, so `known-vulnerable-actions` (GW014) and other online
  audits were not compared. One file is missing from zizmor's results because
  of the internal error noted above.
- Matching within 2 lines undercounts agreement when the tools point at
  different parts of one construct (GW004, GW006); the file-level column
  shows that.
- Recall is measured only where zizmor has a related audit. GW009, GW012 and
  GW016 have no counterpart and were not measured here.
- GW001's recall beyond the real-world data rests on 20 hand-picked contexts;
  contexts not in that file were not tested.
