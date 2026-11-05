# Real-world scan

Date: 2026-11-05. First scan with gha-warden v0.1.0; re-scans after the GW010 rework and the GW011-GW017 triage (see the sections below).

This page measures gha-warden against workflows of popular public
repositories. It reports aggregate numbers only. Repositories and files are
deliberately not named.

## Method

1. Repositories: 43 popular, recently active public repositories were picked
   by hand from `gh search repos --sort stars` results for JavaScript,
   TypeScript, Python, Go, Rust, Java, C++, C# and Shell, plus a few
   infrastructure and tooling projects. Awesome-lists and documentation-only
   repositories were skipped. 42 of the 43 have a `.github/workflows`
   directory.
2. Download: only `*.yml` / `*.yaml` files from `.github/workflows` were
   fetched through the GitHub contents API (default branch, one snapshot).
   Seven file downloads failed and were dropped. Nothing from the downloaded
   data was executed.
3. Scan: `python -m gha_warden --format json <data dir>` (the `gha-warden`
   console script was blocked by Windows application control on the test
   machine, so the module entry point was used; it is the same code).
4. Triage: findings were read in their source context. For each rule up to 5
   findings were drawn at random (fixed seed) and classified as true positive
   (TP: the pattern matches the rule's intent), false positive (FP: the rule
   misfired) or debatable (D). GW010 has only 53 findings, so all of them were
   classified.

## Results

- Repositories scanned: 42
- Workflow files scanned: 1068
- Findings: 3129 (1 critical, 654 high, 1750 medium, 724 low)
- Parse errors: 0. Crashes: 0. Nothing was written to stderr.
- Runtime: about 33 s wall clock for 1068 files, including `uv run` start-up.

| Rule | Findings | Files | Repos |
|------|---------:|------:|------:|
| GW001 | 0 | 0 | 0 |
| GW002 | 1 | 1 | 1 |
| GW003 | 1530 | 420 | 26 |
| GW004 | 364 | 147 | 16 |
| GW005 | 724 | 365 | 30 |
| GW006 | 427 | 121 | 8 |
| GW007 | 15 | 8 | 1 |
| GW008 | 0 | 0 | 0 |
| GW009 | 15 | 9 | 7 |
| GW010 | 53 | 37 | 8 |

## Triage precision

| Rule | Sample | TP | FP | D | Note |
|------|-------:|---:|---:|--:|------|
| GW001 | 0 | - | - | - | No findings. A text search for untrusted contexts outside `env:` and `if:` found none either, so this is consistent but recall was not tested. |
| GW002 | 1 | 0 | 0 | 1 | The pattern matches; whether pull request code can reach the triggering workflow was not verified. |
| GW003 | 5 | 4 | 0 | 1 | The debatable one is a same-repository composite action referenced by path with `@main`. |
| GW004 | 3 | 2 | 0 | 1 | The debatable one is a job that only calls a local reusable workflow. |
| GW005 | 5 | 5 | 0 | 0 | Matched by pattern only. Whether the job later needs the stored token (for example to push) was not checked. |
| GW006 | 2 | 2 | 0 | 0 | |
| GW007 | 5 | 5 | 0 | 0 | All from one repository. Actual exposure depends on the repository's fork-approval settings, which a static scan cannot see. |
| GW009 | 5 | 3 | 0 | 2 | Both debatable cases fetch a script from the project's own repository at a commit or version pinned by a variable. |
| GW010 | 53 (all) | 0 | 45 | 8 | See below. |

The GW004 and GW006 samples are smaller than 5 because the sampling helper
crashed on a non-ASCII character while printing the context (a bug in the
helper, not in gha-warden); there was no time budget left to redo them.

## False-positive classes

All in GW010, which in this scan produced no true positive.

1. Key name contains `token` or `secret`, value is not a credential (23
   findings, 43 % of GW010). Examples: a title string for a token-usage
   summary, a comma-separated list of secret names, a label naming where a
   token comes from, a boolean-like flag for a tokenizer download.
2. Multi-line `with:` input whose key contains `secret` and whose lines map an
   environment variable to a vault path (`NAME=vault-path:field`) (21
   findings). The value is a lookup reference, not a secret.
3. Input that holds the name of an environment variable, not its value (1
   finding), for example `server-password: CI_DEPLOY_PASSWORD` in a Maven
   setup step.

Debatable (8): throw-away passwords for a database or object-store service
container in the same job (7), and one value in a `projectToken` input whose
tool documents it as safe to publish.

Minimal anonymized reproductions are in the "GW010 reproductions" section
below.

Other classes seen but not counted as false positives: GW003 on same-repo
action references, GW004 on caller jobs of reusable workflows, GW009 on
scripts fetched from a pinned ref of the project itself. These are policy
questions the rule docs could address.

## GW010 reproductions

Each of these is reported by GW010 and should not be.

```yaml
# Class 1: name contains "token", value is plain text
on: push
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    env:
      TOKEN_USAGE_SUMMARY_TITLE: Token Usage
      SECRET_NAMES: "A_NAME,B_NAME"
      FETCH_TOKENIZERS: "1"
    steps:
      - run: echo hi
```

```yaml
# Class 2: input maps env names to vault paths
on: push
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: example/get-vault-secrets@v1
        with:
          repo_secrets: |
            MY_API_KEY=team-path:api_key
```

```yaml
# Class 3: input holds a variable name
on: push
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: example/setup-java@v1
        with:
          server-password: CI_DEPLOY_PASSWORD
```

## Re-scan after precision fixes

The same 1068 files were scanned again on 2026-11-05 after the GW010 rework
(credential word must end the key; env-var names, multi-line values, prose
and short non-password values are skipped) and with the new rules GW011-GW017.
Runtime about 33 s, 0 parse errors, 0 crashes.

| Rule | Before | After | Note |
|---|--:|--:|---|
| GW010 | 53 | 5 | Remaining 5 are the "debatable" class: throwaway CI database / object-store passwords and one token documented as public. All three false-positive classes above are gone. |
| GW002 | 1 | 4 | Rule extended to `issue_comment` triggers and `gh pr checkout` / `git fetch pull/...` in `run:`. |
| GW011 | - | 10 | New rule. Triaged below. |
| GW012 | - | 5 | New rule. Triaged below; 4 after the fix described there. |
| GW013 | - | 56 | New rule. Triaged below (10 of 56). |
| GW014 | - | 0 | No known-compromised action versions in use. |
| GW015 | - | 0 | |
| GW016 | - | 10 | New rule. Triaged below. |
| GW017 | - | 1 | New rule. Triaged below. |

Other rules are unchanged (GW003 1530, GW004 364, GW005 724, GW006 427,
GW007 15, GW009 15).

## Triage of GW011-GW017

The new rules were triaged on the same 1068 files by one reviewer, who read
the YAML around each finding and, where a finding depends on another
workflow, that workflow too. Up to 10 findings per rule were classified
(all of them when there were fewer; for GW013, 10 of 56 spread over
different repositories). TP means the pattern matches the rule's intent, not
that the workflow is exploitable; exploitability was not tested.

| Rule | Findings | Sample | TP | FP | D | Notable classes |
|------|---------:|-------:|---:|---:|--:|-----------------|
| GW011 | 10 | 10 | 6 | 0 | 4 | TP: dependency caches (`setup-python`, `setup-node`, `setup-go`, `actions/cache` of `node_modules`) restored in `workflow_run`, `issue_comment` or merged-PR `pull_request_target` workflows, some with cloud credentials in the same job. D: a cache of one data file (a usage log, never executed) in generated workflows; 4 findings in 2 files of one repository. |
| GW012 | 5 | 5 | 1 | 2 | 2 | See below. |
| GW013 | 56 | 10 | 10 | 0 | 0 | Mutable tags are what the rule is about. 21 of the 56 findings have no tag or `latest`. The rest are version tags of database and message-queue service containers, language toolchain images and first-party images. One finding carries an inline suppression for another tool; it is still a TP for this rule. Severity (medium) fits job containers better than throwaway service containers. |
| GW014 | 0 | - | - | - | - | No findings. |
| GW015 | 0 | - | - | - | - | No findings. |
| GW016 | 10 | 10 | 10 | 0 | 0 | Secret as a command-line argument (4: `cargo login`, `poetry publish -p`, `hf auth login --token`, a `--token` flag), `GH_TOKEN=${{ github.token }} cmd` (3), `echo "${{ secrets.X }}" \| docker login --password-stdin` (1), secret written into a dotenv file (1), a registry user name stored as a secret (1). Low severity fits: none of them is an injection, but the value ends up in the script text. |
| GW017 | 1 | 1 | 0 | 0 | 1 | `github.actor == 'dependabot[bot]'` OR-ed with a fork check in a `workflow_run` job. Spoofing the actor grants nothing that the fork branch of the condition does not already grant. The pattern matches the rule's intent, the practical risk is low. |

### GW012 detail

| # | Class | Verdict |
|---|-------|---------|
| 1 | Artifact content written to `$GITHUB_OUTPUT` without validation; the artifact is produced by a `pull_request` workflow that runs code from the pull request. | TP |
| 2 | Same write, but the producing workflow runs only on pushes to protected branches (found by reading the producer). | D |
| 3 | Same write, but the producer carries no pull request code and the job is guarded by a not-a-fork condition; values are a label name and a number. | D |
| 4 | Value reduced to digits with `grep -E '^[0-9]+$'`. | FP, fixed |
| 5 | The file written to `$GITHUB_OUTPUT` is produced in the job itself, not by the download. | FP, not fixed |

False positives and fixes:

- Digits-only `grep` (fixed): the rule skipped writes reduced with `tr -cd
  0-9` or `| tonumber` but not a `grep` that keeps only lines made of digits.
  `_SANITIZED` in `rules/poisoning.py` now also accepts `grep` with an
  anchored `^[0-9]+$` pattern (but not an inverted `-v` one, and not an
  unanchored pattern). Test cases `GW012-grep-digits-only-line` (negative) and
  `GW012-grep-not-digits-only` (positive) were added to
  `tests/test_rules_poisoning.py`.
- File not from the download (not fixed): the check for "file content written
  to an output" looks only at the line with the write and does not know which
  files came from the download. It cannot tell `cat data.json` of a file made
  by the job from a file in the artifact directory, and telling them apart
  needs data flow across steps (for example `FILE=dir/x.json; jq . "$FILE"`
  must stay a finding). A guess that drops lines with literal paths outside
  the download directory would lose recall, so it was left for later.

```yaml
# GW012 digits-only grep (fixed): was reported, now silent
on: workflow_run
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
      - run: echo "NUMBER=$(grep -E '^[0-9]+$' pr_number.txt || true)" >> "$GITHUB_OUTPUT"
```

```yaml
# GW012 file not from the download (not fixed): still reported
on: workflow_run
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: gh run download "$RUN_ID" --name request --dir request
      - run: ./build.sh --out data.json
      - run: |
          { printf 'data='; cat data.json; } >> "$GITHUB_OUTPUT"
```

### Counts after the fix

Scanning the 1068 files again after the GW012 fix: 3165 findings in total
(3166 before). GW012 went from 5 to 4; no other rule changed.

### GW012 data flow (2026-11-05)

GW012 now follows the download destination through each script (see
[GW012](rules/GW012.md#which-files-count-as-downloaded)): only reads inside
the download directory count, path variables and `env:` entries are
resolved, and `while read` loops, the rest of a `gh run download` step,
`actions/github-script` and running checked-out files after a download to
the workspace root are new. The same 1068 files were scanned with
`--format json` before and after the change.

Before the change the scan had 3 GW012 findings, not 4: the class 2 finding
above is no longer reported because of the cross-workflow `workflow_run`
analysis (its upstream workflow was scanned and cannot be started by
untrusted input). With that filter turned off, the class 2 finding appears
both before and after this change. Total findings: 3164 before and after; no
other rule changed.

| # | Before | After | Class | Verdict |
|---|:--:|:--:|-------|---------|
| 1 | yes | yes | Artifact content written to `$GITHUB_OUTPUT` with `jq -r`; the artifact is made by a `pull_request` workflow that runs pull request code (class 1 above). | TP |
| 2 | yes | yes | Artifact downloaded to the workspace root, `jq` writes every key to `$GITHUB_OUTPUT`; the producer runs no pull request code and the job requires a non-fork run (class 3 above). | D |
| 3 | yes | no | The file written to `$GITHUB_OUTPUT` is produced by the job, outside the `--dir` of the download (class 5 above, the known false positive). The artifact values themselves are read into variables and checked with anchored regular expressions before use. | FP, fixed |
| 4 | no | yes | Artifact downloaded to the workspace root right after `actions/checkout`, then a checked-out script is run with `node ./scripts/...`. A pull request can change the producing workflow and put a file with that path into the artifact; whether the download overwrites the checked-out file was not tested. | TP |

After the change GW012 has 3 findings: 2 TP, 1 D, 0 FP. Recall was not
measured beyond the new test cases; content passed through a shell variable
(`PR=$(cat out/pr)`) is still not followed, see
[the rule's limits](rules/GW012.md#limits).

Not measured: recall of GW011-GW017, and the GW013 findings beyond the 10
sampled. GW014 and GW015 had no findings, so nothing can be said about their
precision on real data.

## Limitations

- 42 repositories, one snapshot of the default branch, chosen by hand among
  very popular projects. They are heavily maintained and not representative
  of the long tail of small repositories.
- Precision is estimated from small samples (at most 5 per rule for GW001-GW009,
  53 for GW010, at most 10 for GW011-GW017). Recall (false negatives) was not measured.
- GW001 and GW008 produced no findings, so nothing can be said about their
  precision on real data.
- Findings are counted per occurrence, so large generated workflow files
  inflate GW003 and GW005.
- Triage is by one reviewer reading the YAML; exploitability was not tested
  and settings outside the repository files (fork approval, branch
  protection, default token permissions) are invisible to a static scan.
