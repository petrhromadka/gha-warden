# Real-world scan

Date: 2026-11-05. gha-warden at commit `df57cc0` (branch `realworld`).

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

## Limitations

- 42 repositories, one snapshot of the default branch, chosen by hand among
  very popular projects. They are heavily maintained and not representative
  of the long tail of small repositories.
- Precision is estimated from small samples (at most 5 per rule, 53 for
  GW010). Recall (false negatives) was not measured.
- GW001 and GW008 produced no findings, so nothing can be said about their
  precision on real data.
- Findings are counted per occurrence, so large generated workflow files
  inflate GW003 and GW005.
- Triage is by one reviewer reading the YAML; exploitability was not tested
  and settings outside the repository files (fork approval, branch
  protection, default token permissions) are invisible to a static scan.
