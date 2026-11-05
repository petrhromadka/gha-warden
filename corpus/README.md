# gha-warden regression corpus

Minimal, re-written GitHub Actions workflows that reproduce vulnerability patterns documented in
public advisories, post-mortems and research write-ups. Each `.yml` file starts with a header
comment giving the case name, date, source URL(s) and a one-line description of the pattern.

The files are paraphrased reproductions, not copies of third-party workflows. They contain no real
secrets, tokens or live payload URLs (placeholder hosts use the reserved `.invalid` TLD).

`manifest.json` maps each file to the rule IDs (GW001-GW010, see `SPEC.md`) that the scanner is
expected to report on it, with the source URL and a short summary. `expected_rules` is the complete
set of rules the spec says should fire on the file, including side findings such as GW003 for tag-pinned
`actions/*` steps and GW005 for `actions/checkout` without `persist-credentials: false`.

Conventions:

- A top-level `permissions:` block is present unless the cited source says the token had the
  org/repo default write scopes (Infinispan, Discord.js, Nx); those files omit it and expect GW004.
  Where a block was added only by the reproduction, the header comment says so.
- Incidental steps that are not part of the documented pattern were left out so that
  `expected_rules` stays small.

## Cases

| File | Date | Source | Expected rules |
|------|------|--------|----------------|
| [`infinispan-pr-title-injection.yml`](infinispan-pr-title-injection.yml) | 2024-08-14 | [source](https://securitylab.github.com/advisories/GHSL-2024-048_infinispan/) | GW001, GW004 |
| [`winglang-head-ref-injection.yml`](winglang-head-ref-injection.yml) | 2023-06-16 | [source](https://securitylab.github.com/advisories/GHSL-2023-110_Wing_Language/) | GW001 |
| [`discordjs-pr-title-validation.yml`](discordjs-pr-title-validation.yml) | 2024-07-17 | [source](https://securitylab.github.com/advisories/GHSL-2024-145_Discord_js/) | GW001, GW004 |
| [`harvester-heredoc-title-injection.yml`](harvester-heredoc-title-injection.yml) | 2025-10-16 | [source](https://securitylab.github.com/advisories/GHSL-2025-090_harvester_harvester/) | GW001 |
| [`ultralytics-format-workflow.yml`](ultralytics-format-workflow.yml) | 2024-12-06 | [source](https://www.blog.yossarian.net/2024/12/06/zizmor-ultralytics-injection) | GW003 |
| [`ultralytics-head-ref-injection.yml`](ultralytics-head-ref-injection.yml) | 2024-08-14 | [source](https://github.com/ultralytics/actions/security/advisories/GHSA-7x29-qqmq-v6qc) | GW001 |
| [`nx-s1ngularity-pr-title.yml`](nx-s1ngularity-pr-title.yml) | 2025-08-27 | [source](https://github.com/advisories/GHSA-cxm3-wv7p-598c) | GW001, GW004 |
| [`pwn-request-checkout-head.yml`](pwn-request-checkout-head.yml) | 2021-08-03 | [source](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/) | GW002, GW003, GW005 |
| [`pytorch-self-hosted-runner-pr.yml`](pytorch-self-hosted-runner-pr.yml) | 2024-01-11 | [source](https://johnstawinski.com/2024/01/11/playing-with-fire-how-we-executed-a-critical-supply-chain-attack-on-pytorch/) | GW007, GW009 |
| [`tj-actions-mutable-tag.yml`](tj-actions-mutable-tag.yml) | 2025-03-15 | [source](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3) | GW003 |
| [`artipacked-upload-checkout-dir.yml`](artipacked-upload-checkout-dir.yml) | 2024-08-13 | [source](https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/) | GW003, GW005 |
| [`set-env-unsecure-commands.yml`](set-env-unsecure-commands.yml) | 2020-10-01 | [source](https://github.com/actions/toolkit/security/advisories/GHSA-mfwh-5m23-j46w) | GW008 |
| [`codecov-bash-uploader.yml`](codecov-bash-uploader.yml) | 2021-04-15 | [source](https://about.codecov.io/security-update/) | GW009 |

## Not covered

GW006 (`secrets: inherit`) and GW010 (hardcoded credential literal) have no case here: no public
incident or advisory documenting those exact patterns was verified while building the corpus.
Add them with their own sources rather than invented examples.
