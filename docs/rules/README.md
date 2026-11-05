# Rules

Each rule has its own page with an attack scenario, a vulnerable and a fixed
example, and how to suppress a finding.

| ID | Title | Severity |
|----|-------|----------|
| [GW001](GW001.md) | Script injection from untrusted context | critical |
| [GW002](GW002.md) | Pwn request (untrusted checkout in a privileged workflow) | critical |
| [GW003](GW003.md) | Action not pinned to a full commit SHA | high (medium for `actions/*` and `github/*`) |
| [GW004](GW004.md) | Excessive `GITHUB_TOKEN` permissions | medium |
| [GW005](GW005.md) | `actions/checkout` without `persist-credentials: false` | low |
| [GW006](GW006.md) | Reusable workflow called with `secrets: inherit` | medium |
| [GW007](GW007.md) | Self-hosted runner in a pull request workflow | high |
| [GW008](GW008.md) | `ACTIONS_ALLOW_UNSECURE_COMMANDS` enabled | high |
| [GW009](GW009.md) | Remote script piped to a shell | medium |
| [GW010](GW010.md) | Hardcoded credential in `env:` or `with:` | high |
| [GW015](GW015.md) | Entire `secrets` context exposed | high |
| [GW016](GW016.md) | Secret interpolated into `run:` script | low |

## Suppressing a finding

Add a YAML comment on the line the finding points at:

```yaml
        run: echo "${{ github.event.issue.title }}"  # gha-warden: ignore[GW001]
```

`# gha-warden: ignore` without a list suppresses every rule on that line. To
turn a rule off for a whole run, use `--ignore GW001` on the command line.

See also the [threat model](../threat-model.md).
