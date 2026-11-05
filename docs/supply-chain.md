# Supply-chain security

gha-warden audits other people's workflows, so its own release pipeline is held to the
same standard.

## Releases

Pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml`:

1. The `build` job runs `uv build` on a clean runner with read-only permissions and
   uploads `dist/*` (sdist and wheel) as a workflow artifact.
2. The `attest-and-release` job downloads exactly those files, signs a SLSA build
   provenance attestation for them with `actions/attest-build-provenance` (Sigstore,
   keyless, authenticated by the workflow's OIDC token), and creates the GitHub Release
   with `gh release create`.

No long-lived secrets are used anywhere: publishing relies on the OIDC token and the
job-scoped `GITHUB_TOKEN` only. Top-level workflow permissions are `{}`; each job
declares only what it needs.

## Verifying a release

Download a file from the GitHub Release and verify it against this repository:

```sh
gh attestation verify gha_warden-X.Y.Z-py3-none-any.whl --repo petrhromadka/gha-warden
```

Success means the file's digest matches an attestation signed by a workflow run in
`petrhromadka/gha-warden`. Add `--signer-workflow petrhromadka/gha-warden/.github/workflows/release.yml`
to also require that the release workflow produced it.

## Scorecard and code scanning

- `.github/workflows/scorecard.yml` runs the [OpenSSF Scorecard](https://scorecard.dev)
  on every push to `main` and weekly, publishes the result, and uploads SARIF to code
  scanning.
- `.github/workflows/codeql.yml` runs CodeQL for Python and for GitHub Actions
  workflows on pushes, pull requests and weekly.

## Pinning policy

- Every `uses:` in `.github/workflows/` is pinned to a full 40-character commit SHA with
  the release tag in a trailing comment (`# v1.2.3`). Tags can be moved; SHAs cannot.
- `actions/checkout` always sets `persist-credentials: false`.
- Docker base images are pinned by digest next to a readable version tag.
- Dependabot updates actions, Docker images and Python dependencies through reviewed pull
  requests. gha-warden scans its own workflows in CI, so an unpinned action fails the
  build.
