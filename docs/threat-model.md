# Threat model

gha-warden is a static analyzer. It reads workflow files (and composite
`action.yml` files you pass to it), parses the YAML, and reports patterns that
are known to lead to injection, privilege escalation or supply-chain
compromise. It makes no network calls and needs no tokens.

## What it covers

- Untrusted input reaching a shell or script through `${{ }}` expressions
  (GW001).
- Privileged triggers that run pull request code (GW002).
- Trust placed in third-party code that can change: unpinned actions, remote
  scripts, inherited secrets (GW003, GW006, GW009).
- Over-broad credentials in the workflow definition: `GITHUB_TOKEN`
  permissions, persisted checkout credentials, hardcoded secrets (GW004,
  GW005, GW010).
- Risky runner and runtime configuration: self-hosted runners on pull request
  triggers, the legacy unsafe commands switch (GW007, GW008).

## What it does not cover

- Runtime behavior. It does not run workflows, so it cannot tell whether a
  flagged value is actually attacker-controlled in practice, and it does not
  follow data flow across steps, files or called workflows.
- The contents of actions. A SHA-pinned action can still contain malicious or
  vulnerable code from the start. gha-warden checks how you reference an
  action, not what the action does.
- Repository and organization settings: default `GITHUB_TOKEN` permissions,
  branch protection, required approvals for outside contributors, allowed
  actions policies, runner groups, environment protection rules, and secret
  scopes.
- Secrets exposed outside workflow files, and credentials with unusual names
  (GW010 matches key names, not entropy).
- Dependencies that your own build scripts install.

## Assumptions

- The workflow file is the one that will run. Findings are about the file as
  written, on the branch you scan.
- Pull request authors, issue authors, commit metadata, branch names and
  anything derived from them are attacker-controlled. Maintainers with write
  access are trusted.
- GitHub-hosted runners are ephemeral and isolated. Self-hosted runners are
  not, unless you configure them to be.
- A clean report means none of the implemented rules matched. It does not mean
  the workflow is secure.

## Related reading

- [GitHub Docs: Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [GitHub Security Lab: Keeping your GitHub Actions and workflows secure Part 3: How to trust your building blocks](https://securitylab.github.com/resources/github-actions-building-blocks/)
- [GitHub Security Lab: Keeping your GitHub Actions and workflows secure Part 4: New vulnerability patterns and mitigation strategies](https://securitylab.github.com/resources/github-actions-new-patterns-and-mitigations/)
