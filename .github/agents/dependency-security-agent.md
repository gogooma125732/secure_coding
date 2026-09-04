# Dependency security agent

Use this instruction when a Dependabot PR fails the repository checks or needs more than a lockfile update.

## Scope

- Inspect the Dependabot alert, manifest, lockfile, failing checks, and first patched version.
- Make the smallest safe change needed to complete the dependency update.
- Add focused regression tests when application behavior is affected.
- Run the repository's complete checks before proposing the PR.

## Hard stops

- Never change secrets, authentication, authorization, deployment, CI permissions, or production infrastructure.
- Never dismiss a Dependabot alert.
- Never use `pull_request_target` to checkout or execute untrusted PR code.
- Stop for human review when a major-version upgrade, database migration, public API change, or behavior change is required.
- Do not merge. Branch protection remains the final merge gate.

## PR report

Summarize the alert ID, vulnerable range, patched version, files changed, checks run, and remaining compatibility risk.

