# SAFER Maintenance Procedure

## Purpose

This document defines a repeatable maintenance procedure that prevents feature changes and security fixes from weakening existing authentication, authorization, or transaction integrity.

## Change Procedure

1. Receive a user-reported error, security alert, or dependency warning.
2. Determine the impact using the request ID, audit logs, and reproduction steps.
3. Add a regression test that reproduces the failure first.
4. Implement the smallest necessary code change or a new database migration.
5. Run type checking, linting, security checks, and the full test suite.
6. Update the OWASP control mapping and threat model when a security boundary changes.
7. Deploy only the verified source as a new version.
8. Check Worker errors and administrator security alerts after deployment.
9. If a problem occurs, roll back to the previous saved version and document the cause.

## Required Validation

```bash
npx tsc --noEmit
npm run lint
npm run security:check
npm test
```

When the web boundary changes, add a ZAP Baseline scan. Run Active Scan only against localhost.

## Database Changes

- Add each migration under a new sequence number.
- Do not modify or reuse SQL that has already been applied to production.
- Record authorization, balance, and transaction-state changes in the audit log.
- Do not hard-code production user or administrator IDs in migrations.
- Document backup availability, restore verification, and rollback steps before a destructive change.

## Dependency Maintenance

- Never deploy without a lockfile.
- High or Critical vulnerabilities block deployment by default.
- Dependabot pull requests must pass the full test suite before merging.
- Prefer an official compatible security release over an unreviewed forced major-version change.

## Incident Response

1. Restrict the affected feature or roll back to the previous safe version.
2. Rotate potentially exposed secrets and sessions.
3. Preserve audit logs and request IDs.
4. Analyze the root cause and impact.
5. Redeploy only after applying the fix and adding regression coverage.
6. Record preventive controls and residual risk in the report.
