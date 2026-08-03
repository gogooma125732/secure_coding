# SAFER Maintenance Procedure

## Purpose

This document defines a repeatable maintenance procedure that prevents feature changes and security fixes from weakening existing authentication, authorization, or transaction integrity.

## Change Procedure

1. Receive a user-reported error, security alert, or dependency warning.
2. Determine the impact using the request ID, audit logs, and reproduction steps.
3. Add a regression test that reproduces the failure first.
4. Implement the smallest necessary code change or a new database migration.
5. Run type checking, linting, security checks, and the full test suite.
6. Update the OWASP control mapping, threat model, and published privacy policy when a security or personal-data boundary changes.
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

## Privacy Policy Maintenance

- Manage the user-facing policy as the separate `/privacy` page in the application and keep a direct link in the global footer.
- Treat the deployed page as the canonical user notice; do not maintain an independent full copy in README files.
- Review the policy whenever data fields, purposes, identifiers, retention, access logs, authentication, Passkeys, uploads, chat, reports, transactions, wallets, external processors, or on-chain disclosures change.
- Update the policy in the same pull request as the processing change and verify that `/privacy` renders in the production build.
- After deployment, verify both the footer link and the live policy page, and record the effective date when the substance of the notice changes.
- Use the [Korean Personal Information Protection Act](https://www.law.go.kr/법령/개인정보보호법) and the [Personal Information Protection Commission privacy-policy guidelines (April 2025)](https://www.pipc.go.kr/np/cop/bbs/selectBoardArticle.do?bbsId=BS217&mCode=D010030000&nttId=11134) as the primary drafting references. A legal review is still required before commercial operation.

## Incident Response

1. Restrict the affected feature or roll back to the previous safe version.
2. Rotate potentially exposed secrets and sessions.
3. Preserve audit logs and request IDs.
4. Analyze the root cause and impact.
5. Redeploy only after applying the fix and adding regression coverage.
6. Record preventive controls and residual risk in the report.
