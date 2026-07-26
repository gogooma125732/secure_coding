# Security Policy

## Supported Version

Security fixes target the latest version of the default branch.

## Reporting a Vulnerability

Do not post detailed exploit steps, real account information, tokens, or personal data in a public Issue.

1. Use **Security → Advisories → Report a vulnerability** in the GitHub repository.
2. Provide the affected feature, reproduction conditions, expected impact, and the minimum evidence needed to verify the issue.
3. Use test accounts and de-identified examples instead of real user data.
4. Do not share details with third parties until the fix and disclosure schedule have been agreed upon.

After receiving a report, we will confirm reproducibility and severity as quickly as possible, then coordinate disclosure after the fix, regression testing, and deployment are complete.

## Scope

The following areas receive priority:

- Authentication, session, or Passkey bypass
- Administrator or object-ownership bypass
- Duplicate transfer or product-payment processing
- Exposure of wallet seeds, private keys, or tokens
- SQL, command, or XSS injection
- Image upload validation bypass
- SSRF or Ethereum RPC allowlist bypass
- Sensitive information recorded in audit logs

Do not perform automated high-volume requests, denial-of-service testing, production data modification, or real-asset transfers without prior authorization.
