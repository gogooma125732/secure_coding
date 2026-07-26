# SAFER OWASP Security Control Mapping

Last reviewed: 2026-07-26

This document maps the OWASP API Security Top 10:2023 and OWASP Top 10:2025 to SAFER's implemented controls. Mapping the Top 10 does not guarantee an absence of vulnerabilities. Penetration testing, dependency review, and log monitoring must continue before and after deployment.

## OWASP API Security Top 10:2023

| Item | Implemented Control | Verification Point |
|---|---|---|
| API1:2023 Broken Object Level Authorization | Product updates include `seller_id`, transaction reads and changes include `buyer_id` or `seller_id`, and transfer reads include a participant ID in the SQL condition. Existing objects that the caller is not authorized to access also return 404. | Ownership clauses in API routes and BOLA regression tests |
| API2:2023 Broken Authentication | The server verifies the Sites/ChatGPT federated identity from trusted headers, pseudonymizes it with HMAC, and allows only one account per identity. WebAuthn Passkeys validate the RP ID, origin, one-time challenge, user verification, and signature counter. Legacy passwords use PBKDF2-SHA-256 and login lockout. Server sessions store hashed tokens and enforce an eight-hour absolute timeout, a 30-minute idle timeout, revocation of existing sessions at new login, and deletion of expired cookies. | `requirePlatformIdentity`, `lib/passkeys.ts`, `createSession`, `requireSession`, and authentication tests |
| API3:2023 Broken Object Property Level Authorization | Every JSON command declares an allowlist of fields and rejects unknown properties with `UNKNOWN_FIELD`. Login IDs are returned only to their owner and administrators. Products and chat use random public aliases, product transactions use per-transaction aliases, and product payment history does not return the counterparty's wallet address. | `readJson(..., allowedFields)` and identifier-minimization DTO tests |
| API4:2023 Unrestricted Resource Consumption | Atomic rate limits cover all APIs, authentication, messages, reports, products, and transfers. The service limits JSON to 32 KB, images to 5 MB, result-row counts, search length, and external response size and duration. Probabilistic cleanup with a two-day retention period prevents `rate_limits` from growing indefinitely through IP rotation. | `rate_limits`, `retry-after`, retention, and size-limit tests |
| API5:2023 Broken Function Level Authorization | Administrative functions require a valid session followed by `requireAdmin`. User-status, product, report, and message administration APIs are not exposed to regular users. | Administrator API authorization tests |
| API6:2023 Unrestricted Access to Sensitive Business Flows | Reporting, registration identity checks, wallet creation, purchase requests, transfers, and payments each have dedicated limits. Transfers and product payments use deduplication keys, database constraints, and conditional state transitions. | D1 triggers and idempotency tests |
| API7:2023 Server Side Request Forgery | Registration does not call external URLs such as an email-delivery endpoint. Users cannot specify a server-side request URL, and Ethereum RPC requests must pass both HTTPS enforcement and the production host allowlist. | Absence of external URL input and RPC allowlist tests |
| API8:2023 Security Misconfiguration | HSTS, per-request nonce CSP, frame blocking, MIME-sniffing prevention, Permissions Policy, and Cross-Origin Resource Policy are applied globally, while server-identification headers are removed. Production `connect-src` permits same-origin only, development WebSockets are allowed only on HTTP localhost, and API responses use `no-store`. | Worker header tests |
| API9:2023 Improper Inventory Management | A single `/api` router explicitly lists supported paths and HTTP methods. Every other path returns the same 404 response, and API responses include `X-API-Version: 1`. | Route inventory and Worker headers |
| API10:2023 Unsafe Consumption of APIs | External API responses are not trusted until their status, size, and structure are validated. Secret keys are read only from runtime secrets, and response bodies or credentials are never written to error logs. | Sites identity-header and Ethereum RPC adapter tests |

## OWASP Top 10:2025

| Item | Implemented Control | Verification Point |
|---|---|---|
| A01:2025 Broken Access Control | Default-deny session, CSRF, role, and object-ownership checks run on the server, and cross-origin state-changing requests are blocked. State changes cross-check the exact `Origin`, a same-origin `Referer`, and Fetch Metadata. Browser requests without origin evidence are rejected. | `requireSession`, `requireAdmin`, `validateSameOrigin`, and ownership SQL |
| A02:2025 Security Misconfiguration | Security headers, private deployment, disabled API caching, trusted-host metadata URLs, safe error responses, rejection of production test keys, and fail-closed behavior for missing secrets are enforced. | Worker, metadata-host, and environment-configuration tests |
| A03:2025 Software Supply Chain Failures | The dependency surface is minimized, and automated checks verify lockfile v3, the HTTPS npm registry, and SHA-512 integrity values. High or Critical findings from `npm audit` block deployment. | `npm run security:check` |
| A04:2025 Cryptographic Failures | The service uses Web Crypto CSPRNG, versioned PBKDF2 work factors, SHA-256 token hashes, HMAC-SHA-256 platform-identity pseudonymization, WebAuthn asymmetric signatures, HTTPS/HSTS, and HttpOnly and Secure cookies. It does not store plaintext passwords, sessions, Sites email addresses, or Passkey private keys. | Cryptography, cookie, Passkey, and database-schema tests |
| A05:2025 Injection | Every SQL query uses prepared statements and bound parameters. Inputs are checked for length, format, and integer range. React's default output encoding remains enabled, and uploads are validated by magic bytes. | API and upload tests |
| A06:2025 Insecure Design | Balances, transactions, and automatic report actions are designed around database constraints and state transitions. New accounts start at zero, and linking both an internal transaction wallet and a verified Ethereum wallet never grants an arbitrary balance. Self-transfer, self-dealing, duplicate payment, and identifier-correlation risks are constrained in both the application and database. | D1 CHECK, UNIQUE, triggers, and wallet-activation tests |
| A07:2025 Authentication Failures | A new account can be created only after the Sites-injected ChatGPT federated identity is verified, and the linked identity is exchanged for a server session. Passkey login uses discoverable credentials, required user verification, a five-minute challenge, replay prevention, and fixed RP ID and origin values. The legacy registration and password paths retain signed risk-based bot protection. | Federated identity, Passkey, and automation-defense regression tests |
| A08:2025 Software or Data Integrity Failures | Mass assignment is rejected, while the lockfile, upload contents, transaction state, and idempotency are verified. Sensitive keys in audit-log metadata are automatically redacted. | Integrity and audit-log tests |
| A09:2025 Security Logging and Alerting Failures | Login failures, rate limits, registration-identity conflicts, honeypot triggers, tampering, and high-risk automation requests are written to the audit log. The administrator view summarizes security events from the previous 24 hours, and every server error receives a request-tracking ID. | Administrator summary and error tests |
| A10:2025 Mishandling of Exceptional Conditions | A central error handler hides internal exceptions, stack traces, and SQL messages, recording only an error category and request ID. Malformed percent-encoded cookies and image paths are ignored or return 404 instead of 500. External services use timeouts, size limits, and fail-closed behavior; compensating cleanup handles file or database failures. Ethereum provider errors disclose only user-recoverable causes such as approval rejection, duplicate requests, or network loss. | `handleError`, `parseCookies`, `getImage`, wallet error mapping, and upload-cleanup tests |

## Required Production Configuration

- `BOT_PROTECTION_MODE=adaptive`: enables server-signed risk-based automation defenses.
- `BOT_PROTECTION_SECRET`: an independent random secret of at least 32 characters, used only to sign challenge values. Rotating it invalidates previously issued challenges.
- `PLATFORM_IDENTITY_SECRET`: an independent random secret of at least 32 characters, used only to pseudonymize Sites/ChatGPT identities with HMAC. Rotating it breaks matching between existing identities and new registration attempts, so do not rotate it without a planned account-relinking procedure.
- `PASSKEY_RP_ID`: the production hostname to which Passkeys are bound. Do not include a port, scheme, or path.
- `PASSKEY_ORIGIN`: the exact SAFER origin including `https://`. Passkey processing fails closed when the request origin differs.
- Keep the site access policy private. Before changing to public access, introduce a Passkey or separate OIDC provider because trusted platform identity headers are not guaranteed for anonymous visitors.
- Operators must review administrator security alerts and Worker logs regularly and connect repeated alerts to an external notification channel.

## Residual Risk and Validation Scope

- Without an external CAPTCHA, advanced automation with human assistance cannot be blocked completely. Maintain account-, platform-identity-, and IP-level limits, one-time challenges, login lockout, new-account restrictions, and operational alerts together.
- Passkey recovery strength depends partly on the recovery policy of the ChatGPT federated-identity account. Register two Passkeys on different devices and re-verify the linked ChatGPT identity before Passkey registration or deletion.
- CSP uses a per-request 128-bit nonce for scripts and `<style>` blocks and applies `strict-dynamic` to scripts. Only the limited `style` attributes created by React streaming transport nodes are allowed through `style-src-attr 'unsafe-inline'`; application code does not create inline styles. The Report-Only policy also collects Trusted Types violations.
- Production CSP restricts `connect-src` to `'self'`. The `ws:` and `wss:` values needed for HMR are added only in an HTTP localhost development environment, reducing the ability of malicious scripts to exfiltrate data through arbitrary WebSockets.
- API `OPTIONS` responses expose only the methods allowed for the actual route, rather than a global method list. Unknown routes return 404.
- React render errors, global script errors, unhandled Promises, and CSP violations are recorded in the audit log after size, frequency, and sensitive-data filtering. Raw CSP reports and nonce values are not stored.
- Login IDs, marketplace public aliases, per-product-transaction aliases, internal hash wallets, and Ethereum addresses use separate identifier domains. Direct transfers display only the hash wallet explicitly entered by the user, while product payments return only per-transaction aliases. Administrator access to real mappings is audited.
- The repository provides an OWASP ZAP Baseline configuration and an Active Scan restricted to localhost. Authenticated scans for each role require dedicated test accounts and an automated authentication context.
- Before the final release, dependency findings for Next.js, PostCSS, sharp, and ws were resolved with reviewed patched versions. On 2026-07-26, lockfile integrity, TypeScript, ESLint, the build, regression tests, and the production dependency audit passed locally and through the security workflow.
- The OWASP ZAP configuration and blocking rules are included in the repository. Because Docker is not available in every local environment, run the safe Baseline Scan against the deployment URL and restrict Active Scan to an explicitly approved localhost target.
- This Top 10 mapping is a risk-prioritized control matrix. It does not replace SAST/DAST, role-based API penetration testing, supply-chain signature verification, secret rotation, or recovery exercises.

## Official References

- https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- https://owasp.org/Top10/
