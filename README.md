# SAFER — Secure Second-hand Marketplace

SAFER is a security-focused second-hand marketplace developed for a Secure Software Engineering course.
It provides account registration, product management, chat, reporting, hash ID-based transfers, product payment flows, and administrative operations.

> This repository does not contain passwords, wallet seeds, sessions, API tokens, real environment variables, or production data.

## Key Features

- Authentication with Sites/ChatGPT federated identity and WebAuthn Passkeys
- PBKDF2-SHA-256 password hashing and server-side sessions
- Product registration, search, detail views, and seller management
- JPEG, PNG, and WebP magic-byte validation with a 5 MB upload limit
- Global and one-to-one chat
- User and product reporting with automatic action after repeated reports
- `wlt_` hash ID wallets derived from 256-bit seeds
- Atomic, idempotent transfers with self-transfer and duplicate-payment prevention
- Product purchase request, approval, and payment state transitions
- Ethereum wallet signature linking and a fixed-price escrow example
- Administrator-only dashboard and security audit logs
- CSP nonces, browser security event reporting, and safe error responses
- A separately managed in-product privacy policy linked from the site footer

## Technology Stack

- Frontend: React 19, Next.js 16, Vinext, Vite
- Runtime: Cloudflare Workers
- Database: Cloudflare D1 / Drizzle ORM
- Object storage: Cloudflare R2
- Authentication: Sites/ChatGPT identity, WebAuthn Passkey
- Web3: Solidity, Foundry, OpenZeppelin, viem
- Security testing: Node test runner, ESLint, npm audit, CodeQL, OWASP ZAP

## Requirements

- Node.js 22.13 or later
- npm
- Docker: required only for ZAP scans
- Foundry: required only for smart contract tests
- A Cloudflare Workers-compatible environment with D1 and R2 support

## Local Development

```bash
git clone https://github.com/gogooma125732/secure_coding.git
cd secure_coding
npm ci
npm run setup:local
npm run dev
```

`setup:local` generates separate 256-bit random values in `.dev.vars`, which the Cloudflare Worker reads locally, and restricts the file permissions to the owner. It does not overwrite an existing file. Check the development server output for the local URL.

After changing `.dev.vars`, stop the development server completely and restart it. Never place real secrets in `.env.example` or commit them to Git.

## Environment Variables

| Variable | Required | Purpose |
|---|---:|---|
| `ADMIN_BOOTSTRAP_TOKEN` | Initial setup | One-time random value of at least 32 characters for the first administrator |
| `BOT_PROTECTION_MODE` | Yes | `adaptive` is recommended |
| `BOT_PROTECTION_SECRET` | Yes | HMAC secret for the automation-defense challenge |
| `PLATFORM_IDENTITY_SECRET` | Yes | HMAC secret for platform identity pseudonymization |
| `PASSKEY_RP_ID` | When using Passkeys | Deployment hostname without a port or scheme |
| `PASSKEY_ORIGIN` | When using Passkeys | Exact origin including HTTPS |
| `WEB3_CHAIN_ID` | When using Web3 | `11155111` Sepolia is recommended |
| `WEB3_RPC_URL` | When using Web3 | HTTPS Ethereum RPC URL |
| `WEB3_RPC_HOST_ALLOWLIST` | When using Web3 | List of approved RPC hosts |
| `WEB3_ESCROW_ADDRESS` | When using settlement | Deployed escrow address |
| `WEB3_PAYMENT_TOKEN_ADDRESS` | When using settlement | Payment token address |
| `WEB3_CONFIRMATIONS` | When using Web3 | Required confirmation count |

Generate each secret as an independent, high-entropy random value and manage it only in the hosting environment's secret store.

## Data Bindings and Migrations

The public source does not require or commit `.openai/hosting.json`. The default logical binding names are:

- D1: `DB`
- R2: `UPLOADS`
- Migrations: `drizzle/*.sql`
- Schema: `db/schema.ts`

The binding names can be overridden with the `SAFER_D1_BINDING` and `SAFER_R2_BINDING` environment variables.

Follow this sequence when changing the schema:

```bash
npm run db:generate
npm test
```

Review generated SQL before deployment. Never modify a migration that has already been applied to production.

## Initial Administrator Setup

Administrator accounts are not hard-coded in source code or migrations.

1. Set a one-time `ADMIN_BOOTSTRAP_TOKEN` of at least 32 characters as a runtime secret.
2. Create the first regular account.
3. Send the target username to same-origin `/api/admin/bootstrap` and submit the one-time token in the `x-admin-bootstrap-token` header.
4. Immediately remove or rotate `ADMIN_BOOTSTRAP_TOKEN` after success.
5. Confirm the `admin.bootstrapped` audit event.

Bootstrap requests are rejected once an administrator already exists.

## Quality and Security Checks

```bash
npx tsc --noEmit
npm run lint
npm run security:check
npm test
```

`security:check` verifies that the lockfile uses the HTTPS registry and SHA-512 integrity values, and fails when a High or Critical vulnerability is found in production dependencies.

### OWASP ZAP

```bash
npm run dev
npm run security:zap:baseline
ZAP_ALLOW_ACTIVE_SCAN=local-only npm run security:zap:active
```

The Active Scan script is restricted to localhost. Do not run active attack scans against production or shared environments.

### CodeQL and Dependabot

- `.github/workflows/security.yml`: build, test, dependency audit, and CodeQL analysis
- `.github/dependabot.yml`: weekly npm and GitHub Actions updates

When CodeQL raises an alert, document the fix or false-positive justification before merging.

## Security Design Documents

- [OWASP API Security Top 10:2023 and OWASP Top 10:2025 control mapping](docs/security/owasp-coverage.md)
- [Authentication architecture](docs/security/authentication-architecture.md)
- [Smart contract threat model](docs/security/smart-contract-threat-model.md)
- [Maintenance procedure](docs/maintenance.md)
- [Vulnerability reporting policy](SECURITY.md)
- [Published SAFER privacy policy](https://safer-secure-market-2026.hippipo779.chatgpt.site/privacy)
- [Korean Personal Information Protection Act](https://www.law.go.kr/법령/개인정보보호법)
- [Personal Information Protection Commission privacy-policy guidelines (April 2025)](https://www.pipc.go.kr/np/cop/bbs/selectBoardArticle.do?bbsId=BS217&mCode=D010030000&nttId=11134)

## Privacy Policy Management

The user-facing privacy policy is managed as a separate page inside the deployed service at [`/privacy`](https://safer-secure-market-2026.hippipo779.chatgpt.site/privacy) and is linked directly from the global footer. The route entry is defined in `app/privacy/page.tsx`, while the rendered policy and navigation are maintained with the application UI in `app/marketplace-client.tsx`.

The deployed page is the canonical notice presented to users; this README only describes how it is governed. Any change to collected data, authentication, sessions, Passkeys, uploads, chat, reports, transactions, wallets, security logs, retention, third-party processing, or on-chain disclosure must update the privacy policy in the same change set. The updated page must be reviewed against the Personal Information Protection Act and the Personal Information Protection Commission guidelines, regression-tested, and deployed as a new site version.

## Core Security Principles

- Never trust client input or authorization decisions; validate them again on the server.
- Use prepared statements and bound parameters for every SQL query.
- Keep login IDs, public aliases, per-transaction aliases, and wallet IDs in separate identity domains.
- Do not store wallet seeds or Passkey private keys on the server.
- Protect transfers and product payments with database constraints, state transitions, and idempotency.
- Return only a request ID for API failures; never expose internal stacks or SQL messages.
- Fail closed when required secrets are missing or external verification fails.

## Known Limitations

- Because no external CAPTCHA is used, advanced automation with human assistance cannot be blocked completely.
- Authenticated ZAP scans for each user role require separate test accounts and ZAP contexts.
- An independent smart contract audit is required before deployment to Ethereum mainnet.
- Private deployment based on platform identity depends on the hosting provider's authentication boundary.

## Public Repository Precautions

Never commit the following:

- `.env`, `.env.local`, `.dev.vars`
- Passwords, wallet seeds, private keys, session cookies, or CSRF cookies
- Sites, GitHub, or API tokens, including SIWC bypass tokens
- Production database dumps, real user email addresses, or logs
- ZAP authentication contexts or test-account passwords

If you discover a security issue, do not post exploit steps or secrets in a public Issue. Use the private reporting process in [SECURITY.md](SECURITY.md).

## License and Intended Use

This is an educational project. A separate security and legal review is required before using it as a production service that handles real assets or before deploying it to Ethereum mainnet.
