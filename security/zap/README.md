# OWASP ZAP regression scans

The baseline scan spiders the target and runs passive checks. The active scan
also sends attack payloads and is deliberately restricted to localhost targets.
Never point the active mode at a production or shared deployment.

Start the local application, then run:

```sh
npm run security:zap:baseline
ZAP_ALLOW_ACTIVE_SCAN=local-only npm run security:zap:active
```

Reports are written to `outputs/zap/`. `ZAP_TARGET_URL` may select localhost,
`127.0.0.1`, or `host.docker.internal`; only baseline mode permits an HTTPS
`*.chatgpt.site` target. `ZAP_IMAGE` may pin an organization-approved image
digest in CI.

The unauthenticated scan covers public routes and browser headers. A separate
test-only account/context is still required for authenticated BOLA, CSRF,
product, chat, wallet, and administrator workflows.
