# SAFER Federated Identity and Passkey Authentication Boundary

Last reviewed: 2026-07-26

## Provider and Contract Scope

SAFER uses **Sign in with ChatGPT (SIWC)** supplied by the Sites dispatcher as its identity provider. Without a separate Auth0, Clerk, or Firebase contract or outsourced user database, the server uses only the ChatGPT identity headers verified by the dispatcher. This boundary does not trust arbitrary email headers. It relies on the deployment platform boundary that Sites authenticates and forwards.

Passkeys do not require a separate authentication-service contract. The user's operating system, browser, or security key acts as the WebAuthn authenticator, and SAFER acts as the Relying Party (RP). When a synchronized Passkey is selected, a credential manager such as Apple or Google may provide cross-device synchronization, but SAFER neither contracts with that service nor sends it the private key.

## Registration and Login

1. In the current owner-only private deployment, the Sites access policy authenticates the visitor first, and SAFER verifies the authenticated-user headers forwarded by the dispatcher. The application does not redirect the visitor to `/signin-with-chatgpt` again.
2. SAFER applies HMAC with an independent secret to the forwarded identity and stores only `platform_identity_hash`.
3. Only one new account may be created for each platform identity.
4. A linked user may obtain a SAFER server session through the ChatGPT federated identity.
5. An authenticated user may register up to five Passkeys after re-verifying the ChatGPT identity.
6. After a successful Passkey login, the server verifies the WebAuthn response and exchanges it for the standard HttpOnly and Secure SAFER session.

Username-and-password login remains available for migration compatibility. A new public deployment should prioritize federated identity and Passkeys while presenting password login only as a legacy path.

## Privacy Policy Linkage

The deployed service maintains a separate [privacy policy page](https://safer-secure-market-2026.hippipo779.chatgpt.site/privacy), linked from the global footer. It explains the pseudonymized platform identity, session metadata, Passkey public credential material, and authentication security events processed by this boundary, as well as the information SAFER deliberately does not collect.

Any authentication change that adds an identifier, authenticator attribute, recovery mechanism, processor, or retention period must update the policy in the same pull request. The application policy is the canonical user notice; this architecture document provides the technical rationale.

## Server-side Passkey Verification

- Pin the RP ID and HTTPS origin in runtime configuration and reject requests whose origin does not match.
- Generate registration and login challenges with a CSPRNG and store only their SHA-256 hashes in D1.
- Expire each challenge after five minutes and consume it exactly once with `DELETE ... RETURNING` before verification.
- Use discoverable credentials and `userVerification: required`.
- Request `none` attestation to minimize personal data collection.
- Allow only ES256 and RS256.
- Store only the credential ID, COSE public key, signature counter, transports, backup state, and device type in D1.
- Never store private keys, biometric data, ChatGPT tokens, or plaintext email addresses in SAFER.
- Require a SAFER session, CSRF validation, same-origin validation, and the linked ChatGPT identity for registration and deletion.

## Conditions for Public Access

Confirm the following before changing the Sites access policy to public:

- Anonymous users must receive read-only access, and the registration and login entry points must be moved to a Sites-supported SIWC boundary. Do not expose the private-deployment UI unchanged.
- `/api/auth/platform-identity` must distinguish anonymous visitors from authenticated users.
- `PLATFORM_IDENTITY_SECRET`, `PASSKEY_RP_ID`, and `PASSKEY_ORIGIN` must be configured in the production runtime.
- Finalize the domain first, because existing Passkeys will not work under a different RP ID after a domain change.
- Recommend two recovery Passkeys and document federated-identity account recovery as the final recovery boundary.

## Future Standard OIDC Extension

In the current deployment, where Sites does not expose an external OIDC Core callback directly to the application, SIWC is the supported federated-identity boundary. If provider-neutral OIDC becomes mandatory, link a pseudonymized `issuer + subject` value to the same account key using HMAC, then add Authorization Code + PKCE, `state`, `nonce`, signature, issuer, audience, and expiration validation. Do not use an email address as the account key.
