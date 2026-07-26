import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

test("renders the finished Korean marketplace instead of starter content", async () => {
  const [layout, page, walletPage, client, packageJson] = await Promise.all([
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/wallet/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/marketplace-client.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);
  assert.match(layout, /<html lang="ko">/i);
  assert.match(layout, /SAFER — 안전한 중고거래/);
  assert.match(page, /view="home"/);
  assert.match(walletPage, /view="wallet"/);
  assert.match(client, /좋은 거래는/);
  assert.match(client, /신뢰에서 시작돼요/);
  assert.match(client, /거래 보호 중/);
  assert.match(client, /MAX_CLIENT_IMAGE_BYTES = 5 \* 1024 \* 1024/);
  assert.match(client, /JPEG\(\.jpg, \.jpeg\), PNG\(\.png\), WebP\(\.webp\)/);
  assert.match(client, /status === 413/);
  assert.match(client, /선택한 파일은.*formatFileSize/);
  assert.doesNotMatch(`${layout}${page}${client}${packageJson}`, /codex-preview|Your site is taking shape|react-loading-skeleton/i);
  await assert.rejects(access(new URL("../app/_sites-preview/SkeletonPreview.tsx", import.meta.url)));
});

test("adds browser hardening headers", async () => {
  const worker = await readFile(new URL("../worker/index.ts", import.meta.url), "utf8");
  assert.match(worker, /x-content-type-options.*nosniff/);
  assert.match(worker, /x-frame-options.*DENY/);
  assert.match(worker, /referrer-policy.*no-referrer/);
  assert.match(worker, /object-src 'none'/);
  assert.match(worker, /frame-ancestors 'none'/);
  assert.match(worker, /form-action 'self'/);
  assert.match(worker, /frame-src 'none'/);
  assert.doesNotMatch(worker, /challenges\.cloudflare\.com/);
  assert.match(worker, /cross-origin-resource-policy.*same-origin/);
  assert.match(worker, /x-permitted-cross-domain-policies.*none/);
  assert.match(worker, /script-src-attr 'none'/);
  assert.match(worker, /nonce-\$\{nonce\}/);
  assert.match(worker, /getRandomValues\(new Uint8Array\(16\)\)/);
  assert.match(worker, /'strict-dynamic'/);
  assert.doesNotMatch(worker, /script-src[^\n]*'unsafe-inline'/);
  assert.match(worker, /style-src 'self' 'nonce-\$\{nonce\}'/);
  assert.doesNotMatch(worker, /style-src 'self' 'unsafe-inline'/);
  assert.match(worker, /style-src-attr 'unsafe-inline'/);
  assert.match(worker, /content-security-policy-report-only/);
  assert.match(worker, /report-uri \/api\/security\/csp-report/);
  assert.match(worker, /reporting-endpoints/);
  assert.match(worker, /allowDevelopmentWebSockets/);
  assert.match(worker, /url\.protocol === "http:"/);
  assert.match(worker, /"connect-src 'self'"/);
  assert.match(worker, /content-type.*text\/html/);
  assert.match(worker, /cache-control", "private, no-store/);
  assert.match(worker, /headers\.delete\("server"\)/);
  assert.match(worker, /x-api-version.*1/);
});

test("keeps security controls explicit in source and migrations", async () => {
  const [security, database, api, passkeys, migration, walletMigration, tradeMigration, privacyMigration, platformIdentityMigration, passkeyMigration, adminBootstrapMigration, zeroBalanceMigration, sessionPolicyMigration, client, layout, boundary, viteConfig, coverage, lockCheck, zapRunner, zapRules] = await Promise.all([
    readFile(new URL("../lib/security.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/db.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/[...path]/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/passkeys.ts", import.meta.url), "utf8"),
    readFile(new URL("../drizzle/0000_light_hawkeye.sql", import.meta.url), "utf8"),
    readFile(new URL("../drizzle/0001_cool_sentry.sql", import.meta.url), "utf8"),
    readFile(new URL("../drizzle/0002_yielding_avengers.sql", import.meta.url), "utf8"),
    readFile(new URL("../drizzle/0005_tense_molten_man.sql", import.meta.url), "utf8"),
    readFile(new URL("../drizzle/0006_platform_identity.sql", import.meta.url), "utf8"),
    readFile(new URL("../drizzle/0007_passkeys.sql", import.meta.url), "utf8"),
    readFile(new URL("../drizzle/0008_require_runtime_admin_bootstrap.sql", import.meta.url), "utf8"),
    readFile(new URL("../drizzle/0009_zero_unearned_wallet_balances.sql", import.meta.url), "utf8"),
    readFile(new URL("../drizzle/0010_invalidate_legacy_sessions.sql", import.meta.url), "utf8"),
    readFile(new URL("../app/marketplace-client.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/browser-security-boundary.tsx", import.meta.url), "utf8"),
    readFile(new URL("../vite.config.ts", import.meta.url), "utf8"),
    readFile(new URL("../docs/security/owasp-coverage.md", import.meta.url), "utf8"),
    readFile(new URL("../scripts/verify-lockfile.mjs", import.meta.url), "utf8"),
    readFile(new URL("../scripts/run-zap-regression.sh", import.meta.url), "utf8"),
    readFile(new URL("../security/zap/rules.conf", import.meta.url), "utf8"),
  ]);

  assert.match(security, /PASSWORD_ITERATIONS = 100_000/);
  assert.match(security, /iterations !== PASSWORD_ITERATIONS/);
  assert.match(security, /PBKDF2/);
  assert.match(security, /HttpOnly/);
  assert.match(security, /SameSite=Strict/);
  assert.match(security, /SESSION_TTL_MS = 8 \* 60 \* 60 \* 1000/);
  assert.match(security, /SESSION_IDLE_TIMEOUT_MS = 30 \* 60 \* 1000/);
  assert.match(security, /DELETE FROM sessions WHERE user_id = \? OR expires_at <= \? OR last_seen_at <= \?/);
  assert.match(security, /SESSION_EXPIRED/);
  assert.match(security, /await destroySession\(request/);
  assert.match(security, /CSRF_REJECTED/);
  assert.match(security, /RETURNING count, window_started_at/);
  assert.match(security, /RATE_LIMIT_RETENTION_MS = 2 \* 24 \* 60 \* 60 \* 1000/);
  assert.match(security, /DELETE FROM rate_limits WHERE window_started_at <= \?/);
  assert.match(security, /retry-after/);
  assert.match(security, /BOT_CHALLENGE_TTL_MS = 15 \* 60 \* 1000/);
  assert.match(security, /BOT_PROTECTION_MODE/);
  assert.match(security, /BOT_PROTECTION_SECRET/);
  assert.match(security, /SAFER-BOT-CHALLENGE/);
  assert.match(security, /bot_protection\.honeypot/);
  assert.match(security, /bot_protection\.blocked/);
  assert.match(security, /enforceIdentityRateLimit/);
  assert.doesNotMatch(security, /turnstile/i);
  assert.match(security, /assertAllowedFields/);
  assert.match(security, /UNKNOWN_FIELD/);
  assert.match(security, /readFormData/);
  assert.match(security, /reader\.cancel/);
  assert.match(security, /validateMutationRequest/);
  assert.match(security, /sec-fetch-site/);
  assert.match(security, /ORIGIN_REQUIRED/);
  assert.match(security, /const referer = request\.headers\.get\("referer"\)/);
  assert.match(security, /x-request-id/);
  assert.match(security, /HMAC/);
  assert.match(security, /requirePlatformIdentity/);
  assert.match(security, /oai-authenticated-user-email/);
  assert.match(security, /PLATFORM_IDENTITY_SECRET/);
  assert.match(security, /SAFER-PLATFORM-IDENTITY-V1/);
  assert.doesNotMatch(security, /randomNumericCode/);
  assert.match(api, /verifyBotProtection\(request, body\.botChallenge, body\.website, "signup"\)/);
  assert.match(api, /verifyBotProtection\(request, body\.botChallenge, body\.website, "login"\)/);
  assert.match(api, /enforceIdentityRateLimit\("login-account"/);
  assert.match(api, /enforceIdentityRateLimit\("signup-platform-identity"/);
  assert.match(api, /receiveCspReport/);
  assert.match(api, /receiveBrowserEvent/);
  assert.match(api, /export async function OPTIONS/);
  assert.match(api, /allowedApiMethods/);
  assert.match(api, /API_METHOD_ORDER/);
  assert.match(api, /"allow": methods\.join/);
  assert.match(api, /SECURITY_REPORT_MAX_BYTES = 16 \* 1024/);
  assert.match(api, /logSafeOperationalError/);
  assert.match(api, /decodeURIComponent\(keyValue\)/);
  assert.match(boundary, /getDerivedStateFromError/);
  assert.match(boundary, /componentDidCatch/);
  assert.match(boundary, /securitypolicyviolation/);
  assert.match(boundary, /unhandledrejection/);
  assert.match(layout, /<BrowserSecurityBoundary>\{children\}<\/BrowserSecurityBoundary>/);
  assert.match(layout, /trustedMetadataHost/);
  assert.match(layout, /chatgpt\\\.site/);
  assert.match(zapRunner, /active scans are restricted to localhost test targets/);
  assert.match(zapRunner, /ZAP_ALLOW_ACTIVE_SCAN/);
  assert.match(zapRules, /40012\s+FAIL/);
  assert.doesNotMatch(security, /SELECT count FROM rate_limits/);
  assert.match(api, /image\/jpeg/);
  assert.match(api, /MAX_IMAGE_BYTES = 5 \* 1024 \* 1024/);
  assert.match(api, /seenFormFields/);
  assert.match(api, /Idempotency|idempotency/i);
  assert.match(api, /SIGNUP_RATE_LIMIT_MAX = 20/);
  assert.match(api, /SIGNUP_RATE_LIMIT_WINDOW_SECONDS = 15 \* 60/);
  assert.match(api, /TRANSFER_ATTEMPT_RATE_LIMIT_MAX = 30/);
  assert.match(api, /TRANSFER_ATTEMPT_RATE_LIMIT_WINDOW_SECONDS = 60/);
  assert.match(api, /TRANSFER_SUBMIT_RATE_LIMIT_MAX = 60/);
  assert.match(api, /transfer-attempt:/);
  assert.match(api, /transfer-submit:/);
  assert.match(api, /IDEMPOTENCY_CONFLICT/);
  assert.doesNotMatch(api, /pbkdf2-sha256\$600000/);
  assert.doesNotMatch(api, /\.exec\(/);
  assert.match(migration, /CREATE TRIGGER `transfers_validate_before_insert`/);
  assert.match(migration, /INSUFFICIENT_FUNDS/);
  assert.match(migration, /CREATE TRIGGER `reports_moderate_product_after_insert`/);
  assert.match(migration, /CREATE TRIGGER `reports_moderate_user_after_insert`/);
  assert.match(security, /SAFER-WALLET-V1/);
  assert.match(security, /export async function sha256Hex/);
  assert.match(security, /byte\.toString\(16\)\.padStart\(2, "0"\)/);
  assert.match(api, /await sha256Hex\(message\)/);
  assert.doesNotMatch(api, /message_hash[\s\S]{0,500}await sha256\(message\)/);
  assert.match(api, /PLATFORM_ACCOUNT_EXISTS/);
  assert.match(api, /USERNAME_TAKEN/);
  assert.match(api, /WHERE platform_identity_hash = \? LIMIT 1/);
  assert.match(api, /WHERE username = \? LIMIT 1/);
  assert.doesNotMatch(api, /WHERE username = \? OR platform_identity_hash = \?/);
  assert.match(api, /walletIdField\(body\.walletId\)/);
  assert.match(api, /senderWallet\.id === recipientWallet\.id/);
  assert.match(api, /송금 주소와 입금 주소가 동일합니다/);
  assert.doesNotMatch(api, /u\.username LIKE \?[^\n]+w\.id LIKE/);
  assert.match(api, /sender_wallet_id, recipient_wallet_id/);
  assert.match(walletMigration, /CREATE TABLE `wallets`/);
  assert.match(walletMigration, /INVALID_SENDER_WALLET/);
  assert.match(walletMigration, /INVALID_RECIPIENT_WALLET/);
  assert.match(walletMigration, /SELF_TRANSFER/);
  assert.match(walletMigration, /DROP TRIGGER IF EXISTS `transfers_validate_before_insert`/);
  assert.match(tradeMigration, /CREATE TABLE `product_trades`/);
  assert.match(tradeMigration, /product_trades_open_product_unique/);
  assert.match(tradeMigration, /INVALID_PRODUCT_TRADE/);
  assert.match(tradeMigration, /UPDATE `products` SET `sold_at`/);
  assert.match(tradeMigration, /UPDATE `product_trades` SET `status` = 'completed'/);
  assert.match(api, /database\.batch\(\[/);
  assert.match(api, /product_trade\.completed/);
  assert.match(api, /public_alias AS seller_alias/);
  assert.match(api, /public_alias AS sender_alias/);
  assert.match(api, /peer_wallet_id/);
  assert.match(api, /peer_alias/);
  const publicTransferSection = api.slice(api.indexOf("async function listTransfers"), api.indexOf("async function listProductTrades"));
  assert.doesNotMatch(publicTransferSection, /username|JOIN users/);
  assert.match(database, /wallet_activated_at IS NULL/);
  assert.match(database, /AND balance = 0/);
  assert.doesNotMatch(database, /THEN 100000/);
  assert.match(database, /users_inactive_balance_before_insert/);
  assert.match(database, /INACTIVE_WALLET_BALANCE/);
  assert.match(database, /EXISTS \(SELECT 1 FROM wallets/);
  assert.match(database, /EXISTS \(SELECT 1 FROM web3_wallets/);
  assert.match(api, /activateWalletAccountIfReady/);
  assert.match(api, /'user', 'active', 0, NULL/);
  assert.doesNotMatch(client, /peerUsername|seller\.username/);
  assert.match(client, /publicAlias/);
  assert.match(client, /walletReady/);
  assert.match(client, /거래 상대 \{trade\.counterpartyAlias\}/);
  assert.match(client, /잔액 표시가 활성화되며 0원에서 시작합니다/);
  assert.doesNotMatch(client, /초기 거래 잔액이 지급되었습니다/);
  assert.match(client, /product-trades\/\$\{trade\.id\}\/pay/);
  assert.match(client, /지갑으로 상품 거래/);
  assert.match(client, /구매 요청 승인/);
  assert.match(client, /상품 결제가 완료/);
  assert.match(client, /MARKETPLACE TRADES/);
  assert.match(client, /위험 기반 요청 보호/);
  assert.match(client, /name="website"/);
  assert.match(client, /\/api\/auth\/bot-challenge/);
  assert.doesNotMatch(client, /Turnstile|TURNSTILE/);
  assert.match(client, /ChatGPT 연합 신원/);
  assert.match(client, /신원 확인 후 가입/);
  assert.match(client, /이 ChatGPT 신원으로 SAFER 가입/);
  assert.match(client, /platformIdentity\.accountLinked === false/);
  assert.match(client, /이미 연결된 계정이 있습니다/);
  assert.match(client, /기존 SAFER 계정으로 로그인/);
  assert.match(client, /비공개 Sites가 전달한 인증 신원만 사용/);
  assert.doesNotMatch(client, /\/signin-with-chatgpt/);
  assert.match(client, /\/api\/auth\/platform-login/);
  assert.match(client, /startAuthentication/);
  assert.match(client, /startRegistration/);
  assert.match(client, /Passkey로 로그인/);
  assert.match(client, /8시간·30분 유휴 만료 서버 세션/);
  assert.match(client, /\/login\?reason=session-expired/);
  assert.match(client, /로그인 세션이 만료되었습니다/);
  assert.match(client, /Passkey 관리/);
  assert.match(client, /compactPublicAlias/);
  assert.match(client, /공개 hash 별칭 전체 복사/);
  assert.match(client, /result\.user\.role === "admin" \? "\/admin" : "\/market"/);
  assert.match(client, /관리자 대시보드/);
  assert.match(client, /admin-dashboard-grid/);
  assert.match(client, /!isAdminConsole \? <Header/);
  assert.match(client, /!isAdminConsole \? <Footer/);
  assert.match(client, /function AdminFrame/);
  assert.match(client, /admin-console-topbar/);
  assert.match(client, /관리자 로그아웃/);
  assert.match(client, /사용자 화면/);
  assert.match(client, /ADMINISTRATOR/);
  assert.doesNotMatch(client, /name="email"/);
  assert.doesNotMatch(client, /\/api\/auth\/signup\/verify/);
  assert.doesNotMatch(client, /one-time-code|인증번호 유효시간/);
  assert.match(client, /개인 지갑 등록하기/);
  assert.match(client, /복구 seed · 이번에만 표시됩니다/);
  assert.match(client, /name="walletId"/);
  assert.match(client, /pattern="wlt_\[A-Za-z0-9_-\]\{43\}"/);
  assert.match(client, /사용자 아이디는 사용할 수 없습니다/);
  assert.match(client, /송금 주소와 입금 주소가 동일합니다/);
  assert.match(client, /transferRequestKey\.current \|\| crypto\.randomUUID\(\)/);
  assert.match(client, /disabled=\{transferPending\}/);
  assert.match(client, /송금 처리 중…/);
  assert.match(client, /ethereumProviderErrorMessage/);
  assert.match(client, /code === -32002/);
  assert.match(client, /code === 4001/);
  assert.match(client, /decodeURIComponent\(value\.slice\(prefix\.length\)\)/);
  assert.match(client, /href="\/wallet">지갑·거래/);
  assert.match(client, /function WalletCenter/);
  assert.match(client, /wallet-flow-panels/);
  assert.match(client, /<h2>송금<\/h2>/);
  assert.match(client, /<h2>수금<\/h2>/);
  assert.match(client, /거래 데이터 필터/);
  assert.match(client, /useState<"account" \| "products">/);
  assert.doesNotMatch(client, /tab === "wallet"/);
  assert.doesNotMatch(client, /\/api\/wallets\?q=/);
  assert.doesNotMatch(client, /아이디 또는 wlt_ hash ID 검색/);
  assert.doesNotMatch(viteConfig, /\.openai\/hosting\.json/);
  assert.match(viteConfig, /process\.env\.SAFER_D1_BINDING \?\? "DB"/);
  assert.match(viteConfig, /process\.env\.SAFER_R2_BINDING \?\? "UPLOADS"/);

  assert.match(privacyMigration, /ALTER TABLE `users` ADD `public_alias` text/);
  assert.match(privacyMigration, /ALTER TABLE `users` ADD `wallet_activated_at` integer/);
  assert.match(privacyMigration, /ALTER TABLE `product_trades` ADD `buyer_alias` text/);
  assert.match(privacyMigration, /ALTER TABLE `product_trades` ADD `seller_alias` text/);
  assert.match(privacyMigration, /UPDATE `users` SET `balance` = 0/);
  assert.match(privacyMigration, /wallet_activated_at` IS NOT NULL/);
  assert.match(privacyMigration, /users_inactive_balance_before_update/);
  assert.match(privacyMigration, /INACTIVE_WALLET_BALANCE/);
  assert.match(platformIdentityMigration, /DELETE FROM `pending_signups`/);
  assert.match(platformIdentityMigration, /ALTER TABLE `users` ADD `platform_identity_hash` text/);
  assert.match(platformIdentityMigration, /CREATE UNIQUE INDEX `users_platform_identity_hash_unique`/);
  assert.ok(passkeyMigration.includes("CREATE TABLE `passkey_challenges`"));
  assert.ok(passkeyMigration.includes("CREATE TABLE `passkey_credentials`"));
  assert.match(passkeyMigration, /passkey_challenges_kind/);
  assert.match(passkeyMigration, /passkey_credentials_counter_nonnegative/);
  assert.match(adminBootstrapMigration, /ADMIN_BOOTSTRAP_TOKEN/);
  assert.doesNotMatch(adminBootstrapMigration, /slash202|SET `role` = 'admin'/);
  assert.match(zeroBalanceMigration, /wallet\.legacy_activation_grant_reversed/);
  assert.match(zeroBalanceMigration, /SET `balance` = 0/);
  assert.match(zeroBalanceMigration, /NOT EXISTS \([\s\S]*FROM `transfers`/);
  assert.match(sessionPolicyMigration, /auth\.sessions_revoked_policy_upgrade/);
  assert.match(sessionPolicyMigration, /DELETE FROM `sessions`/);
  assert.match(passkeys, /verifyRegistrationResponse/);
  assert.match(passkeys, /verifyAuthenticationResponse/);
  assert.match(passkeys, /userVerification: "required"/);
  assert.match(passkeys, /attestationType: "none"/);
  assert.match(passkeys, /supportedAlgorithmIDs: \[-7, -257\]/);
  assert.match(passkeys, /DELETE FROM passkey_challenges/);
  assert.match(passkeys, /expectedOrigin: challenge\.origin/);
  assert.match(passkeys, /expectedRPID: challenge\.rp_id/);
  assert.match(passkeys, /auth\.passkey_login/);
  assert.match(database, /users_platform_identity_hash_unique/);
  assert.match(api, /platform_identity_hash/);
  assert.match(api, /identityProvider: "sites-chatgpt"/);
  assert.doesNotMatch(api, /sendSignupVerificationEmail|EMAIL_VERIFICATION_TTL_MS|signupCodeHash/);
  assert.match(api, /api-write.*, 180, 60/);
  assert.match(api, /securityAlerts/);
  assert.match(lockCheck, /sha512-/);
  for (let index = 1; index <= 10; index += 1) {
    assert.match(coverage, new RegExp(`API${index}:2023`));
    assert.match(coverage, new RegExp(`A${String(index).padStart(2, "0")}:2025`));
  }
});
