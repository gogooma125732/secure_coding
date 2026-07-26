import { activateWalletAccountIfReady, audit, getDatabase, getEnv } from "../../../lib/db";
import {
  HttpError,
  constantTimeTextEqual,
  createBotChallenge,
  createSession,
  createWalletIdentity,
  destroySession,
  enforceRateLimit,
  enforceIdentityRateLimit,
  handleError,
  hashPassword,
  integerField,
  json,
  readJson,
  randomToken,
  readFormData,
  requireAdmin,
  requirePlatformIdentity,
  requireSession,
  sha256,
  sha256Hex,
  textField,
  validatePassword,
  validateMutationRequest,
  validateUsername,
  verifyBotProtection,
  verifyPassword,
} from "../../../lib/security";
import {
  createSiweMessage,
  normalizeWalletAddress,
  publicWeb3Config,
  verifyWalletOwnership,
  web3Config,
} from "../../../lib/web3";
import {
  createPasskeyAuthenticationOptions,
  createPasskeyRegistrationOptions,
  deletePasskey,
  getPasskeys,
  verifyPasskeyAuthentication,
  verifyPasskeyRegistration,
} from "../../../lib/passkeys";

export const dynamic = "force-dynamic";

const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
const MAX_PRODUCT_REQUEST_BYTES = 6 * 1024 * 1024;
const REPORT_THRESHOLD = 3;
const SIGNUP_RATE_LIMIT_MAX = 20;
const SIGNUP_RATE_LIMIT_WINDOW_SECONDS = 15 * 60;
const TRANSFER_ATTEMPT_RATE_LIMIT_MAX = 30;
const TRANSFER_ATTEMPT_RATE_LIMIT_WINDOW_SECONDS = 60;
const TRANSFER_SUBMIT_RATE_LIMIT_MAX = 60;
const TRANSFER_SUBMIT_RATE_LIMIT_WINDOW_SECONDS = 60 * 60;
const WEB3_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const SECURITY_REPORT_MAX_BYTES = 16 * 1024;
const API_METHOD_ORDER = ["GET", "HEAD", "POST", "PATCH", "DELETE", "OPTIONS"] as const;

const GET_API_PATHS = [
  /^\/auth\/me$/u,
  /^\/auth\/platform-identity$/u,
  /^\/auth\/passkeys$/u,
  /^\/auth\/bot-challenge$/u,
  /^\/products$/u,
  /^\/products\/[^/]+$/u,
  /^\/images\/[^/]+$/u,
  /^\/users$/u,
  /^\/users\/[^/]+$/u,
  /^\/chat\/group$/u,
  /^\/chat\/direct$/u,
  /^\/wallets\/me$/u,
  /^\/web3\/config$/u,
  /^\/web3\/wallet$/u,
  /^\/transfers$/u,
  /^\/product-trades$/u,
  /^\/admin\/summary$/u,
] as const;

const POST_API_PATHS = [
  /^\/security\/csp-report$/u,
  /^\/security\/browser-event$/u,
  /^\/auth\/signup$/u,
  /^\/auth\/login$/u,
  /^\/auth\/platform-login$/u,
  /^\/auth\/passkeys\/registration\/options$/u,
  /^\/auth\/passkeys\/registration\/verify$/u,
  /^\/auth\/passkeys\/authentication\/options$/u,
  /^\/auth\/passkeys\/authentication\/verify$/u,
  /^\/auth\/logout$/u,
  /^\/products$/u,
  /^\/reports$/u,
  /^\/chat\/group$/u,
  /^\/chat\/direct$/u,
  /^\/wallets$/u,
  /^\/web3\/challenge$/u,
  /^\/web3\/link$/u,
  /^\/transfers$/u,
  /^\/product-trades$/u,
  /^\/product-trades\/[^/]+\/pay$/u,
  /^\/admin\/bootstrap$/u,
] as const;

const PATCH_API_PATHS = [
  /^\/profile$/u,
  /^\/products\/[^/]+$/u,
  /^\/product-trades\/[^/]+$/u,
  /^\/admin\/users\/[^/]+$/u,
  /^\/admin\/products\/[^/]+$/u,
  /^\/admin\/reports\/[^/]+$/u,
] as const;

const DELETE_API_PATHS = [
  /^\/auth\/passkeys\/[^/]+$/u,
  /^\/admin\/messages\/[^/]+$/u,
  /^\/products\/[^/]+$/u,
] as const;

export async function GET(request: Request): Promise<Response> {
  try {
    await enforceRateLimit(request, "api-read", 600, 60);
    const url = new URL(request.url);
    const path = apiPath(url);

    if (path === "/auth/me") return await getCurrentUser(request);
    if (path === "/auth/platform-identity") return await getPlatformIdentityStatus(request);
    if (path === "/auth/passkeys") return await getPasskeys(request);
    if (path === "/auth/bot-challenge") return await createBotChallenge(request, url.searchParams.get("action"));
    if (path === "/products") return await listProducts(request, url);
    if (path.startsWith("/products/")) return await getProduct(request, path.slice(10));
    if (path.startsWith("/images/")) return await getImage(path.slice(8));
    if (path === "/users") return await listUsers(request, url);
    if (path.startsWith("/users/")) return await getUserProfile(path.slice(7));
    if (path === "/chat/group") return await listGroupMessages(request, url);
    if (path === "/chat/direct") return await listDirectMessages(request, url);
    if (path === "/wallets/me") return await getMyWallet(request);
    if (path === "/web3/config") return json(publicWeb3Config());
    if (path === "/web3/wallet") return await getLinkedWeb3Wallet(request);
    if (path === "/transfers") return await listTransfers(request);
    if (path === "/product-trades") return await listProductTrades(request, url);
    if (path === "/admin/summary") return await getAdminSummary(request);
    throw new HttpError(404, "NOT_FOUND", "요청한 항목을 찾을 수 없습니다.");
  } catch (error) {
    return handleError(error, request);
  }
}

export async function POST(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    const path = apiPath(url);
    if (path === "/security/csp-report") return await receiveCspReport(request);
    validateMutationRequest(request);
    await enforceRateLimit(request, "api-write", 180, 60);

    if (path === "/security/browser-event") return await receiveBrowserEvent(request);
    if (path === "/auth/signup") return await signUp(request);
    if (path === "/auth/login") return await login(request);
    if (path === "/auth/platform-login") return await platformLogin(request);
    if (path === "/auth/passkeys/registration/options") return await createPasskeyRegistrationOptions(request);
    if (path === "/auth/passkeys/registration/verify") return await verifyPasskeyRegistration(request);
    if (path === "/auth/passkeys/authentication/options") return await createPasskeyAuthenticationOptions(request);
    if (path === "/auth/passkeys/authentication/verify") return await verifyPasskeyAuthentication(request);
    if (path === "/auth/logout") return await logout(request);
    if (path === "/products") return await createProduct(request);
    if (path === "/reports") return await createReport(request);
    if (path === "/chat/group") return await sendGroupMessage(request);
    if (path === "/chat/direct") return await sendDirectMessage(request);
    if (path === "/wallets") return await createWallet(request);
    if (path === "/web3/challenge") return await createWeb3Challenge(request);
    if (path === "/web3/link") return await linkWeb3Wallet(request);
    if (path === "/transfers") return await transferMoney(request);
    if (path === "/product-trades") return await createProductTrade(request);
    if (path.startsWith("/product-trades/") && path.endsWith("/pay")) return await payProductTrade(request, path.slice(16, -4));
    if (path === "/admin/bootstrap") return await bootstrapAdministrator(request);
    throw new HttpError(404, "NOT_FOUND", "요청한 항목을 찾을 수 없습니다.");
  } catch (error) {
    return handleError(error, request);
  }
}

export async function PATCH(request: Request): Promise<Response> {
  try {
    validateMutationRequest(request);
    await enforceRateLimit(request, "api-write", 180, 60);
    const path = apiPath(new URL(request.url));
    if (path === "/profile") return await updateProfile(request);
    if (path.startsWith("/products/")) return await updateProduct(request, path.slice(10));
    if (path.startsWith("/product-trades/")) return await updateProductTrade(request, path.slice(16));
    if (path.startsWith("/admin/users/")) return await administerUser(request, path.slice(13));
    if (path.startsWith("/admin/products/")) return await administerProduct(request, path.slice(16));
    if (path.startsWith("/admin/reports/")) return await administerReport(request, path.slice(15));
    throw new HttpError(404, "NOT_FOUND", "요청한 항목을 찾을 수 없습니다.");
  } catch (error) {
    return handleError(error, request);
  }
}

export async function DELETE(request: Request): Promise<Response> {
  try {
    validateMutationRequest(request);
    await enforceRateLimit(request, "api-write", 180, 60);
    const path = apiPath(new URL(request.url));
    if (path.startsWith("/auth/passkeys/")) return await deletePasskey(request, path.slice(15));
    if (path.startsWith("/admin/messages/")) return await deleteMessageAsAdmin(request, path.slice(16));
    if (path.startsWith("/products/")) return await deleteProduct(request, path.slice(10));
    throw new HttpError(404, "NOT_FOUND", "요청한 항목을 찾을 수 없습니다.");
  } catch (error) {
    return handleError(error, request);
  }
}

export async function OPTIONS(request: Request): Promise<Response> {
  try {
    const path = apiPath(new URL(request.url));
    const methods = allowedApiMethods(path);
    if (methods.length === 0) {
      throw new HttpError(404, "NOT_FOUND", "요청한 항목을 찾을 수 없습니다.");
    }
    return new Response(null, {
      status: 204,
      headers: {
        "allow": methods.join(", "),
        "cache-control": "no-store",
      },
    });
  } catch (error) {
    return handleError(error, request);
  }
}

async function receiveCspReport(request: Request): Promise<Response> {
  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite && fetchSite !== "same-origin" && fetchSite !== "none") {
    throw new HttpError(403, "CROSS_ORIGIN_REJECTED", "교차 출처 보안 보고는 허용되지 않습니다.");
  }
  await enforceRateLimit(request, "csp-report", 120, 60);
  const payload = await readSecurityReportJson(request);
  const candidate = Array.isArray(payload)
    ? payload.find((item) => isRecord(item) && item.type === "csp-violation")
    : payload;
  const envelope = isRecord(candidate) && isRecord(candidate.body)
    ? candidate.body
    : isRecord(candidate) && isRecord(candidate["csp-report"])
      ? candidate["csp-report"]
      : candidate;
  if (!isRecord(envelope)) throw new HttpError(400, "INVALID_SECURITY_REPORT", "보안 보고 형식을 확인할 수 없습니다.");

  const directive = securityReportText(envelope.effectiveDirective ?? envelope["effective-directive"], 80, "unknown");
  const disposition = securityReportText(envelope.disposition, 20, "report");
  const documentUrl = envelope.documentURL ?? envelope["document-uri"];
  const blockedUrl = envelope.blockedURL ?? envelope["blocked-uri"];
  const database = await getDatabase();
  await audit(database, null, "browser.csp_violation", "security_policy", directive, {
    directive,
    disposition,
    document: safeReportUrl(documentUrl, request, false),
    blocked: safeReportUrl(blockedUrl, request, true),
    statusCode: boundedSecurityInteger(envelope.statusCode ?? envelope["status-code"]),
  });
  return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
}

async function receiveBrowserEvent(request: Request): Promise<Response> {
  await enforceRateLimit(request, "browser-event", 60, 60);
  const body = await readJson(request, SECURITY_REPORT_MAX_BYTES, ["kind", "message", "source", "line", "column", "componentStack", "route"]);
  const kind = textField(body.kind, "브라우저 이벤트", 3, 40, {
    pattern: /^(?:react_render_error|window_error|unhandled_rejection|csp_violation)$/u,
  });
  const message = redactBrowserEventText(textField(body.message, "오류 분류", 1, 160), 160);
  const source = body.source === undefined ? "" : redactBrowserEventText(textField(body.source, "오류 위치", 0, 256), 256);
  const route = textField(body.route, "화면 경로", 1, 256, { pattern: /^\/(?:[^?#\u0000-\u001f]*)$/u });
  const componentStack = body.componentStack === undefined
    ? ""
    : redactBrowserEventText(textField(body.componentStack, "컴포넌트 정보", 0, 1_500, { trim: false }), 1_500);
  const database = await getDatabase();
  await audit(database, null, `browser.${kind}`, "browser", route, {
    kind,
    message,
    source,
    line: boundedSecurityInteger(body.line),
    column: boundedSecurityInteger(body.column),
    componentStack,
  });
  return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
}

async function readSecurityReportJson(request: Request): Promise<unknown> {
  const contentType = (request.headers.get("content-type") ?? "").split(";", 1)[0].trim().toLowerCase();
  if (!["application/csp-report", "application/reports+json", "application/json"].includes(contentType)) {
    throw new HttpError(415, "UNSUPPORTED_SECURITY_REPORT", "지원하지 않는 보안 보고 형식입니다.");
  }
  const declaredLength = Number(request.headers.get("content-length") ?? 0);
  if (declaredLength > SECURITY_REPORT_MAX_BYTES) throw new HttpError(413, "PAYLOAD_TOO_LARGE", "보안 보고가 너무 큽니다.");
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > SECURITY_REPORT_MAX_BYTES) {
    throw new HttpError(413, "PAYLOAD_TOO_LARGE", "보안 보고가 너무 큽니다.");
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new HttpError(400, "INVALID_SECURITY_REPORT", "보안 보고 형식을 확인할 수 없습니다.");
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function securityReportText(value: unknown, maximum: number, fallback: string): string {
  if (typeof value !== "string") return fallback;
  return value.normalize("NFC").replace(/[\u0000-\u001f\u007f]/gu, "").slice(0, maximum) || fallback;
}

function safeReportUrl(value: unknown, request: Request, allowKeyword: boolean): string {
  const text = securityReportText(value, 1_024, "unknown");
  if (allowKeyword && /^(?:inline|eval|self|data|blob)$/u.test(text)) return text;
  try {
    const reportUrl = new URL(text, request.url);
    const requestOrigin = new URL(request.url).origin;
    return reportUrl.origin === requestOrigin ? reportUrl.pathname.slice(0, 256) : reportUrl.origin.slice(0, 256);
  } catch {
    return "invalid-url";
  }
}

function boundedSecurityInteger(value: unknown): number | null {
  return Number.isSafeInteger(value) && Number(value) >= 0 && Number(value) <= 10_000_000 ? Number(value) : null;
}

function redactBrowserEventText(value: string, maximum: number): string {
  return value
    .replace(/(?:bearer\s+|token[=:]\s*)[A-Za-z0-9._~-]+/giu, "[REDACTED]")
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/giu, "[EMAIL]")
    .replace(/[\u0000-\u001f\u007f]/gu, " ")
    .slice(0, maximum);
}

async function signUp(request: Request): Promise<Response> {
  const body = await readJson(request, 32_000, ["username", "password", "bio", "botChallenge", "website"]);
  const username = validateUsername(body.username);
  const password = validatePassword(body.password);
  const bio = body.bio === undefined ? "" : textField(body.bio, "소개글", 0, 300);
  const platformIdentityHash = await requirePlatformIdentity(request);
  await enforceRateLimit(request, "signup", SIGNUP_RATE_LIMIT_MAX, SIGNUP_RATE_LIMIT_WINDOW_SECONDS);
  await enforceIdentityRateLimit("signup-platform-identity", platformIdentityHash, 3, 3600);
  await enforceIdentityRateLimit("signup-username", await sha256(username), 5, 3600);
  await verifyBotProtection(request, body.botChallenge, body.website, "signup");
  const database = await getDatabase();
  const now = Date.now();
  const id = crypto.randomUUID();
  const publicAlias = createMarketplaceAlias();
  const passwordHash = await hashPassword(password);
  const existingPlatformAccount = await database
    .prepare("SELECT id FROM users WHERE platform_identity_hash = ? LIMIT 1")
    .bind(platformIdentityHash)
    .first();
  if (existingPlatformAccount) {
    await audit(database, null, "auth.signup_conflict", "signup", null, { reason: "platform_identity" });
    throw new HttpError(409, "PLATFORM_ACCOUNT_EXISTS", "이 ChatGPT 신원은 이미 SAFER 계정과 연결되어 있습니다. 기존 계정으로 로그인해 주세요.");
  }
  const existingUsername = await database
    .prepare("SELECT id FROM users WHERE username = ? LIMIT 1")
    .bind(username)
    .first();
  if (existingUsername) {
    await audit(database, null, "auth.signup_conflict", "signup", null, { reason: "username" });
    throw new HttpError(409, "USERNAME_TAKEN", "이미 사용 중인 아이디입니다. 다른 아이디를 입력해 주세요.");
  }
  try {
    await database.batch([
      database
        .prepare(`INSERT INTO users
                  (id, username, public_alias, platform_identity_hash, email, email_verified_at,
                   password_hash, bio, role, status, balance, wallet_activated_at, failed_logins, created_at, updated_at)
                  VALUES (?, ?, ?, ?, NULL, NULL, ?, ?, 'user', 'active', 0, NULL, 0, ?, ?)`)
        .bind(id, username, publicAlias, platformIdentityHash, passwordHash, bio, now, now),
      database.prepare("DELETE FROM pending_signups WHERE username = ?").bind(username),
      database
        .prepare("INSERT INTO audit_logs (id, actor_id, action, target_type, target_id, metadata, created_at) VALUES (?, ?, 'auth.signup', 'user', ?, ?, ?)")
        .bind(crypto.randomUUID(), id, id, JSON.stringify({ identityProvider: "sites-chatgpt" }), now),
    ]);
  } catch (error) {
    if (error instanceof Error && error.message.includes("UNIQUE")) {
      const conflictingPlatformAccount = await database
        .prepare("SELECT id FROM users WHERE platform_identity_hash = ? LIMIT 1")
        .bind(platformIdentityHash)
        .first();
      if (conflictingPlatformAccount) {
        throw new HttpError(409, "PLATFORM_ACCOUNT_EXISTS", "이 ChatGPT 신원은 이미 SAFER 계정과 연결되어 있습니다. 기존 계정으로 로그인해 주세요.");
      }
      const conflictingUsername = await database
        .prepare("SELECT id FROM users WHERE username = ? LIMIT 1")
        .bind(username)
        .first();
      if (conflictingUsername) {
        throw new HttpError(409, "USERNAME_TAKEN", "이미 사용 중인 아이디입니다. 다른 아이디를 입력해 주세요.");
      }
      throw new HttpError(409, "SIGNUP_CONFLICT", "계정 생성 중 중복된 값이 확인되었습니다. 다시 시도해 주세요.");
    }
    throw error;
  }
  const session = await createSession(id, request);
  return json(
    { user: { id, username, publicAlias, bio, role: "user", status: "active", balance: null, walletReady: false } },
    { status: 201, headers: session.headers },
  );
}

async function login(request: Request): Promise<Response> {
  await enforceRateLimit(request, "login", 10, 900);
  const body = await readJson(request, 32_000, ["username", "password", "botChallenge", "website"]);
  const username = validateUsername(body.username);
  await enforceIdentityRateLimit("login-account", await sha256(username), 8, 900);
  await verifyBotProtection(request, body.botChallenge, body.website, "login");
  const password = textField(body.password, "비밀번호", 1, 128, { trim: false });
  const database = await getDatabase();
  const user = await database
    .prepare("SELECT id, username, public_alias, password_hash, bio, role, status, balance, wallet_activated_at, failed_logins, locked_until FROM users WHERE username = ? LIMIT 1")
    .bind(username)
    .first<Record<string, unknown>>();
  const now = Date.now();
  const validPassword = user ? await verifyPassword(password, String(user.password_hash)) : await consumeDummyPasswordWork(password);
  const accountLocked = Boolean(user && Number(user.locked_until ?? 0) > now);
  if (!user || !validPassword || user.status !== "active" || accountLocked) {
    if (user) {
      if (!accountLocked) {
        const failures = Number(user.failed_logins ?? 0) + 1;
        const lockedUntil = failures >= 5 ? now + 15 * 60 * 1000 : null;
        await database.prepare("UPDATE users SET failed_logins = ?, locked_until = ?, updated_at = ? WHERE id = ?").bind(failures >= 5 ? 0 : failures, lockedUntil, now, user.id).run();
      }
      await audit(database, String(user.id), "auth.login_failed", "user", String(user.id));
    }
    await new Promise((resolve) => setTimeout(resolve, 350));
    throw new HttpError(401, "INVALID_CREDENTIALS", "아이디 또는 비밀번호를 확인해 주세요.");
  }
  await database.prepare("UPDATE users SET failed_logins = 0, locked_until = NULL, updated_at = ? WHERE id = ?").bind(now, user.id).run();
  await database.prepare("DELETE FROM sessions WHERE expires_at <= ?").bind(now).run();
  await audit(database, String(user.id), "auth.login", "user", String(user.id));
  const session = await createSession(String(user.id), request);
  return json({ user: publicSessionUser(user) }, { headers: session.headers });
}

async function getPlatformIdentityStatus(request: Request): Promise<Response> {
  if (!request.headers.get("oai-authenticated-user-email")) {
    return json({ authenticated: false, accountLinked: false, provider: "chatgpt-siwc" });
  }
  const identityHash = await requirePlatformIdentity(request);
  const database = await getDatabase();
  const account = await database
    .prepare("SELECT id FROM users WHERE platform_identity_hash = ? LIMIT 1")
    .bind(identityHash)
    .first();
  return json({ authenticated: true, accountLinked: Boolean(account), provider: "chatgpt-siwc" });
}

async function platformLogin(request: Request): Promise<Response> {
  const body = await readJson(request, 1_024, []);
  void body;
  const identityHash = await requirePlatformIdentity(request);
  await enforceRateLimit(request, "platform-login", 20, 900);
  await enforceIdentityRateLimit("platform-login-identity", identityHash, 10, 900);
  const database = await getDatabase();
  const user = await database
    .prepare(`SELECT id, username, public_alias, bio, role, status, balance, wallet_activated_at
              FROM users WHERE platform_identity_hash = ? LIMIT 1`)
    .bind(identityHash)
    .first<Record<string, unknown>>();
  if (!user || user.status !== "active") {
    throw new HttpError(404, "PLATFORM_ACCOUNT_NOT_LINKED", "연결된 SAFER 계정이 없습니다. 먼저 회원가입해 주세요.");
  }
  await audit(database, String(user.id), "auth.platform_login", "user", String(user.id), { provider: "chatgpt-siwc" });
  const session = await createSession(String(user.id), request);
  return json({ user: publicSessionUser(user) }, { headers: session.headers });
}

async function logout(request: Request): Promise<Response> {
  const user = await requireSession(request, true);
  const database = await getDatabase();
  await audit(database, user.id, "auth.logout", "session", user.sessionId);
  return json({ ok: true }, { headers: await destroySession(request, user.sessionId) });
}

async function getCurrentUser(request: Request): Promise<Response> {
  try {
    const user = await requireSession(request);
    return json({ user: publicSessionUser(user) });
  } catch (error) {
    if (error instanceof HttpError && error.status === 401) return json({ user: null });
    throw error;
  }
}

async function updateProfile(request: Request): Promise<Response> {
  const user = await requireSession(request, true);
  await enforceRateLimit(request, `profile:${user.id}`, 10, 3600);
  const body = await readJson(request, 32_000, ["bio", "currentPassword", "newPassword"]);
  const database = await getDatabase();
  const bio = body.bio === undefined ? user.bio : textField(body.bio, "소개글", 0, 300);
  const hasPasswordChange = body.newPassword !== undefined;
  let passwordHash: string | null = null;
  if (hasPasswordChange) {
    const currentPassword = textField(body.currentPassword, "현재 비밀번호", 1, 128, { trim: false });
    const newPassword = validatePassword(body.newPassword);
    const stored = await database.prepare("SELECT password_hash FROM users WHERE id = ?").bind(user.id).first<{ password_hash: string }>();
    if (!stored || !(await verifyPassword(currentPassword, stored.password_hash))) {
      throw new HttpError(401, "INVALID_CURRENT_PASSWORD", "현재 비밀번호가 올바르지 않습니다.");
    }
    passwordHash = await hashPassword(newPassword);
  }
  const now = Date.now();
  let responseHeaders: Headers | undefined;
  if (passwordHash) {
    await database.prepare("UPDATE users SET bio = ?, password_hash = ?, updated_at = ? WHERE id = ?").bind(bio, passwordHash, now, user.id).run();
    await database.prepare("DELETE FROM sessions WHERE user_id = ?").bind(user.id).run();
    responseHeaders = (await createSession(user.id, request)).headers;
    await audit(database, user.id, "profile.password_changed", "user", user.id);
  } else {
    await database.prepare("UPDATE users SET bio = ?, updated_at = ? WHERE id = ?").bind(bio, now, user.id).run();
  }
  await audit(database, user.id, "profile.updated", "user", user.id);
  return json({ user: { ...publicSessionUser(user), bio } }, { headers: responseHeaders });
}

async function listProducts(request: Request, url: URL): Promise<Response> {
  const database = await getDatabase();
  const query = (url.searchParams.get("q") ?? "").normalize("NFC").trim().slice(0, 60);
  const mine = url.searchParams.get("mine") === "1";
  let sql = `SELECT p.id, p.name, p.description, p.price, p.image_key, p.status, p.sold_at, p.created_at,
                    u.id AS seller_id, u.public_alias AS seller_alias
             FROM products p JOIN users u ON u.id = p.seller_id`;
  const bindings: unknown[] = [];
  if (mine) {
    const user = await requireSession(request);
    sql += " WHERE p.seller_id = ?";
    bindings.push(user.id);
  } else {
    sql += " WHERE p.status = 'active' AND p.sold_at IS NULL AND u.status = 'active' AND NOT EXISTS (SELECT 1 FROM product_trades pt WHERE pt.product_id = p.id AND pt.status IN ('requested', 'accepted', 'completed'))";
  }
  if (query) {
    sql += " AND (p.name LIKE ? ESCAPE '\\' OR p.description LIKE ? ESCAPE '\\')";
    const pattern = `%${escapeLike(query)}%`;
    bindings.push(pattern, pattern);
  }
  sql += " ORDER BY p.created_at DESC LIMIT 100";
  const result = await database.prepare(sql).bind(...bindings).all<Record<string, unknown>>();
  return json({ products: result.results.map(productJson) });
}

async function getProduct(_request: Request, idValue: string): Promise<Response> {
  const id = uuidField(idValue);
  const database = await getDatabase();
  const product = await database
    .prepare(
      `SELECT p.id, p.name, p.description, p.price, p.image_key, p.status, p.sold_at, p.created_at,
              u.id AS seller_id, u.public_alias AS seller_alias, u.bio AS seller_bio
       FROM products p JOIN users u ON u.id = p.seller_id
       WHERE p.id = ? AND p.status = 'active' AND u.status = 'active' LIMIT 1`,
    )
    .bind(id)
    .first<Record<string, unknown>>();
  if (!product) throw new HttpError(404, "NOT_FOUND", "상품을 찾을 수 없습니다.");
  return json({ product: productJson(product) });
}

async function createProduct(request: Request): Promise<Response> {
  const user = await requireSession(request, true);
  await enforceRateLimit(request, `product:${user.id}`, 20, 3600);
  const form = await readFormData(request, MAX_PRODUCT_REQUEST_BYTES);
  const allowedFormFields = new Set(["name", "description", "price", "image"]);
  const seenFormFields = new Set<string>();
  for (const key of form.keys()) {
    if (!allowedFormFields.has(key) || seenFormFields.has(key)) {
      throw new HttpError(400, "UNKNOWN_FIELD", "허용되지 않거나 중복된 요청 항목이 포함되어 있습니다.");
    }
    seenFormFields.add(key);
  }
  const name = textField(form.get("name"), "상품명", 2, 80);
  const description = textField(form.get("description"), "상품 설명", 10, 3000);
  const price = integerField(form.get("price"), "가격", 1, 1_000_000_000);
  const file = form.get("image");
  if (!(file instanceof File)) throw new HttpError(400, "IMAGE_REQUIRED", "상품 사진을 선택해 주세요.");
  const image = await validateImage(file);
  const extension = image.type === "image/jpeg" ? "jpg" : image.type === "image/png" ? "png" : "webp";
  const key = `${user.id}/${crypto.randomUUID()}.${extension}`;
  const uploads = getEnv().UPLOADS;
  if (!uploads) throw new HttpError(503, "STORAGE_UNAVAILABLE", "이미지 저장소를 사용할 수 없습니다.");
  try {
    await uploads.put(key, image.bytes, { httpMetadata: { contentType: image.type }, customMetadata: { owner: user.id } });
  } catch (error) {
    logSafeOperationalError("product_image_upload_failed", error);
    throw new HttpError(503, "IMAGE_STORAGE_FAILED", "이미지를 저장하지 못했습니다. 잠시 후 다시 시도해 주세요.");
  }
  const database = await getDatabase();
  const id = crypto.randomUUID();
  const now = Date.now();
  try {
    await database
      .prepare("INSERT INTO products (id, seller_id, name, description, price, image_key, image_type, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)")
      .bind(id, user.id, name, description, price, key, image.type, now, now)
      .run();
  } catch (error) {
    try {
      await uploads.delete(key);
    } catch (cleanupError) {
      logSafeOperationalError("product_image_cleanup_failed", cleanupError);
    }
    logSafeOperationalError("product_record_create_failed", error);
    throw new HttpError(503, "PRODUCT_SAVE_FAILED", "상품 정보를 저장하지 못했습니다. 잠시 후 다시 시도해 주세요.");
  }
  try {
    await audit(database, user.id, "product.created", "product", id, { price });
  } catch (error) {
    // The product and image are already committed. Keep the successful user
    // response and record the audit subsystem failure in Worker logs.
    logSafeOperationalError("product_audit_failed", error);
  }
  return json({ product: { id, name, description, price, imageUrl: `/api/images/${key}`, status: "active", seller: { id: user.id, alias: user.publicAlias } } }, { status: 201 });
}

async function updateProduct(request: Request, idValue: string): Promise<Response> {
  const user = await requireSession(request, true);
  const id = uuidField(idValue);
  const body = await readJson(request, 32_000, ["name", "description", "price"]);
  const name = textField(body.name, "상품명", 2, 80);
  const description = textField(body.description, "상품 설명", 10, 3000);
  const price = integerField(body.price, "가격", 1, 1_000_000_000);
  const database = await getDatabase();
  const result = await database
    .prepare("UPDATE products SET name = ?, description = ?, price = ?, updated_at = ? WHERE id = ? AND seller_id = ? AND status = 'active' AND sold_at IS NULL AND NOT EXISTS (SELECT 1 FROM product_trades WHERE product_id = ? AND status IN ('requested', 'accepted'))")
    .bind(name, description, price, Date.now(), id, user.id, id)
    .run();
  if (!result.meta.changes) throw new HttpError(404, "NOT_FOUND", "수정할 상품을 찾을 수 없습니다.");
  await audit(database, user.id, "product.updated", "product", id);
  return json({ ok: true });
}

async function deleteProduct(request: Request, idValue: string): Promise<Response> {
  const user = await requireSession(request, true);
  const id = uuidField(idValue);
  const database = await getDatabase();
  const result = await database
    .prepare("UPDATE products SET status = 'deleted', updated_at = ? WHERE id = ? AND (seller_id = ? OR ? = 'admin') AND status <> 'deleted' AND sold_at IS NULL AND NOT EXISTS (SELECT 1 FROM product_trades WHERE product_id = ? AND status IN ('requested', 'accepted'))")
    .bind(Date.now(), id, user.id, user.role, id)
    .run();
  if (!result.meta.changes) throw new HttpError(404, "NOT_FOUND", "삭제할 상품을 찾을 수 없습니다.");
  await audit(database, user.id, "product.deleted", "product", id);
  return json({ ok: true });
}

async function getImage(keyValue: string): Promise<Response> {
  let key = "";
  try {
    key = decodeURIComponent(keyValue);
  } catch {
    throw new HttpError(404, "NOT_FOUND", "이미지를 찾을 수 없습니다.");
  }
  if (!/^[0-9a-f-]{36}\/[0-9a-f-]{36}\.(?:jpg|png|webp)$/u.test(key)) throw new HttpError(404, "NOT_FOUND", "이미지를 찾을 수 없습니다.");
  const object = await getEnv().UPLOADS?.get(key);
  if (!object) throw new HttpError(404, "NOT_FOUND", "이미지를 찾을 수 없습니다.");
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("cache-control", "public, max-age=31536000, immutable");
  headers.set("content-security-policy", "default-src 'none'; sandbox");
  headers.set("x-content-type-options", "nosniff");
  headers.set("cross-origin-resource-policy", "same-origin");
  return new Response(object.body, { headers });
}

async function listUsers(request: Request, url: URL): Promise<Response> {
  const user = await requireSession(request);
  const database = await getDatabase();
  const query = (url.searchParams.get("q") ?? "").normalize("NFC").trim().slice(0, 40);
  const pattern = `%${escapeLike(query)}%`;
  const result = await database
    .prepare("SELECT id, public_alias AS alias, bio FROM users WHERE status = 'active' AND id <> ? AND public_alias LIKE ? ESCAPE '\\' ORDER BY public_alias LIMIT 30")
    .bind(user.id, pattern)
    .all<Record<string, unknown>>();
  return json({ users: result.results });
}

async function getUserProfile(idValue: string): Promise<Response> {
  const id = uuidField(idValue);
  const database = await getDatabase();
  const profile = await database.prepare("SELECT id, public_alias AS alias, bio, created_at FROM users WHERE id = ? AND status = 'active' LIMIT 1").bind(id).first<Record<string, unknown>>();
  if (!profile) throw new HttpError(404, "NOT_FOUND", "사용자를 찾을 수 없습니다.");
  return json({ user: profile });
}

async function createReport(request: Request): Promise<Response> {
  const user = await requireSession(request, true);
  await enforceRateLimit(request, `report:${user.id}`, 10, 86400);
  const body = await readJson(request, 32_000, ["targetType", "targetId", "reason"]);
  const targetType = body.targetType === "user" || body.targetType === "product" ? body.targetType : null;
  if (!targetType) throw new HttpError(400, "INVALID_INPUT", "신고 대상을 확인해 주세요.");
  const targetId = uuidField(body.targetId);
  const reason = textField(body.reason, "신고 사유", 10, 500);
  const database = await getDatabase();
  if (targetType === "user") {
    if (targetId === user.id) throw new HttpError(400, "SELF_REPORT", "본인은 신고할 수 없습니다.");
    const target = await database.prepare("SELECT id, role, status FROM users WHERE id = ?").bind(targetId).first<Record<string, unknown>>();
    if (!target || target.role === "admin") throw new HttpError(404, "NOT_FOUND", "신고 대상을 찾을 수 없습니다.");
  } else {
    const target = await database.prepare("SELECT id, seller_id, status, sold_at FROM products WHERE id = ?").bind(targetId).first<Record<string, unknown>>();
    if (!target || target.status !== "active" || target.sold_at !== null) throw new HttpError(404, "NOT_FOUND", "신고 대상을 찾을 수 없습니다.");
    if (target.seller_id === user.id) throw new HttpError(400, "SELF_REPORT", "본인 상품은 신고할 수 없습니다.");
  }
  try {
    await database
      .prepare("INSERT INTO reports (id, reporter_id, target_type, target_id, reason, status, created_at) VALUES (?, ?, ?, ?, ?, 'open', ?)")
      .bind(crypto.randomUUID(), user.id, targetType, targetId, reason, Date.now())
      .run();
  } catch (error) {
    if (error instanceof Error && error.message.includes("UNIQUE")) throw new HttpError(409, "ALREADY_REPORTED", "이미 신고한 대상입니다.");
    throw error;
  }
  const count = await database.prepare("SELECT COUNT(*) AS count FROM reports WHERE target_type = ? AND target_id = ? AND status = 'open'").bind(targetType, targetId).first<{ count: number }>();
  await audit(database, user.id, "report.created", targetType, targetId, { openReports: count?.count ?? 0, threshold: REPORT_THRESHOLD });
  return json({ ok: true, reportCount: count?.count ?? 0 }, { status: 201 });
}

async function listGroupMessages(request: Request, url: URL): Promise<Response> {
  await requireSession(request);
  const after = Math.max(0, Number(url.searchParams.get("after") ?? 0) || 0);
  const database = await getDatabase();
  const result = await database
    .prepare(
      `SELECT m.id, m.body, m.created_at, u.id AS sender_id, u.public_alias AS sender_alias
       FROM messages m JOIN users u ON u.id = m.sender_id
       WHERE m.recipient_id IS NULL AND m.created_at > ? AND u.status = 'active'
       ORDER BY m.created_at ASC LIMIT 100`,
    )
    .bind(after)
    .all<Record<string, unknown>>();
  return json({ messages: result.results });
}

async function sendGroupMessage(request: Request): Promise<Response> {
  const user = await requireSession(request, true);
  await enforceRateLimit(request, `message:${user.id}`, 30, 60);
  const body = await readJson(request, 8_000, ["message"]);
  const message = textField(body.message, "메시지", 1, 500);
  const database = await getDatabase();
  const id = crypto.randomUUID();
  const now = Date.now();
  await database.prepare("INSERT INTO messages (id, sender_id, recipient_id, body, created_at) VALUES (?, ?, NULL, ?, ?)").bind(id, user.id, message, now).run();
  return json({ message: { id, body: message, created_at: now, sender_id: user.id, sender_alias: user.publicAlias } }, { status: 201 });
}

async function listDirectMessages(request: Request, url: URL): Promise<Response> {
  const user = await requireSession(request);
  const otherId = uuidField(url.searchParams.get("userId"));
  const database = await getDatabase();
  const other = await database.prepare("SELECT id, public_alias AS alias FROM users WHERE id = ? AND status = 'active'").bind(otherId).first<Record<string, unknown>>();
  if (!other) throw new HttpError(404, "NOT_FOUND", "사용자를 찾을 수 없습니다.");
  const result = await database
    .prepare(
      `SELECT m.id, m.body, m.created_at, u.id AS sender_id, u.public_alias AS sender_alias
       FROM messages m JOIN users u ON u.id = m.sender_id
       WHERE (m.sender_id = ? AND m.recipient_id = ?) OR (m.sender_id = ? AND m.recipient_id = ?)
       ORDER BY m.created_at ASC LIMIT 200`,
    )
    .bind(user.id, otherId, otherId, user.id)
    .all<Record<string, unknown>>();
  return json({ user: other, messages: result.results });
}

async function sendDirectMessage(request: Request): Promise<Response> {
  const user = await requireSession(request, true);
  await enforceRateLimit(request, `message:${user.id}`, 30, 60);
  const body = await readJson(request, 8_000, ["userId", "message"]);
  const recipientId = uuidField(body.userId);
  if (recipientId === user.id) throw new HttpError(400, "INVALID_RECIPIENT", "본인에게 메시지를 보낼 수 없습니다.");
  const message = textField(body.message, "메시지", 1, 500);
  const database = await getDatabase();
  const recipient = await database.prepare("SELECT id FROM users WHERE id = ? AND status = 'active'").bind(recipientId).first();
  if (!recipient) throw new HttpError(404, "NOT_FOUND", "사용자를 찾을 수 없습니다.");
  const id = crypto.randomUUID();
  const now = Date.now();
  await database.prepare("INSERT INTO messages (id, sender_id, recipient_id, body, created_at) VALUES (?, ?, ?, ?, ?)").bind(id, user.id, recipientId, message, now).run();
  return json({ message: { id, body: message, created_at: now, sender_id: user.id, sender_alias: user.publicAlias } }, { status: 201 });
}

async function getMyWallet(request: Request): Promise<Response> {
  const user = await requireSession(request);
  const database = await getDatabase();
  const wallet = await database
    .prepare("SELECT id, created_at FROM wallets WHERE user_id = ? LIMIT 1")
    .bind(user.id)
    .first<Record<string, unknown>>();
  return json({ wallet: wallet ? { id: wallet.id, createdAt: wallet.created_at } : null });
}

async function getLinkedWeb3Wallet(request: Request): Promise<Response> {
  const user = await requireSession(request);
  const { chainId } = web3Config();
  const database = await getDatabase();
  const wallet = await database
    .prepare("SELECT address, account_kind, verified_at, created_at FROM web3_wallets WHERE user_id = ? AND chain_id = ? LIMIT 1")
    .bind(user.id, chainId)
    .first<{ address: string; account_kind: "eoa" | "contract"; verified_at: number; created_at: number }>();
  return json({
    wallet: wallet ? { address: wallet.address, accountKind: wallet.account_kind, verifiedAt: wallet.verified_at, createdAt: wallet.created_at } : null,
  });
}

async function createWeb3Challenge(request: Request): Promise<Response> {
  const user = await requireSession(request, true);
  await enforceRateLimit(request, `web3-challenge:${user.id}`, 10, 10 * 60);
  const body = await readJson(request, 4_000, ["address"]);
  const { address, addressKey } = normalizeWalletAddress(body.address);
  const config = web3Config();
  const now = Date.now();
  const expiresAt = now + WEB3_CHALLENGE_TTL_MS;
  const nonce = crypto.randomUUID().replaceAll("-", "");
  const challengeToken = randomToken(32);
  const message = createSiweMessage(request, address, nonce, expiresAt);
  const database = await getDatabase();
  await database.prepare("DELETE FROM web3_challenges WHERE expires_at <= ? OR used_at IS NOT NULL").bind(now).run();
  await database
    .prepare("INSERT INTO web3_challenges (id, challenge_hash, user_id, chain_id, address_key, message_hash, expires_at, used_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)")
    .bind(crypto.randomUUID(), await sha256(challengeToken), user.id, config.chainId, addressKey, await sha256Hex(message), expiresAt, now)
    .run();
  await audit(database, user.id, "web3.challenge_created", "web3_wallet", addressKey, { chainId: config.chainId });
  return json({ challengeToken, message, address, chainId: config.chainId, expiresAt }, { status: 201 });
}

async function linkWeb3Wallet(request: Request): Promise<Response> {
  const user = await requireSession(request, true);
  await enforceRateLimit(request, `web3-link:${user.id}`, 8, 10 * 60);
  const body = await readJson(request, 8_000, ["address", "challengeToken", "message", "signature"]);
  const { address, addressKey } = normalizeWalletAddress(body.address);
  const challengeToken = textField(body.challengeToken, "지갑 연결 요청", 43, 43, { pattern: /^[A-Za-z0-9_-]{43}$/u });
  const message = textField(body.message, "서명 메시지", 100, 2_048, { trim: false });
  const signature = textField(body.signature, "지갑 서명", 4, 1_024, { trim: false, pattern: /^0x[0-9a-fA-F]+$/u }) as `0x${string}`;
  const config = web3Config();
  const database = await getDatabase();
  const challenge = await database
    .prepare("SELECT id, user_id, chain_id, address_key, message_hash, expires_at, used_at FROM web3_challenges WHERE challenge_hash = ? LIMIT 1")
    .bind(await sha256(challengeToken))
    .first<Record<string, unknown>>();
  const now = Date.now();
  const validChallenge = challenge
    && challenge.user_id === user.id
    && Number(challenge.chain_id) === config.chainId
    && challenge.address_key === addressKey
    && !challenge.used_at
    && Number(challenge.expires_at) > now
    && await constantTimeTextEqual(String(challenge.message_hash), await sha256Hex(message));
  if (!validChallenge) {
    throw new HttpError(400, "WEB3_CHALLENGE_INVALID", "지갑 연결 요청이 만료되었거나 일치하지 않습니다. 다시 연결해 주세요.");
  }

  const accountKind = await verifyWalletOwnership(address, message, signature);
  const consumed = await database
    .prepare("UPDATE web3_challenges SET used_at = ? WHERE id = ? AND used_at IS NULL AND expires_at > ? RETURNING id")
    .bind(now, challenge.id, now)
    .first<{ id: string }>();
  if (!consumed) throw new HttpError(409, "WEB3_CHALLENGE_REPLAYED", "이미 사용된 지갑 연결 요청입니다. 다시 연결해 주세요.");

  try {
    await database
      .prepare(`INSERT INTO web3_wallets (id, user_id, chain_id, address, address_key, account_kind, verified_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id, chain_id) DO UPDATE SET
                  address = excluded.address, address_key = excluded.address_key,
                  account_kind = excluded.account_kind, verified_at = excluded.verified_at`)
      .bind(crypto.randomUUID(), user.id, config.chainId, address, addressKey, accountKind, now, now)
      .run();
  } catch (error) {
    if (error instanceof Error && error.message.includes("UNIQUE")) {
      throw new HttpError(409, "WEB3_WALLET_ALREADY_LINKED", "이 Ethereum 지갑은 이미 다른 계정에 연결되어 있습니다.");
    }
    throw error;
  }
  const accountActivated = await activateWalletAccountIfReady(database, user.id, config.chainId);
  await audit(database, user.id, "web3.wallet_linked", "web3_wallet", addressKey, { chainId: config.chainId, accountKind, accountActivated });
  if (accountActivated) await audit(database, user.id, "wallet.account_activated", "user", user.id, { policy: "internal-and-ethereum-wallet" });
  return json({ wallet: { address, accountKind, verifiedAt: now, createdAt: now }, accountActivated });
}

async function createWallet(request: Request): Promise<Response> {
  const user = await requireSession(request, true);
  await enforceRateLimit(request, `wallet:${user.id}`, 3, 3600);
  const database = await getDatabase();
  const existing = await database.prepare("SELECT id FROM wallets WHERE user_id = ? LIMIT 1").bind(user.id).first<{ id: string }>();
  if (existing) throw new HttpError(409, "WALLET_EXISTS", "이미 등록된 지갑이 있습니다.");
  const identity = await createWalletIdentity();
  const now = Date.now();
  try {
    await database.prepare("INSERT INTO wallets (id, user_id, created_at) VALUES (?, ?, ?)").bind(identity.id, user.id, now).run();
  } catch (error) {
    if (error instanceof Error && error.message.includes("UNIQUE")) {
      throw new HttpError(409, "WALLET_EXISTS", "이미 등록된 지갑이 있습니다.");
    }
    throw error;
  }
  const { chainId } = web3Config();
  const accountActivated = await activateWalletAccountIfReady(database, user.id, chainId);
  await audit(database, user.id, "wallet.created", "wallet", identity.id, { accountActivated });
  if (accountActivated) await audit(database, user.id, "wallet.account_activated", "user", user.id, { policy: "internal-and-ethereum-wallet" });
  return json({ wallet: { id: identity.id, createdAt: now }, seed: identity.seed, accountActivated }, { status: 201 });
}

async function transferMoney(request: Request): Promise<Response> {
  const user = await requireSession(request, true);
  if (!user.walletReady) throw new HttpError(409, "WALLET_ACCOUNT_INACTIVE", "거래 지갑을 등록하고 Ethereum 지갑 연결을 완료해 주세요.");
  await enforceRateLimit(request, `transfer-attempt:${user.id}`, TRANSFER_ATTEMPT_RATE_LIMIT_MAX, TRANSFER_ATTEMPT_RATE_LIMIT_WINDOW_SECONDS);
  const body = await readJson(request, 8_000, ["walletId", "amount", "memo"]);
  const recipientWalletId = walletIdField(body.walletId);
  const amount = integerField(body.amount, "송금액", 1, 100_000_000);
  const memo = body.memo === undefined ? "" : textField(body.memo, "메모", 0, 100);
  const idempotencyKey = textField(request.headers.get("idempotency-key"), "중복 방지 키", 16, 100, { pattern: /^[A-Za-z0-9_-]+$/ });
  const database = await getDatabase();
  const senderWallet = await database
    .prepare("SELECT w.id, w.user_id FROM wallets w JOIN users u ON u.id = w.user_id WHERE w.user_id = ? AND u.status = 'active' LIMIT 1")
    .bind(user.id)
    .first<{ id: string; user_id: string }>();
  if (!senderWallet) throw new HttpError(409, "WALLET_REQUIRED", "송금하려면 먼저 내 지갑을 등록해야 합니다.");
  const recipientWallet = await database
    .prepare("SELECT w.id, w.user_id FROM wallets w JOIN users u ON u.id = w.user_id WHERE w.id = ? AND u.status = 'active' AND u.wallet_activated_at IS NOT NULL LIMIT 1")
    .bind(recipientWalletId)
    .first<{ id: string; user_id: string }>();
  if (!recipientWallet) throw new HttpError(404, "INVALID_WALLET", "받는 지갑을 확인할 수 없습니다.");
  if (senderWallet.id === recipientWallet.id) throw new HttpError(400, "SELF_TRANSFER", "송금 주소와 입금 주소가 동일합니다. 본인 지갑으로 송금할 수 없습니다.");
  await enforceRateLimit(request, `transfer-submit:${user.id}`, TRANSFER_SUBMIT_RATE_LIMIT_MAX, TRANSFER_SUBMIT_RATE_LIMIT_WINDOW_SECONDS);
  const id = crypto.randomUUID();
  try {
    await database
      .prepare("INSERT INTO transfers (id, sender_id, recipient_id, sender_wallet_id, recipient_wallet_id, amount, memo, idempotency_key, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .bind(id, senderWallet.user_id, recipientWallet.user_id, senderWallet.id, recipientWallet.id, amount, memo, idempotencyKey, Date.now())
      .run();
  } catch (error) {
    if (error instanceof Error && error.message.includes("UNIQUE")) {
      const prior = await database
        .prepare("SELECT id, recipient_wallet_id, amount, memo FROM transfers WHERE sender_wallet_id = ? AND idempotency_key = ?")
        .bind(senderWallet.id, idempotencyKey)
        .first<{ id: string; recipient_wallet_id: string; amount: number; memo: string }>();
      if (!prior || prior.recipient_wallet_id !== recipientWallet.id || prior.amount !== amount || prior.memo !== memo) {
        throw new HttpError(409, "IDEMPOTENCY_CONFLICT", "같은 중복 방지 키로 다른 송금 요청을 처리할 수 없습니다.");
      }
      return json({ ok: true, transferId: prior.id, duplicate: true });
    }
    throw error;
  }
  await audit(database, user.id, "transfer.created", "transfer", id, { senderWalletId: senderWallet.id, recipientWalletId, amount });
  return json({ ok: true, transferId: id, senderWalletId: senderWallet.id, recipientWalletId }, { status: 201 });
}

async function listTransfers(request: Request): Promise<Response> {
  const user = await requireSession(request);
  const database = await getDatabase();
  const result = await database
    .prepare(
      `SELECT t.id, t.amount, t.memo, t.created_at, t.product_trade_id,
              CASE WHEN t.sender_id = ? THEN 'sent' ELSE 'received' END AS direction,
              CASE WHEN t.product_trade_id IS NULL
                   THEN CASE WHEN t.sender_id = ? THEN t.recipient_wallet_id ELSE t.sender_wallet_id END
                   ELSE NULL END AS peer_wallet_id,
              CASE WHEN t.product_trade_id IS NOT NULL
                   THEN CASE WHEN t.sender_id = ? THEN pt.seller_alias ELSE pt.buyer_alias END
                   ELSE NULL END AS peer_alias
       FROM transfers t
       LEFT JOIN product_trades pt ON pt.id = t.product_trade_id
       WHERE t.sender_id = ? OR t.recipient_id = ?
       ORDER BY t.created_at DESC LIMIT 100`,
    )
    .bind(user.id, user.id, user.id, user.id, user.id)
    .all<Record<string, unknown>>();
  return json({ transfers: result.results });
}

async function listProductTrades(request: Request, url: URL): Promise<Response> {
  const user = await requireSession(request);
  const productIdValue = url.searchParams.get("productId");
  const productId = productIdValue ? uuidField(productIdValue) : null;
  const database = await getDatabase();
  let sql = `SELECT pt.id, pt.product_id, pt.buyer_id, pt.seller_id, pt.price, pt.status,
                    pt.transfer_id, pt.created_at, pt.updated_at, p.name AS product_name,
                    p.image_key AS product_image_key, p.sold_at, pt.buyer_alias, pt.seller_alias
             FROM product_trades pt
             JOIN products p ON p.id = pt.product_id
             WHERE (pt.buyer_id = ? OR pt.seller_id = ?)`;
  const bindings: unknown[] = [user.id, user.id];
  if (productId) {
    sql += " AND pt.product_id = ?";
    bindings.push(productId);
  }
  sql += " ORDER BY pt.updated_at DESC LIMIT 100";
  const result = await database.prepare(sql).bind(...bindings).all<Record<string, unknown>>();
  return json({ trades: result.results.map((row) => productTradeJson(row, user.id)) });
}

async function createProductTrade(request: Request): Promise<Response> {
  const buyer = await requireSession(request, true);
  if (!buyer.walletReady) throw new HttpError(409, "WALLET_ACCOUNT_INACTIVE", "상품 거래를 요청하려면 거래 지갑 등록과 Ethereum 지갑 연결을 완료해 주세요.");
  await enforceRateLimit(request, `product-trade:${buyer.id}`, 20, 3600);
  const body = await readJson(request, 8_000, ["productId"]);
  const productId = uuidField(body.productId);
  const database = await getDatabase();
  const product = await database
    .prepare(
      `SELECT p.id, p.name, p.price, p.seller_id, p.status, p.sold_at,
              seller.status AS seller_status, seller.wallet_activated_at AS seller_wallet_activated_at,
              seller_wallet.id AS seller_wallet_id
       FROM products p
       JOIN users seller ON seller.id = p.seller_id
       LEFT JOIN wallets seller_wallet ON seller_wallet.user_id = p.seller_id
       WHERE p.id = ? LIMIT 1`,
    )
    .bind(productId)
    .first<Record<string, unknown>>();
  if (!product || product.status !== "active" || product.sold_at !== null || product.seller_status !== "active") {
    throw new HttpError(404, "NOT_FOUND", "거래할 수 있는 상품을 찾지 못했습니다.");
  }
  if (product.seller_id === buyer.id) throw new HttpError(400, "SELF_TRADE", "본인이 등록한 상품은 구매할 수 없습니다.");
  if (!product.seller_wallet_id || !product.seller_wallet_activated_at) {
    throw new HttpError(409, "SELLER_WALLET_REQUIRED", "판매자가 아직 거래 지갑 등록과 계정 연결을 완료하지 않았습니다.");
  }
  const buyerWallet = await database.prepare("SELECT id FROM wallets WHERE user_id = ? LIMIT 1").bind(buyer.id).first<{ id: string }>();
  if (!buyerWallet) throw new HttpError(409, "WALLET_REQUIRED", "상품 거래를 요청하려면 먼저 내 지갑을 등록해야 합니다.");
  if (Number(product.price) > 100_000_000) throw new HttpError(409, "PRICE_NOT_PAYABLE", "지갑 상품 결제는 1억원 이하 상품만 지원합니다.");
  const id = crypto.randomUUID();
  const now = Date.now();
  const buyerAlias = createTradeAlias();
  let sellerAlias = createTradeAlias();
  while (sellerAlias === buyerAlias) sellerAlias = createTradeAlias();
  try {
    await database
      .prepare("INSERT INTO product_trades (id, product_id, buyer_id, seller_id, buyer_alias, seller_alias, price, status, transfer_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'requested', NULL, ?, ?)")
      .bind(id, productId, buyer.id, product.seller_id, buyerAlias, sellerAlias, product.price, now, now)
      .run();
  } catch (error) {
    if (error instanceof Error && error.message.includes("UNIQUE")) {
      const existing = await database
        .prepare("SELECT buyer_id, status FROM product_trades WHERE product_id = ? AND status IN ('requested', 'accepted', 'completed') LIMIT 1")
        .bind(productId)
        .first<{ buyer_id: string; status: string }>();
      if (existing?.buyer_id === buyer.id) throw new HttpError(409, "TRADE_EXISTS", "이미 이 상품의 거래가 진행 중입니다.");
      throw new HttpError(409, "PRODUCT_RESERVED", "다른 구매자가 이 상품의 거래를 진행 중입니다.");
    }
    throw error;
  }
  await audit(database, buyer.id, "product_trade.requested", "product_trade", id, { productId, price: product.price });
  return json({ tradeId: id, status: "requested" }, { status: 201 });
}

async function updateProductTrade(request: Request, idValue: string): Promise<Response> {
  const user = await requireSession(request, true);
  await enforceRateLimit(request, `product-trade-update:${user.id}`, 30, 3600);
  const id = uuidField(idValue);
  const body = await readJson(request, 8_000, ["action"]);
  const action = body.action === "accept" || body.action === "cancel" ? body.action : null;
  if (!action) throw new HttpError(400, "INVALID_INPUT", "거래 처리 방법을 확인해 주세요.");
  const database = await getDatabase();
  const trade = await database
    .prepare("SELECT id, product_id, buyer_id, seller_id, status FROM product_trades WHERE id = ? LIMIT 1")
    .bind(id)
    .first<Record<string, unknown>>();
  if (!trade || (trade.buyer_id !== user.id && trade.seller_id !== user.id)) throw new HttpError(404, "NOT_FOUND", "상품 거래를 찾지 못했습니다.");
  if (trade.status === "completed" || trade.status === "cancelled") throw new HttpError(409, "TRADE_CLOSED", "이미 종료된 상품 거래입니다.");
  let changes = 0;
  let nextStatus: "accepted" | "cancelled";
  if (action === "accept") {
    if (trade.seller_id !== user.id) throw new HttpError(403, "FORBIDDEN", "판매자만 구매 요청을 승인할 수 있습니다.");
    const result = await database
      .prepare("UPDATE product_trades SET status = 'accepted', updated_at = ? WHERE id = ? AND status = 'requested' AND EXISTS (SELECT 1 FROM products WHERE id = ? AND status = 'active' AND sold_at IS NULL)")
      .bind(Date.now(), id, trade.product_id)
      .run();
    changes = result.meta.changes;
    nextStatus = "accepted";
  } else {
    const result = await database
      .prepare("UPDATE product_trades SET status = 'cancelled', updated_at = ? WHERE id = ? AND status IN ('requested', 'accepted')")
      .bind(Date.now(), id)
      .run();
    changes = result.meta.changes;
    nextStatus = "cancelled";
  }
  if (!changes) throw new HttpError(409, "TRADE_CHANGED", "거래 상태가 변경되었습니다. 새로고침 후 확인해 주세요.");
  await audit(database, user.id, `product_trade.${nextStatus}`, "product_trade", id, { productId: trade.product_id });
  return json({ ok: true, status: nextStatus });
}

async function payProductTrade(request: Request, idValue: string): Promise<Response> {
  const buyer = await requireSession(request, true);
  if (!buyer.walletReady) throw new HttpError(409, "WALLET_ACCOUNT_INACTIVE", "결제하려면 거래 지갑 등록과 Ethereum 지갑 연결을 완료해 주세요.");
  await enforceRateLimit(request, `product-trade-pay-attempt:${buyer.id}`, TRANSFER_ATTEMPT_RATE_LIMIT_MAX, TRANSFER_ATTEMPT_RATE_LIMIT_WINDOW_SECONDS);
  const id = uuidField(idValue);
  const idempotencyKey = textField(request.headers.get("idempotency-key"), "중복 방지 키", 16, 100, { pattern: /^[A-Za-z0-9_-]+$/ });
  const database = await getDatabase();
  const trade = await database
    .prepare(
      `SELECT pt.id, pt.product_id, pt.buyer_id, pt.seller_id, pt.price, pt.status,
              p.name AS product_name, p.status AS product_status, p.sold_at,
              buyer_wallet.id AS buyer_wallet_id, seller_wallet.id AS seller_wallet_id,
              seller.wallet_activated_at AS seller_wallet_activated_at
       FROM product_trades pt
       JOIN products p ON p.id = pt.product_id
       JOIN users seller ON seller.id = pt.seller_id
       LEFT JOIN wallets buyer_wallet ON buyer_wallet.user_id = pt.buyer_id
       LEFT JOIN wallets seller_wallet ON seller_wallet.user_id = pt.seller_id
       WHERE pt.id = ? AND pt.buyer_id = ? LIMIT 1`,
    )
    .bind(id, buyer.id)
    .first<Record<string, unknown>>();
  if (!trade) throw new HttpError(404, "NOT_FOUND", "결제할 상품 거래를 찾지 못했습니다.");
  if (trade.status === "completed") {
    const prior = await database.prepare("SELECT id FROM transfers WHERE product_trade_id = ? LIMIT 1").bind(id).first<{ id: string }>();
    if (prior) return json({ ok: true, transferId: prior.id, duplicate: true });
  }
  if (trade.status !== "accepted" || trade.product_status !== "active" || trade.sold_at !== null) {
    throw new HttpError(409, "TRADE_NOT_PAYABLE", "판매자가 승인한 판매 중 상품만 결제할 수 있습니다.");
  }
  if (!trade.buyer_wallet_id) throw new HttpError(409, "WALLET_REQUIRED", "결제하려면 먼저 내 지갑을 등록해야 합니다.");
  if (!trade.seller_wallet_id || !trade.seller_wallet_activated_at) {
    throw new HttpError(409, "SELLER_WALLET_REQUIRED", "판매자의 활성화된 거래 지갑을 확인할 수 없습니다.");
  }
  await enforceRateLimit(request, `product-trade-pay-submit:${buyer.id}`, TRANSFER_SUBMIT_RATE_LIMIT_MAX, TRANSFER_SUBMIT_RATE_LIMIT_WINDOW_SECONDS);
  const transferId = crypto.randomUUID();
  const now = Date.now();
  const memo = `상품 거래 · ${String(trade.product_name)}`.slice(0, 100);
  try {
    await database.batch([
      database
        .prepare("INSERT INTO transfers (id, sender_id, recipient_id, sender_wallet_id, recipient_wallet_id, product_trade_id, amount, memo, idempotency_key, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(transferId, trade.buyer_id, trade.seller_id, trade.buyer_wallet_id, trade.seller_wallet_id, id, trade.price, memo, idempotencyKey, now),
      database
        .prepare("INSERT INTO audit_logs (id, actor_id, action, target_type, target_id, metadata, created_at) VALUES (?, ?, 'product_trade.completed', 'product_trade', ?, ?, ?)")
        .bind(crypto.randomUUID(), buyer.id, id, JSON.stringify({ productId: trade.product_id, transferId, price: trade.price }), now),
    ]);
  } catch (error) {
    if (error instanceof Error && error.message.includes("UNIQUE")) {
      const prior = await database
        .prepare("SELECT id, product_trade_id, amount FROM transfers WHERE sender_id = ? AND idempotency_key = ? LIMIT 1")
        .bind(buyer.id, idempotencyKey)
        .first<{ id: string; product_trade_id: string | null; amount: number }>();
      if (prior?.product_trade_id === id && prior.amount === Number(trade.price)) return json({ ok: true, transferId: prior.id, duplicate: true });
      throw new HttpError(409, "IDEMPOTENCY_CONFLICT", "같은 중복 방지 키로 다른 결제를 처리할 수 없습니다.");
    }
    if (error instanceof Error && error.message.includes("INVALID_PRODUCT_TRADE")) {
      throw new HttpError(409, "TRADE_CHANGED", "상품 거래 상태가 변경되었습니다. 새로고침 후 확인해 주세요.");
    }
    throw error;
  }
  return json({ ok: true, transferId, status: "completed" }, { status: 201 });
}

async function getAdminSummary(request: Request): Promise<Response> {
  const user = await requireSession(request);
  requireAdmin(user);
  const database = await getDatabase();
  await audit(database, user.id, "admin.identity_mapping_viewed", "admin_dashboard", null);
  const [users, products, reports, transferStats, transfers, messages, logs, securityAlerts] = await Promise.all([
    database.prepare("SELECT id, username, bio, role, status, balance, created_at FROM users ORDER BY created_at DESC LIMIT 200").all(),
    database.prepare("SELECT p.id, p.name, p.price, CASE WHEN p.sold_at IS NOT NULL THEN 'sold' ELSE p.status END AS status, p.created_at, u.username AS seller_username FROM products p JOIN users u ON u.id = p.seller_id ORDER BY p.created_at DESC LIMIT 200").all(),
    database.prepare("SELECT r.id, r.target_type, r.target_id, r.reason, r.status, r.created_at, u.username AS reporter_username FROM reports r JOIN users u ON u.id = r.reporter_id ORDER BY r.created_at DESC LIMIT 200").all(),
    database.prepare("SELECT COUNT(*) AS count, COALESCE(SUM(amount), 0) AS total FROM transfers").first(),
    database.prepare(`SELECT t.id, t.amount, t.memo, t.created_at, t.sender_wallet_id, t.recipient_wallet_id, t.product_trade_id,
                             sender.username AS sender_username, recipient.username AS recipient_username
                      FROM transfers t
                      JOIN users sender ON sender.id = t.sender_id
                      JOIN users recipient ON recipient.id = t.recipient_id
                      ORDER BY t.created_at DESC LIMIT 200`).all(),
    database.prepare(`SELECT m.id, m.body, m.created_at, sender.username AS sender_username,
                             recipient.username AS recipient_username
                      FROM messages m
                      JOIN users sender ON sender.id = m.sender_id
                      LEFT JOIN users recipient ON recipient.id = m.recipient_id
                      ORDER BY m.created_at DESC LIMIT 200`).all(),
    database.prepare("SELECT id, actor_id, action, target_type, target_id, metadata, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 100").all(),
    database
      .prepare("SELECT action, COUNT(*) AS count, MAX(created_at) AS last_seen_at FROM audit_logs WHERE created_at >= ? AND action IN ('rate_limit.exceeded', 'auth.login_failed', 'auth.signup_conflict', 'bot_protection.honeypot', 'bot_protection.invalid_challenge', 'bot_protection.blocked') GROUP BY action ORDER BY count DESC")
      .bind(Date.now() - 24 * 60 * 60 * 1000)
      .all(),
  ]);
  return json({ users: users.results, products: products.results, reports: reports.results, transferStats, transfers: transfers.results, messages: messages.results, logs: logs.results, securityAlerts: securityAlerts.results });
}

async function deleteMessageAsAdmin(request: Request, idValue: string): Promise<Response> {
  const admin = await requireSession(request, true);
  requireAdmin(admin);
  const id = uuidField(idValue);
  const database = await getDatabase();
  const result = await database.prepare("DELETE FROM messages WHERE id = ?").bind(id).run();
  if (!result.meta.changes) throw new HttpError(404, "NOT_FOUND", "삭제할 메시지를 찾을 수 없습니다.");
  await audit(database, admin.id, "admin.message_deleted", "message", id);
  return json({ ok: true });
}

async function administerUser(request: Request, idValue: string): Promise<Response> {
  const admin = await requireSession(request, true);
  requireAdmin(admin);
  const id = uuidField(idValue);
  if (id === admin.id) throw new HttpError(400, "SELF_ADMIN_CHANGE", "본인 계정 상태는 변경할 수 없습니다.");
  const body = await readJson(request, 8_000, ["status"]);
  const status = body.status === "active" || body.status === "dormant" ? body.status : null;
  if (!status) throw new HttpError(400, "INVALID_INPUT", "계정 상태를 확인해 주세요.");
  const database = await getDatabase();
  const result = await database.prepare("UPDATE users SET status = ?, updated_at = ? WHERE id = ? AND role <> 'admin'").bind(status, Date.now(), id).run();
  if (!result.meta.changes) throw new HttpError(404, "NOT_FOUND", "변경할 사용자를 찾을 수 없습니다.");
  if (status === "dormant") await database.prepare("DELETE FROM sessions WHERE user_id = ?").bind(id).run();
  await audit(database, admin.id, "admin.user_status", "user", id, { status });
  return json({ ok: true });
}

async function administerProduct(request: Request, idValue: string): Promise<Response> {
  const admin = await requireSession(request, true);
  requireAdmin(admin);
  const id = uuidField(idValue);
  const body = await readJson(request, 8_000, ["status"]);
  const status = body.status === "active" || body.status === "blocked" || body.status === "deleted" ? body.status : null;
  if (!status) throw new HttpError(400, "INVALID_INPUT", "상품 상태를 확인해 주세요.");
  const database = await getDatabase();
  const result = await database.prepare("UPDATE products SET status = ?, updated_at = ? WHERE id = ?").bind(status, Date.now(), id).run();
  if (!result.meta.changes) throw new HttpError(404, "NOT_FOUND", "변경할 상품을 찾을 수 없습니다.");
  await audit(database, admin.id, "admin.product_status", "product", id, { status });
  return json({ ok: true });
}

async function administerReport(request: Request, idValue: string): Promise<Response> {
  const admin = await requireSession(request, true);
  requireAdmin(admin);
  const id = uuidField(idValue);
  const body = await readJson(request, 8_000, ["status"]);
  const status = body.status === "reviewed" || body.status === "dismissed" ? body.status : null;
  if (!status) throw new HttpError(400, "INVALID_INPUT", "신고 상태를 확인해 주세요.");
  const database = await getDatabase();
  const result = await database.prepare("UPDATE reports SET status = ? WHERE id = ?").bind(status, id).run();
  if (!result.meta.changes) throw new HttpError(404, "NOT_FOUND", "변경할 신고를 찾을 수 없습니다.");
  await audit(database, admin.id, "admin.report_status", "report", id, { status });
  return json({ ok: true });
}

async function bootstrapAdministrator(request: Request): Promise<Response> {
  await enforceRateLimit(request, "admin-bootstrap", 3, 3600);
  const configuredToken = getEnv().ADMIN_BOOTSTRAP_TOKEN;
  const suppliedToken = request.headers.get("x-admin-bootstrap-token") ?? "";
  if (!configuredToken || configuredToken.length < 32 || !(await constantTimeTextEqual(await sha256(suppliedToken), await sha256(configuredToken)))) {
    throw new HttpError(404, "NOT_FOUND", "요청한 항목을 찾을 수 없습니다.");
  }
  const body = await readJson(request, 8_000, ["username"]);
  const username = validateUsername(body.username);
  const database = await getDatabase();
  const existingAdmin = await database.prepare("SELECT id FROM users WHERE role = 'admin' LIMIT 1").first();
  if (existingAdmin) throw new HttpError(409, "ADMIN_EXISTS", "관리자 계정이 이미 설정되어 있습니다.");
  const target = await database.prepare("SELECT id FROM users WHERE username = ? AND status = 'active'").bind(username).first<{ id: string }>();
  if (!target) throw new HttpError(404, "NOT_FOUND", "사용자를 찾을 수 없습니다.");
  await database.prepare("UPDATE users SET role = 'admin', updated_at = ? WHERE id = ?").bind(Date.now(), target.id).run();
  await audit(database, target.id, "admin.bootstrapped", "user", target.id);
  return json({ ok: true });
}

async function validateImage(file: File): Promise<{ bytes: ArrayBuffer; type: string }> {
  if (file.size < 12 || file.size > MAX_IMAGE_BYTES) throw new HttpError(400, "INVALID_IMAGE", "이미지는 5MB 이하의 JPEG, PNG 또는 WebP 파일이어야 합니다.");
  const bytes = await file.arrayBuffer();
  const data = new Uint8Array(bytes);
  const isJpeg = data[0] === 0xff && data[1] === 0xd8 && data[2] === 0xff;
  const isPng = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a].every((byte, index) => data[index] === byte);
  const isWebp = String.fromCharCode(...data.slice(0, 4)) === "RIFF" && String.fromCharCode(...data.slice(8, 12)) === "WEBP";
  const type = isJpeg ? "image/jpeg" : isPng ? "image/png" : isWebp ? "image/webp" : "";
  if (!type || file.type !== type) throw new HttpError(400, "INVALID_IMAGE", "파일 내용과 이미지 형식이 일치하지 않습니다.");
  return { bytes, type };
}

async function consumeDummyPasswordWork(password: string): Promise<boolean> {
  const dummy = "pbkdf2-sha256$100000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  return verifyPassword(password, dummy);
}

function logSafeOperationalError(event: string, error: unknown): void {
  console.error(JSON.stringify({
    event,
    errorType: error instanceof Error ? error.name.slice(0, 80) : typeof error,
  }));
}

function apiPath(url: URL): string {
  if (url.pathname.length > 512 || /%2f|%5c/iu.test(url.pathname)) {
    throw new HttpError(400, "INVALID_PATH", "요청 경로를 확인해 주세요.");
  }
  return url.pathname.replace(/^\/api/u, "").replace(/\/$/u, "") || "/";
}

function allowedApiMethods(path: string): string[] {
  const allowed = new Set<string>(["OPTIONS"]);
  if (GET_API_PATHS.some((pattern) => pattern.test(path))) {
    allowed.add("GET");
    allowed.add("HEAD");
  }
  if (POST_API_PATHS.some((pattern) => pattern.test(path))) allowed.add("POST");
  if (PATCH_API_PATHS.some((pattern) => pattern.test(path))) allowed.add("PATCH");
  if (DELETE_API_PATHS.some((pattern) => pattern.test(path))) allowed.add("DELETE");
  if (allowed.size === 1) return [];
  return API_METHOD_ORDER.filter((method) => allowed.has(method));
}

function uuidField(value: unknown): string {
  return textField(value, "식별자", 36, 36, { pattern: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i });
}

function walletIdField(value: unknown): string {
  return textField(value, "지갑 ID", 47, 47, { pattern: /^wlt_[A-Za-z0-9_-]{43}$/ });
}

function escapeLike(value: string): string {
  return value.replace(/[\\%_]/gu, (character) => `\\${character}`);
}

function productJson(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    price: row.price,
    imageUrl: `/api/images/${row.image_key}`,
    status: row.sold_at !== null && row.sold_at !== undefined ? "sold" : row.status,
    createdAt: row.created_at,
    seller: { id: row.seller_id, alias: row.seller_alias, bio: row.seller_bio },
  };
}

function productTradeJson(row: Record<string, unknown>, userId: string): Record<string, unknown> {
  return {
    id: row.id,
    productId: row.product_id,
    productName: row.product_name,
    productImageUrl: `/api/images/${row.product_image_key}`,
    counterpartyAlias: row.buyer_id === userId ? row.seller_alias : row.buyer_alias,
    price: row.price,
    status: row.status,
    transferId: row.transfer_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    role: row.buyer_id === userId ? "buyer" : "seller",
  };
}

function publicSessionUser(user: Record<string, unknown> | object): Record<string, unknown> {
  const value = user as Record<string, unknown>;
  const walletReady = value.walletReady === true || (value.wallet_activated_at !== null && value.wallet_activated_at !== undefined);
  return {
    id: value.id,
    username: value.username,
    publicAlias: value.publicAlias ?? value.public_alias,
    bio: value.bio,
    role: value.role,
    status: value.status,
    balance: walletReady ? value.balance : null,
    walletReady,
  };
}

function createMarketplaceAlias(): string {
  return `mkt_${randomToken(12)}`;
}

function createTradeAlias(): string {
  return `party_${randomToken(10)}`;
}
