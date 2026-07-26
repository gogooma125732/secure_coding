import { audit, getDatabase, getEnv } from "./db";

const encoder = new TextEncoder();
// Cloudflare Workers currently rejects PBKDF2 iteration counts above 100,000.
// Keep the encoded work factor explicit so hashes remain versioned and verifiable.
const PASSWORD_ITERATIONS = 100_000;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const SESSION_IDLE_TIMEOUT_MS = 30 * 60 * 1000;
const BOT_CHALLENGE_TTL_MS = 15 * 60 * 1000;
const BOT_MIN_WAIT_MS = { login: 1_000, signup: 2_000 } as const;
const RATE_LIMIT_RETENTION_MS = 2 * 24 * 60 * 60 * 1000;

type BotAction = keyof typeof BOT_MIN_WAIT_MS;

export type SessionUser = {
  id: string;
  username: string;
  publicAlias: string;
  bio: string;
  role: "user" | "admin";
  status: "active" | "dormant";
  balance: number;
  walletReady: boolean;
  sessionId: string;
};

export class HttpError extends Error {
  constructor(public status: number, public code: string, message: string, public headers?: HeadersInit) {
    super(message);
  }
}

export function json(data: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  return new Response(JSON.stringify(data), { ...init, headers });
}

function botProtectionMode(): "adaptive" | "off" {
  const configured = getEnv().BOT_PROTECTION_MODE?.trim().toLowerCase() || "adaptive";
  if (configured !== "adaptive" && configured !== "off") {
    throw new HttpError(503, "BOT_PROTECTION_MISCONFIGURED", "자동화 요청 방어 설정을 확인할 수 없습니다.");
  }
  return configured;
}

function botProtectionSecret(): string {
  const secret = getEnv().BOT_PROTECTION_SECRET?.trim() ?? "";
  if (secret.length < 32) {
    throw new HttpError(503, "BOT_PROTECTION_UNAVAILABLE", "자동화 요청 방어를 사용할 수 없습니다. 잠시 후 다시 시도해 주세요.");
  }
  return secret;
}

function clientNetworkIdentifier(request: Request): string {
  return (request.headers.get("cf-connecting-ip") ?? "unknown").trim().slice(0, 64);
}

export async function createBotChallenge(request: Request, actionValue: string | null): Promise<Response> {
  const action = actionValue === "login" || actionValue === "signup" ? actionValue : null;
  if (!action) throw new HttpError(400, "INVALID_BOT_ACTION", "요청 목적을 확인할 수 없습니다.");
  await enforceRateLimit(request, `bot-challenge:${action}`, 60, 60);
  const mode = botProtectionMode();
  if (mode === "off") return json({ mode, challengeToken: "", minWaitMs: 0, expiresInSeconds: 0 });
  const issuedAt = Date.now();
  const expiresAt = issuedAt + BOT_CHALLENGE_TTL_MS;
  const ipHash = await sha256(clientNetworkIdentifier(request));
  const payload = toBase64Url(encoder.encode(["v1", action, issuedAt, expiresAt, ipHash, randomToken(16)].join("|")));
  const signature = await hmacSha256(botProtectionSecret(), `SAFER-BOT-CHALLENGE:${payload}`);
  return json({
    mode,
    challengeToken: `${payload}.${signature}`,
    minWaitMs: BOT_MIN_WAIT_MS[action],
    expiresInSeconds: Math.floor(BOT_CHALLENGE_TTL_MS / 1000),
  });
}

export async function verifyBotProtection(
  request: Request,
  challengeValue: unknown,
  honeypotValue: unknown,
  expectedAction: BotAction,
): Promise<void> {
  if (botProtectionMode() === "off") return;
  const database = await getDatabase();
  const honeypot = honeypotValue === undefined ? "" : textField(honeypotValue, "보안 확인", 0, 200);
  if (honeypot) {
    await audit(database, null, "bot_protection.honeypot", "request", null, { action: expectedAction });
    throw new HttpError(400, "REQUEST_REJECTED", "요청을 확인할 수 없습니다. 페이지를 새로고침한 뒤 다시 시도해 주세요.");
  }
  const challenge = textField(challengeValue, "보안 요청", 80, 1024, { pattern: /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u });
  const [payload, signature] = challenge.split(".");
  const expectedSignature = await hmacSha256(botProtectionSecret(), `SAFER-BOT-CHALLENGE:${payload}`);
  let fields: string[] = [];
  try {
    fields = new TextDecoder().decode(fromBase64Url(payload)).split("|");
  } catch {
    fields = [];
  }
  const [version, action, issuedText, expiresText, ipHash] = fields;
  const issuedAt = Number(issuedText);
  const expiresAt = Number(expiresText);
  const now = Date.now();
  const expectedIpHash = await sha256(clientNetworkIdentifier(request));
  const valid = await constantTimeTextEqual(signature, expectedSignature) &&
    version === "v1" && action === expectedAction && ipHash === expectedIpHash &&
    Number.isSafeInteger(issuedAt) && Number.isSafeInteger(expiresAt) &&
    issuedAt <= now && expiresAt > now && expiresAt - issuedAt === BOT_CHALLENGE_TTL_MS;
  if (!valid) {
    await audit(database, null, "bot_protection.invalid_challenge", "request", null, { action: expectedAction });
    throw new HttpError(400, "REQUEST_REJECTED", "요청을 확인할 수 없습니다. 페이지를 새로고침한 뒤 다시 시도해 주세요.");
  }
  await enforceIdentityRateLimit(`bot-challenge-use:${expectedAction}`, await sha256(signature), 1, Math.ceil(BOT_CHALLENGE_TTL_MS / 1000));
  let riskScore = 0;
  if (now - issuedAt < BOT_MIN_WAIT_MS[expectedAction]) riskScore += 70;
  if (!request.headers.get("user-agent")) riskScore += 30;
  if (!request.headers.get("accept-language")) riskScore += 20;
  if (riskScore >= 50) {
    await audit(database, null, "bot_protection.blocked", "request", null, { action: expectedAction, riskBand: "high" });
    throw new HttpError(429, "REQUEST_REJECTED", "요청이 너무 빠르거나 비정상적입니다. 잠시 후 다시 시도해 주세요.", { "retry-after": "2" });
  }
  if (riskScore > 0) {
    await audit(database, null, "bot_protection.observed", "request", null, { action: expectedAction, riskBand: "medium" });
  }
}

export async function readJson(request: Request, maxBytes = 32_000, allowedFields?: readonly string[]): Promise<Record<string, unknown>> {
  const type = request.headers.get("content-type") ?? "";
  if (!type.toLowerCase().startsWith("application/json")) {
    throw new HttpError(415, "UNSUPPORTED_MEDIA_TYPE", "JSON 형식으로 요청해 주세요.");
  }
  const length = Number(request.headers.get("content-length") ?? 0);
  if (length > maxBytes) throw new HttpError(413, "PAYLOAD_TOO_LARGE", "요청 데이터가 너무 큽니다.");
  const text = await request.text();
  if (encoder.encode(text).byteLength > maxBytes) {
    throw new HttpError(413, "PAYLOAD_TOO_LARGE", "요청 데이터가 너무 큽니다.");
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
    if (!value || Array.isArray(value) || typeof value !== "object") throw new Error();
  } catch {
    throw new HttpError(400, "INVALID_JSON", "올바른 JSON 요청이 아닙니다.");
  }
  const object = value as Record<string, unknown>;
  if (allowedFields) assertAllowedFields(object, allowedFields);
  return object;
}

export async function readFormData(request: Request, maxBytes: number): Promise<FormData> {
  const type = request.headers.get("content-type") ?? "";
  if (!type.toLowerCase().startsWith("multipart/form-data;")) {
    throw new HttpError(415, "UNSUPPORTED_MEDIA_TYPE", "파일 업로드 형식을 확인해 주세요.");
  }
  const declaredLength = Number(request.headers.get("content-length") ?? 0);
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new HttpError(413, "PAYLOAD_TOO_LARGE", "요청 데이터가 너무 큽니다.");
  }
  const reader = request.body?.getReader();
  if (!reader) throw new HttpError(400, "INVALID_BODY", "요청 본문을 확인해 주세요.");
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new HttpError(413, "PAYLOAD_TOO_LARGE", "요청 데이터가 너무 큽니다.");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return await new Response(bytes, { headers: { "content-type": type } }).formData();
  } catch {
    throw new HttpError(400, "INVALID_FORM_DATA", "파일 업로드 요청을 확인해 주세요.");
  }
}

export function assertAllowedFields(value: Record<string, unknown>, allowedFields: readonly string[]): void {
  const allowed = new Set(allowedFields);
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw new HttpError(400, "UNKNOWN_FIELD", "허용되지 않은 요청 항목이 포함되어 있습니다.");
  }
}

export function textField(
  value: unknown,
  name: string,
  min: number,
  max: number,
  options: { trim?: boolean; pattern?: RegExp } = {},
): string {
  if (typeof value !== "string") throw new HttpError(400, "INVALID_INPUT", `${name} 형식이 올바르지 않습니다.`);
  const normalized = value.normalize("NFC");
  const result = options.trim === false ? normalized : normalized.trim();
  const length = [...result].length;
  if (length < min || length > max || (options.pattern && !options.pattern.test(result))) {
    throw new HttpError(400, "INVALID_INPUT", `${name} 값을 확인해 주세요.`);
  }
  return result;
}

export function integerField(value: unknown, name: string, min: number, max: number): number {
  const number = typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(number) || (number as number) < min || (number as number) > max) {
    throw new HttpError(400, "INVALID_INPUT", `${name} 값을 확인해 주세요.`);
  }
  return number as number;
}

export function validateUsername(value: unknown): string {
  return textField(value, "아이디", 3, 24, { pattern: /^[A-Za-z0-9_]+$/ }).toLowerCase();
}

export function validateEmail(value: unknown): string {
  const email = textField(value, "이메일", 3, 254).toLowerCase();
  const separator = email.lastIndexOf("@");
  const local = email.slice(0, separator);
  const domain = email.slice(separator + 1);
  if (
    separator < 1 || local.length > 64 || local.startsWith(".") || local.endsWith(".") || local.includes("..") ||
    !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/u.test(local) ||
    domain.length > 253 || !domain.includes(".") ||
    !domain.split(".").every((label) => /^(?!-)[a-z0-9-]{1,63}(?<!-)$/u.test(label))
  ) {
    throw new HttpError(400, "INVALID_EMAIL", "이메일 주소를 확인해 주세요.");
  }
  return email;
}

export async function requirePlatformIdentity(request: Request): Promise<string> {
  const rawEmail = request.headers.get("oai-authenticated-user-email");
  if (!rawEmail) {
    throw new HttpError(401, "PLATFORM_IDENTITY_REQUIRED", "ChatGPT로 로그인한 뒤 다시 시도해 주세요.");
  }
  const secret = getEnv().PLATFORM_IDENTITY_SECRET?.trim() ?? "";
  if (secret.length < 32) {
    throw new HttpError(503, "PLATFORM_IDENTITY_UNAVAILABLE", "플랫폼 계정 확인을 사용할 수 없습니다. 관리자에게 문의해 주세요.");
  }
  const normalizedEmail = validateEmail(rawEmail);
  return hmacSha256(secret, `SAFER-PLATFORM-IDENTITY-V1:${normalizedEmail}`);
}

export function validatePassword(value: unknown): string {
  const password = textField(value, "비밀번호", 12, 128, { trim: false });
  if (!/[A-Za-z]/.test(password) || !/\d/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    throw new HttpError(400, "WEAK_PASSWORD", "비밀번호에는 영문, 숫자, 특수문자가 모두 필요합니다.");
  }
  return password;
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PASSWORD_ITERATIONS },
    key,
    256,
  );
  return `pbkdf2-sha256$${PASSWORD_ITERATIONS}$${toBase64Url(salt)}$${toBase64Url(new Uint8Array(bits))}`;
}

export async function verifyPassword(password: string, encoded: string): Promise<boolean> {
  const [algorithm, iterationsText, saltText, expectedText] = encoded.split("$");
  if (algorithm !== "pbkdf2-sha256" || !/^\d+$/.test(iterationsText ?? "")) return false;
  const iterations = Number(iterationsText);
  if (iterations !== PASSWORD_ITERATIONS) return false;
  try {
    const salt = fromBase64Url(saltText);
    const expected = fromBase64Url(expectedText);
    const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: salt.buffer as ArrayBuffer, iterations }, key, expected.length * 8);
    return constantTimeEqual(new Uint8Array(bits), expected);
  } catch {
    return false;
  }
}

export async function createSession(userId: string, request: Request): Promise<{ headers: Headers }> {
  const database = await getDatabase();
  const token = randomToken(32);
  const csrf = randomToken(24);
  const now = Date.now();
  await database.batch([
    database.prepare("DELETE FROM sessions WHERE user_id = ? OR expires_at <= ? OR last_seen_at <= ?").bind(userId, now, now - SESSION_IDLE_TIMEOUT_MS),
    database
      .prepare("INSERT INTO sessions (id, user_id, token_hash, csrf_hash, expires_at, last_seen_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .bind(crypto.randomUUID(), userId, await sha256(token), await sha256(csrf), now + SESSION_TTL_MS, now, now),
  ]);
  const headers = new Headers();
  appendCookie(headers, request, "session", token, true, Math.floor(SESSION_TTL_MS / 1000));
  appendCookie(headers, request, "csrf", csrf, false, Math.floor(SESSION_TTL_MS / 1000));
  return { headers };
}

export async function requireSession(request: Request, requireCsrf = false): Promise<SessionUser> {
  if (requireCsrf) {
    validateSameOrigin(request);
  }
  const cookies = parseCookies(request.headers.get("cookie") ?? "");
  const token = cookies.get("__Host-session") ?? cookies.get("session");
  if (!token || token.length > 256) throw new HttpError(401, "AUTH_REQUIRED", "로그인이 필요합니다.");
  const database = await getDatabase();
  const row = await database
    .prepare(
      `SELECT s.id AS session_id, s.csrf_hash, s.expires_at, s.last_seen_at,
              u.id, u.username, u.public_alias, u.bio, u.role, u.status, u.balance, u.wallet_activated_at
       FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = ? LIMIT 1`,
    )
    .bind(await sha256(token))
    .first<Record<string, unknown>>();
  const now = Date.now();
  const expired = !row ||
    Number(row.expires_at) <= now ||
    now - Number(row.last_seen_at ?? 0) > SESSION_IDLE_TIMEOUT_MS;
  if (expired || row?.status !== "active") {
    const headers = await destroySession(request, row?.session_id ? String(row.session_id) : undefined);
    throw new HttpError(
      401,
      expired ? "SESSION_EXPIRED" : "ACCOUNT_INACTIVE",
      expired ? "로그인 세션이 만료되었습니다. 다시 로그인해 주세요." : "사용할 수 없는 계정입니다.",
      headers,
    );
  }
  if (requireCsrf) {
    const csrfCookie = cookies.get("__Host-csrf") ?? cookies.get("csrf") ?? "";
    const csrfHeader = request.headers.get("x-csrf-token") ?? "";
    if (!csrfCookie || csrfCookie !== csrfHeader || !(await constantTimeTextEqual(await sha256(csrfHeader), String(row.csrf_hash)))) {
      throw new HttpError(403, "CSRF_REJECTED", "요청을 확인할 수 없습니다. 새로고침 후 다시 시도해 주세요.");
    }
  }
  if (now - Number(row.last_seen_at ?? 0) > 60_000) {
    await database.prepare("UPDATE sessions SET last_seen_at = ? WHERE id = ?").bind(now, row.session_id).run();
  }
  return {
    id: String(row.id),
    username: String(row.username),
    publicAlias: String(row.public_alias),
    bio: String(row.bio),
    role: row.role === "admin" ? "admin" : "user",
    status: "active",
    balance: Number(row.balance),
    walletReady: row.wallet_activated_at !== null && row.wallet_activated_at !== undefined,
    sessionId: String(row.session_id),
  };
}

export function requireAdmin(user: SessionUser): void {
  if (user.role !== "admin") throw new HttpError(403, "FORBIDDEN", "관리자 권한이 필요합니다.");
}

export async function destroySession(request: Request, sessionId?: string): Promise<Headers> {
  const database = await getDatabase();
  if (sessionId) await database.prepare("DELETE FROM sessions WHERE id = ?").bind(sessionId).run();
  const headers = new Headers();
  appendCookie(headers, request, "session", "", true, 0);
  appendCookie(headers, request, "csrf", "", false, 0);
  return headers;
}

export async function enforceRateLimit(request: Request, action: string, maximum: number, windowSeconds: number): Promise<void> {
  const forwarded = request.headers.get("cf-connecting-ip") ?? request.headers.get("x-forwarded-for")?.split(",")[0] ?? "local";
  await enforceRateLimitKey(action, await sha256(forwarded.trim().slice(0, 64)), maximum, windowSeconds);
}

export async function enforceIdentityRateLimit(action: string, identityHash: string, maximum: number, windowSeconds: number): Promise<void> {
  await enforceRateLimitKey(action, identityHash.slice(0, 128), maximum, windowSeconds);
}

async function enforceRateLimitKey(action: string, identifier: string, maximum: number, windowSeconds: number): Promise<void> {
  const database = await getDatabase();
  const key = `${action}:${identifier}`;
  const now = Date.now();
  const windowMs = windowSeconds * 1000;
  // A rotating set of client identifiers must not grow the D1 table without
  // bound. Cleanup is deliberately probabilistic to keep the hot path cheap.
  if (crypto.getRandomValues(new Uint8Array(1))[0] === 0) {
    await database.prepare("DELETE FROM rate_limits WHERE window_started_at <= ?").bind(now - RATE_LIMIT_RETENTION_MS).run();
  }
  const row = await database
    .prepare(
      `INSERT INTO rate_limits (key, count, window_started_at) VALUES (?, 1, ?)
       ON CONFLICT(key) DO UPDATE SET
         count = CASE WHEN rate_limits.window_started_at <= ? THEN 1 ELSE rate_limits.count + 1 END,
         window_started_at = CASE WHEN rate_limits.window_started_at <= ? THEN excluded.window_started_at ELSE rate_limits.window_started_at END
       RETURNING count, window_started_at`,
    )
    .bind(key, now, now - windowMs, now - windowMs)
    .first<{ count: number; window_started_at: number }>();
  if ((row?.count ?? 0) > maximum) {
    await audit(database, null, "rate_limit.exceeded", "request", null, { action });
    const retryAfterSeconds = Math.max(1, Math.ceil(((row?.window_started_at ?? now) + windowMs - now) / 1000));
    throw new HttpError(
      429,
      "RATE_LIMITED",
      `요청이 너무 많습니다. ${retryAfterSeconds}초 후 다시 시도해 주세요.`,
      { "retry-after": String(retryAfterSeconds) },
    );
  }
}

export function handleError(error: unknown, request?: Request): Response {
  const requestId = request?.headers.get("cf-ray")?.slice(0, 128) || crypto.randomUUID();
  if (error instanceof HttpError) {
    const headers = new Headers(error.headers);
    headers.set("x-request-id", requestId);
    if (error.status >= 500) console.error(JSON.stringify({ event: "request_failed", requestId, code: error.code, status: error.status }));
    return json({ error: { code: error.code, message: error.message, requestId } }, { status: error.status, headers });
  }
  const message = error instanceof Error ? error.message : "UNKNOWN";
  const knownError = (status: number, code: string, safeMessage: string): Response => json(
    { error: { code, message: safeMessage, requestId } },
    { status, headers: { "x-request-id": requestId } },
  );
  if (message.includes("UNIQUE constraint failed")) {
    return knownError(409, "CONFLICT", "이미 처리된 요청이거나 중복된 값입니다.");
  }
  if (message.includes("INSUFFICIENT_FUNDS")) {
    return knownError(409, "INSUFFICIENT_FUNDS", "잔액이 부족합니다.");
  }
  if (message.includes("INVALID_SENDER_WALLET")) {
    return knownError(409, "WALLET_REQUIRED", "송금하려면 먼저 내 지갑을 등록해야 합니다.");
  }
  if (message.includes("INVALID_RECIPIENT_WALLET")) {
    return knownError(404, "INVALID_WALLET", "받는 지갑을 확인할 수 없습니다.");
  }
  if (message.includes("SELF_TRANSFER")) {
    return knownError(400, "SELF_TRANSFER", "송금 주소와 입금 주소가 동일합니다. 본인 지갑으로 송금할 수 없습니다.");
  }
  if (message.includes("INVALID_PRODUCT_TRADE")) {
    return knownError(409, "TRADE_CHANGED", "상품 거래 상태가 변경되었습니다. 새로고침 후 확인해 주세요.");
  }
  console.error(JSON.stringify({
    event: "request_failed",
    requestId,
    code: "INTERNAL_ERROR",
    errorType: error instanceof Error ? error.name.slice(0, 80) : typeof error,
  }));
  return json(
    { error: { code: "INTERNAL_ERROR", message: "요청을 처리하지 못했습니다.", requestId } },
    { status: 500, headers: { "x-request-id": requestId } },
  );
}

export async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return toBase64Url(new Uint8Array(digest));
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function hmacSha256(secret: string, value: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return toBase64Url(new Uint8Array(signature));
}

export async function createWalletIdentity(): Promise<{ id: string; seed: string }> {
  const seed = randomToken(32);
  const digest = await sha256(`SAFER-WALLET-V1:${seed}`);
  return { id: `wlt_${digest}`, seed };
}

export function constantTimeTextEqual(a: string, b: string): Promise<boolean> {
  return Promise.resolve(constantTimeEqual(encoder.encode(a), encoder.encode(b)));
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  let mismatch = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) mismatch |= (a[index] ?? 0) ^ (b[index] ?? 0);
  return mismatch === 0;
}

export function randomToken(bytes: number): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return toBase64Url(bytes);
}

export function base64UrlToBytes(value: string): Uint8Array {
  return fromBase64Url(value);
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function fromBase64Url(value: string): Uint8Array {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(base64);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function parseCookies(header: string): Map<string, string> {
  const values = new Map<string, string>();
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 1) continue;
    try {
      values.set(part.slice(0, separator).trim(), decodeURIComponent(part.slice(separator + 1).trim()));
    } catch {
      // A malformed cookie is untrusted input. Ignore only that segment rather
      // than turning a bad percent escape into a server error.
    }
  }
  return values;
}

function appendCookie(headers: Headers, request: Request, name: string, value: string, httpOnly: boolean, maxAge: number): void {
  const secure = new URL(request.url).protocol === "https:";
  const cookieName = secure ? `__Host-${name}` : name;
  const parts = [`${cookieName}=${encodeURIComponent(value)}`, "Path=/", `Max-Age=${maxAge}`, "SameSite=Strict"];
  if (secure) parts.push("Secure");
  if (httpOnly) parts.push("HttpOnly");
  headers.append("set-cookie", parts.join("; "));
}

export function validateMutationRequest(request: Request): void {
  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite && fetchSite !== "same-origin" && fetchSite !== "none") {
    throw new HttpError(403, "CROSS_ORIGIN_REJECTED", "교차 출처 요청은 허용되지 않습니다.");
  }
  validateSameOrigin(request);
}

function validateSameOrigin(request: Request): void {
  const requestOrigin = new URL(request.url).origin;
  const origin = request.headers.get("origin");
  if (origin) {
    if (origin !== requestOrigin) throw new HttpError(403, "CROSS_ORIGIN_REJECTED", "교차 출처 요청은 허용되지 않습니다.");
    return;
  }
  const referer = request.headers.get("referer");
  if (referer) {
    try {
      if (new URL(referer).origin === requestOrigin) return;
    } catch {
      // Invalid Referer values fail closed below.
    }
    throw new HttpError(403, "CROSS_ORIGIN_REJECTED", "교차 출처 요청은 허용되지 않습니다.");
  }
  // Browser fetches expose Fetch Metadata. If it exists, a mutation without
  // both Origin and Referer is anomalous and must fail closed. Non-browser
  // administrative clients remain possible when they send neither header.
  if (request.headers.has("sec-fetch-site")) {
    throw new HttpError(403, "ORIGIN_REQUIRED", "요청 출처를 확인할 수 없습니다.");
  }
}
