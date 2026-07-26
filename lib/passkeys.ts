import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type RegistrationResponseJSON,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { audit, getDatabase, getEnv } from "./db";
import {
  HttpError,
  bytesToBase64Url,
  base64UrlToBytes,
  constantTimeTextEqual,
  createSession,
  enforceIdentityRateLimit,
  enforceRateLimit,
  json,
  randomToken,
  readJson,
  requirePlatformIdentity,
  requireSession,
  sha256,
  textField,
} from "./security";

const PASSKEY_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const MAX_PASSKEYS_PER_USER = 5;
const ALLOWED_TRANSPORTS = new Set<AuthenticatorTransportFuture>([
  "ble",
  "cable",
  "hybrid",
  "internal",
  "nfc",
  "smart-card",
  "usb",
]);

type ChallengeRow = {
  user_id: string | null;
  challenge_hash: string;
  rp_id: string;
  origin: string;
  expires_at: number;
};

export async function getPasskeys(request: Request): Promise<Response> {
  const user = await requireSession(request);
  const database = await getDatabase();
  const credentials = await database
    .prepare(`SELECT id, name, device_type, backed_up, created_at, last_used_at
              FROM passkey_credentials WHERE user_id = ? ORDER BY created_at ASC`)
    .bind(user.id)
    .all<Record<string, unknown>>();
  return json({
    passkeys: credentials.results.map((credential) => ({
      id: credential.id,
      name: credential.name,
      deviceType: credential.device_type,
      backedUp: credential.backed_up === 1,
      createdAt: credential.created_at,
      lastUsedAt: credential.last_used_at,
    })),
  });
}

export async function createPasskeyRegistrationOptions(request: Request): Promise<Response> {
  const user = await requireSession(request, true);
  await requireMatchingPlatformIdentity(request, user.id);
  await enforceRateLimit(request, `passkey-register:${user.id}`, 10, 3600);
  const { rpID, origin } = passkeyConfig(request);
  const database = await getDatabase();
  const existing = await database
    .prepare("SELECT id, transports FROM passkey_credentials WHERE user_id = ? ORDER BY created_at ASC")
    .bind(user.id)
    .all<{ id: string; transports: string }>();
  if (existing.results.length >= MAX_PASSKEYS_PER_USER) {
    throw new HttpError(409, "PASSKEY_LIMIT_REACHED", "Passkey는 계정당 최대 5개까지 등록할 수 있습니다.");
  }
  const options = await generateRegistrationOptions({
    rpName: "SAFER",
    rpID,
    userID: new TextEncoder().encode(user.id),
    userName: user.username,
    userDisplayName: user.publicAlias,
    attestationType: "none",
    supportedAlgorithmIDs: [-7, -257],
    excludeCredentials: existing.results.map((credential) => ({
      id: credential.id,
      transports: parseTransports(credential.transports),
    })),
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required",
    },
    timeout: 60_000,
  });
  const challengeId = randomToken(24);
  const now = Date.now();
  await database.batch([
    database.prepare("DELETE FROM passkey_challenges WHERE user_id = ? AND kind = 'registration'").bind(user.id),
    database
      .prepare(`INSERT INTO passkey_challenges
                (id, kind, user_id, challenge_hash, rp_id, origin, expires_at, created_at)
                VALUES (?, 'registration', ?, ?, ?, ?, ?, ?)`)
      .bind(await sha256(challengeId), user.id, await sha256(options.challenge), rpID, origin, now + PASSKEY_CHALLENGE_TTL_MS, now),
  ]);
  return json({ challengeId, options });
}

export async function verifyPasskeyRegistration(request: Request): Promise<Response> {
  const user = await requireSession(request, true);
  await requireMatchingPlatformIdentity(request, user.id);
  const body = await readJson(request, 48_000, ["challengeId", "response", "name"]);
  const challengeId = textField(body.challengeId, "Passkey 요청", 20, 128, { pattern: /^[A-Za-z0-9_-]+$/u });
  if (!isRecord(body.response)) throw new HttpError(400, "INVALID_PASSKEY_RESPONSE", "Passkey 등록 응답을 확인할 수 없습니다.");
  const name = body.name === undefined ? "내 Passkey" : textField(body.name, "Passkey 이름", 1, 40);
  const challenge = await consumeChallenge(challengeId, "registration");
  if (challenge.user_id !== user.id) throw new HttpError(403, "PASSKEY_USER_MISMATCH", "Passkey 등록 사용자를 확인할 수 없습니다.");
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: body.response as unknown as RegistrationResponseJSON,
      expectedChallenge: (actual) => challengeMatches(challenge.challenge_hash, actual),
      expectedOrigin: challenge.origin,
      expectedRPID: challenge.rp_id,
      requireUserPresence: true,
      requireUserVerification: true,
      supportedAlgorithmIDs: [-7, -257],
    });
  } catch {
    throw new HttpError(400, "PASSKEY_VERIFICATION_FAILED", "Passkey 등록을 검증하지 못했습니다. 다시 시도해 주세요.");
  }
  if (!verification.verified || !verification.registrationInfo) {
    throw new HttpError(400, "PASSKEY_VERIFICATION_FAILED", "Passkey 등록을 검증하지 못했습니다.");
  }
  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
  const transports = sanitizeTransports(credential.transports);
  const database = await getDatabase();
  const now = Date.now();
  try {
    await database
      .prepare(`INSERT INTO passkey_credentials
                (id, user_id, name, public_key, counter, transports, device_type, backed_up, created_at, last_used_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`)
      .bind(
        credential.id,
        user.id,
        name,
        bytesToBase64Url(credential.publicKey),
        credential.counter,
        JSON.stringify(transports),
        credentialDeviceType,
        credentialBackedUp ? 1 : 0,
        now,
      )
      .run();
  } catch (error) {
    if (error instanceof Error && error.message.includes("UNIQUE")) {
      throw new HttpError(409, "PASSKEY_ALREADY_REGISTERED", "이미 등록된 Passkey입니다.");
    }
    throw error;
  }
  await audit(database, user.id, "auth.passkey_registered", "passkey", credential.id, {
    deviceType: credentialDeviceType,
    backedUp: credentialBackedUp,
  });
  return json({ ok: true, credentialId: credential.id }, { status: 201 });
}

export async function createPasskeyAuthenticationOptions(request: Request): Promise<Response> {
  await enforceRateLimit(request, "passkey-auth-options", 30, 60);
  const { rpID, origin } = passkeyConfig(request);
  const options = await generateAuthenticationOptions({
    rpID,
    userVerification: "required",
    timeout: 60_000,
  });
  const challengeId = randomToken(24);
  const now = Date.now();
  const database = await getDatabase();
  await database
    .prepare(`INSERT INTO passkey_challenges
              (id, kind, user_id, challenge_hash, rp_id, origin, expires_at, created_at)
              VALUES (?, 'authentication', NULL, ?, ?, ?, ?, ?)`)
    .bind(await sha256(challengeId), await sha256(options.challenge), rpID, origin, now + PASSKEY_CHALLENGE_TTL_MS, now)
    .run();
  await database.prepare("DELETE FROM passkey_challenges WHERE expires_at <= ?").bind(now).run();
  return json({ challengeId, options });
}

export async function verifyPasskeyAuthentication(request: Request): Promise<Response> {
  const body = await readJson(request, 48_000, ["challengeId", "response"]);
  const challengeId = textField(body.challengeId, "Passkey 요청", 20, 128, { pattern: /^[A-Za-z0-9_-]+$/u });
  if (!isRecord(body.response)) throw new HttpError(400, "INVALID_PASSKEY_RESPONSE", "Passkey 로그인 응답을 확인할 수 없습니다.");
  const response = body.response as unknown as AuthenticationResponseJSON;
  const credentialId = textField(response.id, "Passkey 식별자", 16, 1_024, { pattern: /^[A-Za-z0-9_-]+$/u });
  await enforceIdentityRateLimit("passkey-credential", await sha256(credentialId), 10, 900);
  const challenge = await consumeChallenge(challengeId, "authentication");
  const database = await getDatabase();
  const credential = await database
    .prepare(`SELECT p.id, p.user_id, p.name, p.public_key, p.counter, p.transports, p.device_type,
                     p.backed_up, p.created_at, p.last_used_at, u.username, u.public_alias, u.bio,
                     u.role, u.status, u.balance, u.wallet_activated_at
              FROM passkey_credentials p JOIN users u ON u.id = p.user_id
              WHERE p.id = ? LIMIT 1`)
    .bind(credentialId)
    .first<Record<string, unknown>>();
  if (!credential || credential.status !== "active") {
    throw new HttpError(401, "PASSKEY_AUTHENTICATION_FAILED", "Passkey 로그인을 확인하지 못했습니다.");
  }
  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: (actual) => challengeMatches(challenge.challenge_hash, actual),
      expectedOrigin: challenge.origin,
      expectedRPID: challenge.rp_id,
      credential: {
        id: credentialId,
        publicKey: new Uint8Array(base64UrlToBytes(String(credential.public_key))),
        counter: Number(credential.counter),
        transports: parseTransports(String(credential.transports)),
      },
      requireUserVerification: true,
    });
  } catch {
    throw new HttpError(401, "PASSKEY_AUTHENTICATION_FAILED", "Passkey 로그인을 확인하지 못했습니다.");
  }
  if (!verification.verified || !verification.authenticationInfo.userVerified) {
    throw new HttpError(401, "PASSKEY_AUTHENTICATION_FAILED", "Passkey 로그인을 확인하지 못했습니다.");
  }
  const now = Date.now();
  await database
    .prepare("UPDATE passkey_credentials SET counter = ?, backed_up = ?, device_type = ?, last_used_at = ? WHERE id = ?")
    .bind(
      verification.authenticationInfo.newCounter,
      verification.authenticationInfo.credentialBackedUp ? 1 : 0,
      verification.authenticationInfo.credentialDeviceType,
      now,
      credentialId,
    )
    .run();
  await audit(database, String(credential.user_id), "auth.passkey_login", "passkey", credentialId);
  const session = await createSession(String(credential.user_id), request);
  return json(
    {
      user: {
        id: credential.user_id,
        username: credential.username,
        publicAlias: credential.public_alias,
        bio: credential.bio,
        role: credential.role,
        status: credential.status,
        balance: credential.wallet_activated_at === null ? null : credential.balance,
        walletReady: credential.wallet_activated_at !== null,
      },
    },
    { headers: session.headers },
  );
}

export async function deletePasskey(request: Request, credentialIdValue: string): Promise<Response> {
  const user = await requireSession(request, true);
  await requireMatchingPlatformIdentity(request, user.id);
  const credentialId = textField(credentialIdValue, "Passkey 식별자", 16, 1_024, { pattern: /^[A-Za-z0-9_-]+$/u });
  const database = await getDatabase();
  const result = await database
    .prepare("DELETE FROM passkey_credentials WHERE id = ? AND user_id = ?")
    .bind(credentialId, user.id)
    .run();
  if (!result.meta.changes) throw new HttpError(404, "PASSKEY_NOT_FOUND", "삭제할 Passkey를 찾을 수 없습니다.");
  await audit(database, user.id, "auth.passkey_deleted", "passkey", credentialId);
  return json({ ok: true });
}

async function requireMatchingPlatformIdentity(request: Request, userId: string): Promise<void> {
  const identityHash = await requirePlatformIdentity(request);
  const database = await getDatabase();
  const user = await database
    .prepare("SELECT platform_identity_hash FROM users WHERE id = ? LIMIT 1")
    .bind(userId)
    .first<{ platform_identity_hash: string | null }>();
  if (!user) throw new HttpError(401, "AUTH_REQUIRED", "로그인이 필요합니다.");
  if (!user.platform_identity_hash) {
    try {
      await database.prepare("UPDATE users SET platform_identity_hash = ?, updated_at = ? WHERE id = ? AND platform_identity_hash IS NULL")
        .bind(identityHash, Date.now(), userId)
        .run();
      await audit(database, userId, "auth.platform_identity_linked", "user", userId);
      return;
    } catch (error) {
      if (error instanceof Error && error.message.includes("UNIQUE")) {
        throw new HttpError(409, "PLATFORM_IDENTITY_CONFLICT", "이 ChatGPT 신원은 다른 SAFER 계정에 연결되어 있습니다.");
      }
      throw error;
    }
  }
  if (!(await constantTimeTextEqual(user.platform_identity_hash, identityHash))) {
    throw new HttpError(403, "PLATFORM_IDENTITY_MISMATCH", "현재 ChatGPT 신원이 이 SAFER 계정과 일치하지 않습니다.");
  }
}

async function consumeChallenge(challengeId: string, kind: "registration" | "authentication"): Promise<ChallengeRow> {
  const database = await getDatabase();
  const challenge = await database
    .prepare(`DELETE FROM passkey_challenges WHERE id = ? AND kind = ?
              RETURNING user_id, challenge_hash, rp_id, origin, expires_at`)
    .bind(await sha256(challengeId), kind)
    .first<ChallengeRow>();
  if (!challenge || challenge.expires_at <= Date.now()) {
    throw new HttpError(400, "PASSKEY_CHALLENGE_EXPIRED", "Passkey 요청이 만료되었거나 이미 사용되었습니다.");
  }
  return challenge;
}

async function challengeMatches(expectedHash: string, actualChallenge: string): Promise<boolean> {
  return constantTimeTextEqual(expectedHash, await sha256(actualChallenge));
}

function passkeyConfig(request: Request): { rpID: string; origin: string } {
  const rpID = getEnv().PASSKEY_RP_ID?.trim().toLowerCase() ?? "";
  const configuredOrigin = getEnv().PASSKEY_ORIGIN?.trim() ?? "";
  if (!rpID || !configuredOrigin) {
    throw new HttpError(503, "PASSKEY_UNAVAILABLE", "Passkey 설정을 사용할 수 없습니다. 관리자에게 문의해 주세요.");
  }
  let origin: URL;
  try {
    origin = new URL(configuredOrigin);
  } catch {
    throw new HttpError(503, "PASSKEY_MISCONFIGURED", "Passkey 도메인 설정을 확인할 수 없습니다.");
  }
  if (
    origin.protocol !== "https:" ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash ||
    (origin.hostname !== rpID && !origin.hostname.endsWith(`.${rpID}`)) ||
    new URL(request.url).origin !== origin.origin
  ) {
    throw new HttpError(503, "PASSKEY_MISCONFIGURED", "Passkey 도메인 설정을 확인할 수 없습니다.");
  }
  return { rpID, origin: origin.origin };
}

function sanitizeTransports(values: AuthenticatorTransportFuture[] | undefined): AuthenticatorTransportFuture[] {
  return [...new Set((values ?? []).filter((value) => ALLOWED_TRANSPORTS.has(value)))];
}

function parseTransports(value: string): AuthenticatorTransportFuture[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed)
      ? sanitizeTransports(parsed.filter((item): item is AuthenticatorTransportFuture => typeof item === "string") as AuthenticatorTransportFuture[])
      : [];
  } catch {
    return [];
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
