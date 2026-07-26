import { env } from "cloudflare:workers";

export type AppEnv = {
  DB: D1Database;
  UPLOADS: R2Bucket;
  ADMIN_BOOTSTRAP_TOKEN?: string;
  BOT_PROTECTION_MODE?: string;
  BOT_PROTECTION_SECRET?: string;
  PLATFORM_IDENTITY_SECRET?: string;
  PASSKEY_RP_ID?: string;
  PASSKEY_ORIGIN?: string;
  WEB3_CHAIN_ID?: string;
  WEB3_RPC_URL?: string;
  WEB3_RPC_HOST_ALLOWLIST?: string;
  WEB3_ESCROW_ADDRESS?: string;
  WEB3_PAYMENT_TOKEN_ADDRESS?: string;
  WEB3_CONFIRMATIONS?: string;
};

export function getEnv(): AppEnv {
  return env as unknown as AppEnv;
}

let schemaReady: Promise<void> | null = null;

const schemaStatements = [
  `CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    username TEXT NOT NULL UNIQUE,
    public_alias TEXT NOT NULL UNIQUE,
    platform_identity_hash TEXT UNIQUE,
    email TEXT UNIQUE,
    email_verified_at INTEGER,
    password_hash TEXT NOT NULL,
    bio TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'dormant')),
    balance INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0),
    wallet_activated_at INTEGER,
    failed_logins INTEGER NOT NULL DEFAULT 0 CHECK (failed_logins >= 0),
    locked_until INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS pending_signups (
    id TEXT PRIMARY KEY NOT NULL,
    challenge_hash TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    bio TEXT NOT NULL DEFAULT '',
    code_hash TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0 AND attempts <= 5),
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    csrf_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS passkey_credentials (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) BETWEEN 16 AND 1024),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 40),
    public_key TEXT NOT NULL CHECK (length(public_key) BETWEEN 16 AND 8192),
    counter INTEGER NOT NULL DEFAULT 0 CHECK (counter >= 0),
    transports TEXT NOT NULL DEFAULT '[]' CHECK (length(transports) <= 256),
    device_type TEXT NOT NULL CHECK (device_type IN ('singleDevice', 'multiDevice')),
    backed_up INTEGER NOT NULL DEFAULT 0 CHECK (backed_up IN (0, 1)),
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
  )`,
  `CREATE TABLE IF NOT EXISTS passkey_challenges (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 43),
    kind TEXT NOT NULL CHECK (kind IN ('registration', 'authentication')),
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    challenge_hash TEXT NOT NULL UNIQUE CHECK (length(challenge_hash) = 43),
    rp_id TEXT NOT NULL CHECK (length(rp_id) BETWEEN 1 AND 253),
    origin TEXT NOT NULL CHECK (length(origin) BETWEEN 9 AND 512),
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY NOT NULL,
    seller_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    price INTEGER NOT NULL CHECK (price > 0 AND price <= 1000000000),
    image_key TEXT NOT NULL,
    image_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'blocked', 'deleted')),
    sold_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY NOT NULL,
    reporter_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    target_type TEXT NOT NULL CHECK (target_type IN ('user', 'product')),
    target_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'reviewed', 'dismissed')),
    created_at INTEGER NOT NULL,
    UNIQUE (reporter_id, target_type, target_id)
  )`,
  `CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY NOT NULL,
    sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    recipient_id TEXT REFERENCES users(id) ON DELETE RESTRICT,
    body TEXT NOT NULL,
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS wallets (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 47 AND substr(id, 1, 4) = 'wlt_'),
    user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS transfers (
    id TEXT PRIMARY KEY NOT NULL,
    sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    sender_wallet_id TEXT REFERENCES wallets(id) ON DELETE RESTRICT,
    recipient_wallet_id TEXT REFERENCES wallets(id) ON DELETE RESTRICT,
    product_trade_id TEXT,
    amount INTEGER NOT NULL CHECK (amount > 0 AND amount <= 100000000),
    memo TEXT NOT NULL DEFAULT '',
    idempotency_key TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (sender_id, idempotency_key),
    CHECK (sender_id <> recipient_id)
  )`,
  `CREATE TABLE IF NOT EXISTS product_trades (
    id TEXT PRIMARY KEY NOT NULL,
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    buyer_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    seller_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    buyer_alias TEXT NOT NULL UNIQUE,
    seller_alias TEXT NOT NULL UNIQUE,
    price INTEGER NOT NULL CHECK (price > 0 AND price <= 1000000000),
    status TEXT NOT NULL DEFAULT 'requested' CHECK (status IN ('requested', 'accepted', 'completed', 'cancelled')),
    transfer_id TEXT UNIQUE REFERENCES transfers(id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    CHECK (buyer_id <> seller_id)
  )`,
  `CREATE TABLE IF NOT EXISTS web3_wallets (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    chain_id INTEGER NOT NULL CHECK (chain_id IN (1, 11155111)),
    address TEXT NOT NULL CHECK (length(address) = 42),
    address_key TEXT NOT NULL CHECK (length(address_key) = 42 AND address_key = lower(address_key)),
    account_kind TEXT NOT NULL CHECK (account_kind IN ('eoa', 'contract')),
    verified_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (chain_id, address_key),
    UNIQUE (user_id, chain_id)
  )`,
  `CREATE TABLE IF NOT EXISTS web3_challenges (
    id TEXT PRIMARY KEY NOT NULL,
    challenge_hash TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    chain_id INTEGER NOT NULL CHECK (chain_id IN (1, 11155111)),
    address_key TEXT NOT NULL CHECK (length(address_key) = 42 AND address_key = lower(address_key)),
    message_hash TEXT NOT NULL UNIQUE CHECK (length(message_hash) = 64),
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY NOT NULL,
    count INTEGER NOT NULL,
    window_started_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY NOT NULL,
    actor_id TEXT,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL
  )`,
  "CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id)",
  "CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at)",
  "CREATE INDEX IF NOT EXISTS passkey_credentials_user_idx ON passkey_credentials(user_id, created_at)",
  "CREATE INDEX IF NOT EXISTS passkey_challenges_expiry_idx ON passkey_challenges(expires_at)",
  "CREATE INDEX IF NOT EXISTS pending_signups_expiry_idx ON pending_signups(expires_at)",
  "CREATE INDEX IF NOT EXISTS products_seller_idx ON products(seller_id)",
  "CREATE INDEX IF NOT EXISTS products_status_created_idx ON products(status, created_at)",
  "CREATE INDEX IF NOT EXISTS reports_target_idx ON reports(target_type, target_id, status)",
  "CREATE INDEX IF NOT EXISTS messages_group_idx ON messages(recipient_id, created_at)",
  "CREATE INDEX IF NOT EXISTS messages_sender_idx ON messages(sender_id, created_at)",
  "CREATE INDEX IF NOT EXISTS transfers_sender_idx ON transfers(sender_id, created_at)",
  "CREATE INDEX IF NOT EXISTS transfers_recipient_idx ON transfers(recipient_id, created_at)",
  "CREATE INDEX IF NOT EXISTS product_trades_buyer_idx ON product_trades(buyer_id, created_at)",
  "CREATE INDEX IF NOT EXISTS product_trades_seller_idx ON product_trades(seller_id, created_at)",
  "CREATE INDEX IF NOT EXISTS web3_wallets_user_idx ON web3_wallets(user_id, chain_id)",
  "CREATE INDEX IF NOT EXISTS web3_challenges_expiry_idx ON web3_challenges(expires_at)",
  "CREATE UNIQUE INDEX IF NOT EXISTS product_trades_open_product_unique ON product_trades(product_id) WHERE status IN ('requested', 'accepted', 'completed')",
  "CREATE INDEX IF NOT EXISTS audit_logs_created_idx ON audit_logs(created_at)",
  `CREATE TRIGGER IF NOT EXISTS reports_moderate_product_after_insert
   AFTER INSERT ON reports WHEN NEW.target_type = 'product'
   BEGIN
     UPDATE products SET status = 'blocked', updated_at = NEW.created_at
     WHERE id = NEW.target_id AND status = 'active'
       AND (SELECT COUNT(*) FROM reports WHERE target_type = 'product' AND target_id = NEW.target_id AND status = 'open') >= 3;
   END`,
  `CREATE TRIGGER IF NOT EXISTS reports_moderate_user_after_insert
   AFTER INSERT ON reports WHEN NEW.target_type = 'user'
   BEGIN
     UPDATE users SET status = 'dormant', updated_at = NEW.created_at
     WHERE id = NEW.target_id AND role <> 'admin' AND status = 'active'
       AND (SELECT COUNT(*) FROM reports WHERE target_type = 'user' AND target_id = NEW.target_id AND status = 'open') >= 3;
     DELETE FROM sessions WHERE user_id = NEW.target_id
       AND (SELECT status FROM users WHERE id = NEW.target_id) = 'dormant';
  END`,
];

const walletTransferTriggerStatements = [
  "DROP TRIGGER IF EXISTS transfers_validate_before_insert",
  "DROP TRIGGER IF EXISTS transfers_apply_after_insert",
  `CREATE TRIGGER transfers_validate_before_insert
   BEFORE INSERT ON transfers
   BEGIN
     SELECT RAISE(ABORT, 'INVALID_SENDER_WALLET')
     WHERE NEW.sender_wallet_id IS NULL OR NOT EXISTS (
       SELECT 1 FROM wallets w JOIN users u ON u.id = w.user_id
       WHERE w.id = NEW.sender_wallet_id AND u.id = NEW.sender_id
         AND u.status = 'active' AND u.wallet_activated_at IS NOT NULL
     );
     SELECT RAISE(ABORT, 'INVALID_RECIPIENT_WALLET')
     WHERE NEW.recipient_wallet_id IS NULL OR NOT EXISTS (
       SELECT 1 FROM wallets w JOIN users u ON u.id = w.user_id
       WHERE w.id = NEW.recipient_wallet_id AND u.id = NEW.recipient_id
         AND u.status = 'active' AND u.wallet_activated_at IS NOT NULL
     );
     SELECT RAISE(ABORT, 'SELF_TRANSFER')
     WHERE NEW.sender_wallet_id = NEW.recipient_wallet_id;
     SELECT RAISE(ABORT, 'INVALID_PRODUCT_TRADE')
     WHERE NEW.product_trade_id IS NOT NULL AND NOT EXISTS (
       SELECT 1 FROM product_trades pt JOIN products p ON p.id = pt.product_id
       WHERE pt.id = NEW.product_trade_id AND pt.status = 'accepted'
         AND pt.buyer_id = NEW.sender_id AND pt.seller_id = NEW.recipient_id
         AND pt.price = NEW.amount AND p.status = 'active' AND p.sold_at IS NULL
     );
     SELECT RAISE(ABORT, 'INSUFFICIENT_FUNDS')
     WHERE (SELECT u.balance FROM users u JOIN wallets w ON w.user_id = u.id WHERE w.id = NEW.sender_wallet_id) < NEW.amount;
   END`,
  `CREATE TRIGGER transfers_apply_after_insert
   AFTER INSERT ON transfers
   BEGIN
     UPDATE users SET balance = balance - NEW.amount, updated_at = NEW.created_at
       WHERE id = (SELECT user_id FROM wallets WHERE id = NEW.sender_wallet_id);
     UPDATE users SET balance = balance + NEW.amount, updated_at = NEW.created_at
       WHERE id = (SELECT user_id FROM wallets WHERE id = NEW.recipient_wallet_id);
     UPDATE product_trades SET status = 'completed', transfer_id = NEW.id, updated_at = NEW.created_at
       WHERE id = NEW.product_trade_id AND status = 'accepted';
     UPDATE products SET sold_at = NEW.created_at, updated_at = NEW.created_at
       WHERE id = (SELECT product_id FROM product_trades WHERE id = NEW.product_trade_id)
         AND NEW.product_trade_id IS NOT NULL AND sold_at IS NULL;
   END`,
];

const walletActivationGuardStatements = [
  "DROP TRIGGER IF EXISTS users_inactive_balance_before_insert",
  "DROP TRIGGER IF EXISTS users_inactive_balance_before_update",
  `CREATE TRIGGER users_inactive_balance_before_insert
   BEFORE INSERT ON users
   WHEN NEW.wallet_activated_at IS NULL AND NEW.balance <> 0
   BEGIN
     SELECT RAISE(ABORT, 'INACTIVE_WALLET_BALANCE');
   END`,
  `CREATE TRIGGER users_inactive_balance_before_update
   BEFORE UPDATE OF balance, wallet_activated_at ON users
   WHEN NEW.wallet_activated_at IS NULL AND NEW.balance <> 0
   BEGIN
     SELECT RAISE(ABORT, 'INACTIVE_WALLET_BALANCE');
   END`,
];

export async function getDatabase(): Promise<D1Database> {
  const database = getEnv().DB;
  if (!database) throw new Error("DATABASE_UNAVAILABLE");
  schemaReady ??= initializeDatabase(database).catch((error) => {
    schemaReady = null;
    throw error;
  });
  await schemaReady;
  return database;
}

async function initializeDatabase(database: D1Database): Promise<void> {
  await database.batch(schemaStatements.map((statement) => database.prepare(statement)));
  const userColumns = await database.prepare("PRAGMA table_info(users)").all<{ name: string }>();
  const userColumnNames = new Set(userColumns.results.map((column) => column.name));
  const userUpgrades: D1PreparedStatement[] = [];
  if (!userColumnNames.has("email")) userUpgrades.push(database.prepare("ALTER TABLE users ADD COLUMN email TEXT"));
  if (!userColumnNames.has("email_verified_at")) userUpgrades.push(database.prepare("ALTER TABLE users ADD COLUMN email_verified_at INTEGER"));
  if (!userColumnNames.has("public_alias")) userUpgrades.push(database.prepare("ALTER TABLE users ADD COLUMN public_alias TEXT"));
  if (!userColumnNames.has("platform_identity_hash")) userUpgrades.push(database.prepare("ALTER TABLE users ADD COLUMN platform_identity_hash TEXT"));
  if (!userColumnNames.has("wallet_activated_at")) userUpgrades.push(database.prepare("ALTER TABLE users ADD COLUMN wallet_activated_at INTEGER"));
  if (userUpgrades.length) await database.batch(userUpgrades);
  await database.prepare("UPDATE users SET public_alias = 'mkt_' || lower(hex(randomblob(12))) WHERE public_alias IS NULL OR public_alias = ''").run();
  await database.prepare(`UPDATE users SET wallet_activated_at = COALESCE(wallet_activated_at, updated_at)
                          WHERE wallet_activated_at IS NULL
                            AND EXISTS (SELECT 1 FROM wallets w WHERE w.user_id = users.id)
                            AND EXISTS (SELECT 1 FROM web3_wallets e WHERE e.user_id = users.id)`).run();
  await database.prepare(`UPDATE users SET balance = 0
                          WHERE wallet_activated_at IS NULL
                            AND NOT EXISTS (SELECT 1 FROM transfers t WHERE t.sender_id = users.id OR t.recipient_id = users.id)`).run();
  await database.batch(walletActivationGuardStatements.map((statement) => database.prepare(statement)));
  await database.prepare("CREATE UNIQUE INDEX IF NOT EXISTS users_public_alias_unique ON users(public_alias)").run();
  await database.prepare("CREATE UNIQUE INDEX IF NOT EXISTS users_platform_identity_hash_unique ON users(platform_identity_hash) WHERE platform_identity_hash IS NOT NULL").run();
  await database.prepare("CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users(email) WHERE email IS NOT NULL").run();
  const columns = await database.prepare("PRAGMA table_info(transfers)").all<{ name: string }>();
  const columnNames = new Set(columns.results.map((column) => column.name));
  const upgrades: D1PreparedStatement[] = [];
  if (!columnNames.has("sender_wallet_id")) {
    upgrades.push(database.prepare("ALTER TABLE transfers ADD COLUMN sender_wallet_id TEXT REFERENCES wallets(id)"));
  }
  if (!columnNames.has("recipient_wallet_id")) {
    upgrades.push(database.prepare("ALTER TABLE transfers ADD COLUMN recipient_wallet_id TEXT REFERENCES wallets(id)"));
  }
  if (!columnNames.has("product_trade_id")) {
    upgrades.push(database.prepare("ALTER TABLE transfers ADD COLUMN product_trade_id TEXT"));
  }
  const productColumns = await database.prepare("PRAGMA table_info(products)").all<{ name: string }>();
  if (!productColumns.results.some((column) => column.name === "sold_at")) {
    upgrades.push(database.prepare("ALTER TABLE products ADD COLUMN sold_at INTEGER"));
  }
  const tradeColumns = await database.prepare("PRAGMA table_info(product_trades)").all<{ name: string }>();
  const tradeColumnNames = new Set(tradeColumns.results.map((column) => column.name));
  if (!tradeColumnNames.has("buyer_alias")) upgrades.push(database.prepare("ALTER TABLE product_trades ADD COLUMN buyer_alias TEXT"));
  if (!tradeColumnNames.has("seller_alias")) upgrades.push(database.prepare("ALTER TABLE product_trades ADD COLUMN seller_alias TEXT"));
  if (upgrades.length) await database.batch(upgrades);
  await database.prepare("UPDATE product_trades SET buyer_alias = 'party_' || lower(hex(randomblob(10))) WHERE buyer_alias IS NULL OR buyer_alias = ''").run();
  await database.prepare("UPDATE product_trades SET seller_alias = 'party_' || lower(hex(randomblob(10))) WHERE seller_alias IS NULL OR seller_alias = ''").run();
  await database.batch([
    database.prepare("CREATE INDEX IF NOT EXISTS transfers_sender_wallet_idx ON transfers(sender_wallet_id, created_at)"),
    database.prepare("CREATE INDEX IF NOT EXISTS transfers_recipient_wallet_idx ON transfers(recipient_wallet_id, created_at)"),
    database.prepare("CREATE UNIQUE INDEX IF NOT EXISTS transfers_product_trade_unique ON transfers(product_trade_id) WHERE product_trade_id IS NOT NULL"),
    database.prepare("CREATE UNIQUE INDEX IF NOT EXISTS product_trades_buyer_alias_unique ON product_trades(buyer_alias)"),
    database.prepare("CREATE UNIQUE INDEX IF NOT EXISTS product_trades_seller_alias_unique ON product_trades(seller_alias)"),
  ]);
  const trigger = await database
    .prepare("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'transfers_validate_before_insert'")
    .first<{ sql: string }>();
  if (!trigger?.sql.includes("product_trade_id") || !trigger.sql.includes("wallet_activated_at")) {
    await database.batch(walletTransferTriggerStatements.map((statement) => database.prepare(statement)));
  }
}

export async function activateWalletAccountIfReady(
  database: D1Database,
  userId: string,
  chainId: number,
): Promise<boolean> {
  const now = Date.now();
  const activated = await database
    .prepare(`UPDATE users
              SET wallet_activated_at = ?, updated_at = ?
              WHERE id = ? AND wallet_activated_at IS NULL
                AND balance = 0
                AND EXISTS (SELECT 1 FROM wallets w WHERE w.user_id = users.id)
                AND EXISTS (SELECT 1 FROM web3_wallets e WHERE e.user_id = users.id AND e.chain_id = ?)
              RETURNING id`)
    .bind(now, now, userId, chainId)
    .first<{ id: string }>();
  return Boolean(activated);
}

export async function audit(
  database: D1Database,
  actorId: string | null,
  action: string,
  targetType: string,
  targetId: string | null,
  metadata: Record<string, unknown> = {},
): Promise<void> {
  const safeMetadata = JSON.stringify(redactAuditMetadata(metadata)).slice(0, 2000);
  await database
    .prepare(
      "INSERT INTO audit_logs (id, actor_id, action, target_type, target_id, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(crypto.randomUUID(), actorId, action, targetType, targetId, safeMetadata, Date.now())
    .run();
}

function redactAuditMetadata(value: unknown, depth = 0): unknown {
  if (depth > 3) return "[DEPTH_LIMIT]";
  if (value === null || typeof value === "boolean" || typeof value === "number") return value;
  if (typeof value === "string") return value.slice(0, 256);
  if (Array.isArray(value)) return value.slice(0, 20).map((item) => redactAuditMetadata(item, depth + 1));
  if (typeof value !== "object") return String(value).slice(0, 256);
  const result: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>).slice(0, 40)) {
    result[key] = /password|token|secret|seed|code|authorization|cookie/i.test(key)
      ? "[REDACTED]"
      : redactAuditMetadata(item, depth + 1);
  }
  return result;
}
