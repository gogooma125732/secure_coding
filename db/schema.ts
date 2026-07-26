import { sql } from "drizzle-orm";
import {
  check,
  index,
  integer,
  sqliteTable,
  text,
  uniqueIndex,
} from "drizzle-orm/sqlite-core";

export const users = sqliteTable(
  "users",
  {
    id: text("id").primaryKey(),
    username: text("username").notNull(),
    publicAlias: text("public_alias").notNull(),
    platformIdentityHash: text("platform_identity_hash"),
    email: text("email"),
    emailVerifiedAt: integer("email_verified_at"),
    passwordHash: text("password_hash").notNull(),
    bio: text("bio").notNull().default(""),
    role: text("role", { enum: ["user", "admin"] }).notNull().default("user"),
    status: text("status", { enum: ["active", "dormant"] }).notNull().default("active"),
    balance: integer("balance").notNull().default(0),
    walletActivatedAt: integer("wallet_activated_at"),
    failedLogins: integer("failed_logins").notNull().default(0),
    lockedUntil: integer("locked_until"),
    createdAt: integer("created_at").notNull(),
    updatedAt: integer("updated_at").notNull(),
  },
  (table) => [
    uniqueIndex("users_username_unique").on(table.username),
    uniqueIndex("users_public_alias_unique").on(table.publicAlias),
    uniqueIndex("users_platform_identity_hash_unique").on(table.platformIdentityHash),
    uniqueIndex("users_email_unique").on(table.email),
    check("users_balance_nonnegative", sql`${table.balance} >= 0`),
    check("users_failed_logins_nonnegative", sql`${table.failedLogins} >= 0`),
  ],
);

export const pendingSignups = sqliteTable(
  "pending_signups",
  {
    id: text("id").primaryKey(),
    challengeHash: text("challenge_hash").notNull(),
    username: text("username").notNull(),
    email: text("email").notNull(),
    passwordHash: text("password_hash").notNull(),
    bio: text("bio").notNull().default(""),
    codeHash: text("code_hash").notNull(),
    attempts: integer("attempts").notNull().default(0),
    expiresAt: integer("expires_at").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (table) => [
    uniqueIndex("pending_signups_challenge_unique").on(table.challengeHash),
    uniqueIndex("pending_signups_username_unique").on(table.username),
    uniqueIndex("pending_signups_email_unique").on(table.email),
    index("pending_signups_expiry_idx").on(table.expiresAt),
    check("pending_signups_attempts_range", sql`${table.attempts} >= 0 AND ${table.attempts} <= 5`),
  ],
);

export const sessions = sqliteTable(
  "sessions",
  {
    id: text("id").primaryKey(),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull(),
    csrfHash: text("csrf_hash").notNull(),
    expiresAt: integer("expires_at").notNull(),
    lastSeenAt: integer("last_seen_at").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (table) => [
    uniqueIndex("sessions_token_hash_unique").on(table.tokenHash),
    index("sessions_user_idx").on(table.userId),
    index("sessions_expiry_idx").on(table.expiresAt),
  ],
);

export const passkeyCredentials = sqliteTable(
  "passkey_credentials",
  {
    id: text("id").primaryKey(),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    publicKey: text("public_key").notNull(),
    counter: integer("counter").notNull().default(0),
    transports: text("transports").notNull().default("[]"),
    deviceType: text("device_type", { enum: ["singleDevice", "multiDevice"] }).notNull(),
    backedUp: integer("backed_up", { mode: "boolean" }).notNull().default(false),
    createdAt: integer("created_at").notNull(),
    lastUsedAt: integer("last_used_at"),
  },
  (table) => [
    index("passkey_credentials_user_idx").on(table.userId, table.createdAt),
    check("passkey_credentials_id_length", sql`length(${table.id}) BETWEEN 16 AND 1024`),
    check("passkey_credentials_name_length", sql`length(${table.name}) BETWEEN 1 AND 40`),
    check("passkey_credentials_public_key_length", sql`length(${table.publicKey}) BETWEEN 16 AND 8192`),
    check("passkey_credentials_transports_length", sql`length(${table.transports}) <= 256`),
    check("passkey_credentials_counter_nonnegative", sql`${table.counter} >= 0`),
    check("passkey_credentials_device_type", sql`${table.deviceType} IN ('singleDevice', 'multiDevice')`),
    check("passkey_credentials_backed_up", sql`${table.backedUp} IN (0, 1)`),
  ],
);

export const passkeyChallenges = sqliteTable(
  "passkey_challenges",
  {
    id: text("id").primaryKey(),
    kind: text("kind", { enum: ["registration", "authentication"] }).notNull(),
    userId: text("user_id").references(() => users.id, { onDelete: "cascade" }),
    challengeHash: text("challenge_hash").notNull(),
    rpId: text("rp_id").notNull(),
    origin: text("origin").notNull(),
    expiresAt: integer("expires_at").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (table) => [
    uniqueIndex("passkey_challenges_hash_unique").on(table.challengeHash),
    index("passkey_challenges_expiry_idx").on(table.expiresAt),
    check("passkey_challenges_id_length", sql`length(${table.id}) = 43`),
    check("passkey_challenges_hash_length", sql`length(${table.challengeHash}) = 43`),
    check("passkey_challenges_rp_id_length", sql`length(${table.rpId}) BETWEEN 1 AND 253`),
    check("passkey_challenges_origin_length", sql`length(${table.origin}) BETWEEN 9 AND 512`),
    check("passkey_challenges_kind", sql`${table.kind} IN ('registration', 'authentication')`),
  ],
);

export const wallets = sqliteTable(
  "wallets",
  {
    id: text("id").primaryKey(),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "restrict" }),
    createdAt: integer("created_at").notNull(),
  },
  (table) => [
    uniqueIndex("wallets_user_unique").on(table.userId),
    check("wallets_id_format", sql`length(${table.id}) = 47 AND substr(${table.id}, 1, 4) = 'wlt_'`),
  ],
);

export const products = sqliteTable(
  "products",
  {
    id: text("id").primaryKey(),
    sellerId: text("seller_id").notNull().references(() => users.id, { onDelete: "restrict" }),
    name: text("name").notNull(),
    description: text("description").notNull(),
    price: integer("price").notNull(),
    imageKey: text("image_key").notNull(),
    imageType: text("image_type").notNull(),
    status: text("status", { enum: ["active", "blocked", "deleted"] }).notNull().default("active"),
    soldAt: integer("sold_at"),
    createdAt: integer("created_at").notNull(),
    updatedAt: integer("updated_at").notNull(),
  },
  (table) => [
    index("products_seller_idx").on(table.sellerId),
    index("products_status_created_idx").on(table.status, table.createdAt),
    check("products_price_range", sql`${table.price} > 0 AND ${table.price} <= 1000000000`),
  ],
);

export const reports = sqliteTable(
  "reports",
  {
    id: text("id").primaryKey(),
    reporterId: text("reporter_id").notNull().references(() => users.id, { onDelete: "restrict" }),
    targetType: text("target_type", { enum: ["user", "product"] }).notNull(),
    targetId: text("target_id").notNull(),
    reason: text("reason").notNull(),
    status: text("status", { enum: ["open", "reviewed", "dismissed"] }).notNull().default("open"),
    createdAt: integer("created_at").notNull(),
  },
  (table) => [
    uniqueIndex("reports_reporter_target_unique").on(table.reporterId, table.targetType, table.targetId),
    index("reports_target_idx").on(table.targetType, table.targetId, table.status),
  ],
);

export const messages = sqliteTable(
  "messages",
  {
    id: text("id").primaryKey(),
    senderId: text("sender_id").notNull().references(() => users.id, { onDelete: "restrict" }),
    recipientId: text("recipient_id").references(() => users.id, { onDelete: "restrict" }),
    body: text("body").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (table) => [
    index("messages_group_idx").on(table.recipientId, table.createdAt),
    index("messages_sender_idx").on(table.senderId, table.createdAt),
  ],
);

export const transfers = sqliteTable(
  "transfers",
  {
    id: text("id").primaryKey(),
    senderId: text("sender_id").notNull().references(() => users.id, { onDelete: "restrict" }),
    recipientId: text("recipient_id").notNull().references(() => users.id, { onDelete: "restrict" }),
    senderWalletId: text("sender_wallet_id").references(() => wallets.id, { onDelete: "restrict" }),
    recipientWalletId: text("recipient_wallet_id").references(() => wallets.id, { onDelete: "restrict" }),
    productTradeId: text("product_trade_id"),
    amount: integer("amount").notNull(),
    memo: text("memo").notNull().default(""),
    idempotencyKey: text("idempotency_key").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (table) => [
    uniqueIndex("transfers_sender_idempotency_unique").on(table.senderId, table.idempotencyKey),
    index("transfers_sender_idx").on(table.senderId, table.createdAt),
    index("transfers_recipient_idx").on(table.recipientId, table.createdAt),
    index("transfers_sender_wallet_idx").on(table.senderWalletId, table.createdAt),
    index("transfers_recipient_wallet_idx").on(table.recipientWalletId, table.createdAt),
    uniqueIndex("transfers_product_trade_unique").on(table.productTradeId),
    check("transfers_positive_amount", sql`${table.amount} > 0 AND ${table.amount} <= 100000000`),
    check("transfers_different_users", sql`${table.senderId} <> ${table.recipientId}`),
  ],
);

export const productTrades = sqliteTable(
  "product_trades",
  {
    id: text("id").primaryKey(),
    productId: text("product_id").notNull().references(() => products.id, { onDelete: "restrict" }),
    buyerId: text("buyer_id").notNull().references(() => users.id, { onDelete: "restrict" }),
    sellerId: text("seller_id").notNull().references(() => users.id, { onDelete: "restrict" }),
    buyerAlias: text("buyer_alias").notNull(),
    sellerAlias: text("seller_alias").notNull(),
    price: integer("price").notNull(),
    status: text("status", { enum: ["requested", "accepted", "completed", "cancelled"] }).notNull().default("requested"),
    transferId: text("transfer_id").references(() => transfers.id, { onDelete: "restrict" }),
    createdAt: integer("created_at").notNull(),
    updatedAt: integer("updated_at").notNull(),
  },
  (table) => [
    index("product_trades_buyer_idx").on(table.buyerId, table.createdAt),
    index("product_trades_seller_idx").on(table.sellerId, table.createdAt),
    uniqueIndex("product_trades_transfer_unique").on(table.transferId),
    uniqueIndex("product_trades_buyer_alias_unique").on(table.buyerAlias),
    uniqueIndex("product_trades_seller_alias_unique").on(table.sellerAlias),
    check("product_trades_different_users", sql`${table.buyerId} <> ${table.sellerId}`),
    check("product_trades_price_range", sql`${table.price} > 0 AND ${table.price} <= 1000000000`),
  ],
);

export const web3Wallets = sqliteTable(
  "web3_wallets",
  {
    id: text("id").primaryKey(),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "restrict" }),
    chainId: integer("chain_id").notNull(),
    address: text("address").notNull(),
    addressKey: text("address_key").notNull(),
    accountKind: text("account_kind", { enum: ["eoa", "contract"] }).notNull(),
    verifiedAt: integer("verified_at").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (table) => [
    uniqueIndex("web3_wallets_chain_address_unique").on(table.chainId, table.addressKey),
    uniqueIndex("web3_wallets_user_chain_unique").on(table.userId, table.chainId),
    index("web3_wallets_user_idx").on(table.userId, table.chainId),
    check("web3_wallets_chain", sql`${table.chainId} IN (1, 11155111)`),
    check("web3_wallets_address_length", sql`length(${table.address}) = 42`),
    check("web3_wallets_address_key", sql`length(${table.addressKey}) = 42 AND ${table.addressKey} = lower(${table.addressKey})`),
  ],
);

export const web3Challenges = sqliteTable(
  "web3_challenges",
  {
    id: text("id").primaryKey(),
    challengeHash: text("challenge_hash").notNull(),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    chainId: integer("chain_id").notNull(),
    addressKey: text("address_key").notNull(),
    messageHash: text("message_hash").notNull(),
    expiresAt: integer("expires_at").notNull(),
    usedAt: integer("used_at"),
    createdAt: integer("created_at").notNull(),
  },
  (table) => [
    uniqueIndex("web3_challenges_challenge_unique").on(table.challengeHash),
    uniqueIndex("web3_challenges_message_unique").on(table.messageHash),
    index("web3_challenges_expiry_idx").on(table.expiresAt),
    check("web3_challenges_chain", sql`${table.chainId} IN (1, 11155111)`),
    check("web3_challenges_address_key", sql`length(${table.addressKey}) = 42 AND ${table.addressKey} = lower(${table.addressKey})`),
    check("web3_challenges_message_hash", sql`length(${table.messageHash}) = 64`),
  ],
);

export const rateLimits = sqliteTable("rate_limits", {
  key: text("key").primaryKey(),
  count: integer("count").notNull(),
  windowStartedAt: integer("window_started_at").notNull(),
});

export const auditLogs = sqliteTable(
  "audit_logs",
  {
    id: text("id").primaryKey(),
    actorId: text("actor_id"),
    action: text("action").notNull(),
    targetType: text("target_type").notNull(),
    targetId: text("target_id"),
    metadata: text("metadata").notNull().default("{}"),
    createdAt: integer("created_at").notNull(),
  },
  (table) => [index("audit_logs_created_idx").on(table.createdAt)],
);
