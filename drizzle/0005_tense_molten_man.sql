PRAGMA foreign_keys=OFF;--> statement-breakpoint
ALTER TABLE `users` ADD `public_alias` text;--> statement-breakpoint
ALTER TABLE `users` ADD `wallet_activated_at` integer;--> statement-breakpoint
UPDATE `users` SET `public_alias` = 'mkt_' || lower(hex(randomblob(12))) WHERE `public_alias` IS NULL OR `public_alias` = '';--> statement-breakpoint
UPDATE `users` SET `wallet_activated_at` = COALESCE(`wallet_activated_at`, `updated_at`)
WHERE `wallet_activated_at` IS NULL
  AND EXISTS (SELECT 1 FROM `wallets` w WHERE w.`user_id` = `users`.`id`)
  AND EXISTS (SELECT 1 FROM `web3_wallets` e WHERE e.`user_id` = `users`.`id`);--> statement-breakpoint
UPDATE `users` SET `balance` = 0
WHERE `wallet_activated_at` IS NULL
  AND NOT EXISTS (SELECT 1 FROM `transfers` t WHERE t.`sender_id` = `users`.`id` OR t.`recipient_id` = `users`.`id`);--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `users_public_alias_unique` ON `users` (`public_alias`);--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `users_email_unique` ON `users` (`email`);--> statement-breakpoint
CREATE TRIGGER `users_inactive_balance_before_insert`
BEFORE INSERT ON `users`
WHEN NEW.`wallet_activated_at` IS NULL AND NEW.`balance` <> 0
BEGIN
	SELECT RAISE(ABORT, 'INACTIVE_WALLET_BALANCE');
END;--> statement-breakpoint
CREATE TRIGGER `users_inactive_balance_before_update`
BEFORE UPDATE OF `balance`, `wallet_activated_at` ON `users`
WHEN NEW.`wallet_activated_at` IS NULL AND NEW.`balance` <> 0
BEGIN
	SELECT RAISE(ABORT, 'INACTIVE_WALLET_BALANCE');
END;--> statement-breakpoint
DROP TRIGGER IF EXISTS `transfers_validate_before_insert`;--> statement-breakpoint
DROP TRIGGER IF EXISTS `transfers_apply_after_insert`;--> statement-breakpoint
ALTER TABLE `product_trades` ADD `buyer_alias` text;--> statement-breakpoint
ALTER TABLE `product_trades` ADD `seller_alias` text;--> statement-breakpoint
UPDATE `product_trades` SET `buyer_alias` = 'party_' || lower(hex(randomblob(10))) WHERE `buyer_alias` IS NULL OR `buyer_alias` = '';--> statement-breakpoint
UPDATE `product_trades` SET `seller_alias` = 'party_' || lower(hex(randomblob(10))) WHERE `seller_alias` IS NULL OR `seller_alias` = '';--> statement-breakpoint
CREATE TABLE `__new_product_trades` (
	`id` text PRIMARY KEY NOT NULL,
	`product_id` text NOT NULL,
	`buyer_id` text NOT NULL,
	`seller_id` text NOT NULL,
	`buyer_alias` text NOT NULL,
	`seller_alias` text NOT NULL,
	`price` integer NOT NULL,
	`status` text DEFAULT 'requested' NOT NULL CHECK (`status` IN ('requested', 'accepted', 'completed', 'cancelled')),
	`transfer_id` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`product_id`) REFERENCES `products`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`buyer_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`seller_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`transfer_id`) REFERENCES `transfers`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "product_trades_different_users" CHECK("buyer_id" <> "seller_id"),
	CONSTRAINT "product_trades_price_range" CHECK("price" > 0 AND "price" <= 1000000000)
);--> statement-breakpoint
INSERT INTO `__new_product_trades`("id", "product_id", "buyer_id", "seller_id", "buyer_alias", "seller_alias", "price", "status", "transfer_id", "created_at", "updated_at")
SELECT "id", "product_id", "buyer_id", "seller_id", "buyer_alias", "seller_alias", "price", "status", "transfer_id", "created_at", "updated_at" FROM `product_trades`;--> statement-breakpoint
DROP TABLE `product_trades`;--> statement-breakpoint
ALTER TABLE `__new_product_trades` RENAME TO `product_trades`;--> statement-breakpoint
CREATE INDEX `product_trades_buyer_idx` ON `product_trades` (`buyer_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `product_trades_seller_idx` ON `product_trades` (`seller_id`,`created_at`);--> statement-breakpoint
CREATE UNIQUE INDEX `product_trades_transfer_unique` ON `product_trades` (`transfer_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `product_trades_buyer_alias_unique` ON `product_trades` (`buyer_alias`);--> statement-breakpoint
CREATE UNIQUE INDEX `product_trades_seller_alias_unique` ON `product_trades` (`seller_alias`);--> statement-breakpoint
CREATE UNIQUE INDEX `product_trades_open_product_unique` ON `product_trades` (`product_id`) WHERE `status` IN ('requested', 'accepted', 'completed');--> statement-breakpoint
DROP TRIGGER IF EXISTS `transfers_validate_before_insert`;--> statement-breakpoint
DROP TRIGGER IF EXISTS `transfers_apply_after_insert`;--> statement-breakpoint
CREATE TRIGGER `transfers_validate_before_insert`
BEFORE INSERT ON `transfers`
BEGIN
	SELECT RAISE(ABORT, 'INVALID_SENDER_WALLET')
	WHERE NEW.`sender_wallet_id` IS NULL OR NOT EXISTS (
		SELECT 1 FROM `wallets` w JOIN `users` u ON u.`id` = w.`user_id`
		WHERE w.`id` = NEW.`sender_wallet_id` AND u.`id` = NEW.`sender_id`
		  AND u.`status` = 'active' AND u.`wallet_activated_at` IS NOT NULL
	);
	SELECT RAISE(ABORT, 'INVALID_RECIPIENT_WALLET')
	WHERE NEW.`recipient_wallet_id` IS NULL OR NOT EXISTS (
		SELECT 1 FROM `wallets` w JOIN `users` u ON u.`id` = w.`user_id`
		WHERE w.`id` = NEW.`recipient_wallet_id` AND u.`id` = NEW.`recipient_id`
		  AND u.`status` = 'active' AND u.`wallet_activated_at` IS NOT NULL
	);
	SELECT RAISE(ABORT, 'SELF_TRANSFER') WHERE NEW.`sender_wallet_id` = NEW.`recipient_wallet_id`;
	SELECT RAISE(ABORT, 'INVALID_PRODUCT_TRADE')
	WHERE NEW.`product_trade_id` IS NOT NULL AND NOT EXISTS (
		SELECT 1 FROM `product_trades` pt JOIN `products` p ON p.`id` = pt.`product_id`
		WHERE pt.`id` = NEW.`product_trade_id` AND pt.`status` = 'accepted'
		  AND pt.`buyer_id` = NEW.`sender_id` AND pt.`seller_id` = NEW.`recipient_id`
		  AND pt.`price` = NEW.`amount` AND p.`status` = 'active' AND p.`sold_at` IS NULL
	);
	SELECT RAISE(ABORT, 'INSUFFICIENT_FUNDS')
	WHERE (SELECT u.`balance` FROM `users` u JOIN `wallets` w ON w.`user_id` = u.`id` WHERE w.`id` = NEW.`sender_wallet_id`) < NEW.`amount`;
END;--> statement-breakpoint
CREATE TRIGGER `transfers_apply_after_insert`
AFTER INSERT ON `transfers`
BEGIN
	UPDATE `users` SET `balance` = `balance` - NEW.`amount`, `updated_at` = NEW.`created_at`
	WHERE `id` = (SELECT `user_id` FROM `wallets` WHERE `id` = NEW.`sender_wallet_id`);
	UPDATE `users` SET `balance` = `balance` + NEW.`amount`, `updated_at` = NEW.`created_at`
	WHERE `id` = (SELECT `user_id` FROM `wallets` WHERE `id` = NEW.`recipient_wallet_id`);
	UPDATE `product_trades` SET `status` = 'completed', `transfer_id` = NEW.`id`, `updated_at` = NEW.`created_at`
	WHERE `id` = NEW.`product_trade_id` AND `status` = 'accepted';
	UPDATE `products` SET `sold_at` = NEW.`created_at`, `updated_at` = NEW.`created_at`
	WHERE `id` = (SELECT `product_id` FROM `product_trades` WHERE `id` = NEW.`product_trade_id`)
	  AND NEW.`product_trade_id` IS NOT NULL AND `sold_at` IS NULL;
END;--> statement-breakpoint
PRAGMA foreign_keys=ON;
