CREATE TABLE `product_trades` (
	`id` text PRIMARY KEY NOT NULL,
	`product_id` text NOT NULL,
	`buyer_id` text NOT NULL,
	`seller_id` text NOT NULL,
	`price` integer NOT NULL,
	`status` text DEFAULT 'requested' NOT NULL CHECK (`status` IN ('requested', 'accepted', 'completed', 'cancelled')),
	`transfer_id` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`product_id`) REFERENCES `products`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`buyer_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`seller_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`transfer_id`) REFERENCES `transfers`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "product_trades_different_users" CHECK("product_trades"."buyer_id" <> "product_trades"."seller_id"),
	CONSTRAINT "product_trades_price_range" CHECK("product_trades"."price" > 0 AND "product_trades"."price" <= 1000000000)
);
--> statement-breakpoint
CREATE INDEX `product_trades_buyer_idx` ON `product_trades` (`buyer_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `product_trades_seller_idx` ON `product_trades` (`seller_id`,`created_at`);--> statement-breakpoint
CREATE UNIQUE INDEX `product_trades_transfer_unique` ON `product_trades` (`transfer_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `product_trades_open_product_unique` ON `product_trades` (`product_id`) WHERE `status` IN ('requested', 'accepted', 'completed');--> statement-breakpoint
ALTER TABLE `products` ADD `sold_at` integer;--> statement-breakpoint
ALTER TABLE `transfers` ADD `product_trade_id` text;--> statement-breakpoint
CREATE UNIQUE INDEX `transfers_product_trade_unique` ON `transfers` (`product_trade_id`);--> statement-breakpoint
DROP TRIGGER IF EXISTS `transfers_validate_before_insert`;--> statement-breakpoint
DROP TRIGGER IF EXISTS `transfers_apply_after_insert`;--> statement-breakpoint
CREATE TRIGGER `transfers_validate_before_insert`
BEFORE INSERT ON `transfers`
BEGIN
	SELECT RAISE(ABORT, 'INVALID_SENDER_WALLET')
	WHERE NEW.`sender_wallet_id` IS NULL OR NOT EXISTS (
		SELECT 1 FROM `wallets` w JOIN `users` u ON u.`id` = w.`user_id`
		WHERE w.`id` = NEW.`sender_wallet_id` AND u.`id` = NEW.`sender_id` AND u.`status` = 'active'
	);
	SELECT RAISE(ABORT, 'INVALID_RECIPIENT_WALLET')
	WHERE NEW.`recipient_wallet_id` IS NULL OR NOT EXISTS (
		SELECT 1 FROM `wallets` w JOIN `users` u ON u.`id` = w.`user_id`
		WHERE w.`id` = NEW.`recipient_wallet_id` AND u.`id` = NEW.`recipient_id` AND u.`status` = 'active'
	);
	SELECT RAISE(ABORT, 'SELF_TRANSFER')
	WHERE NEW.`sender_wallet_id` = NEW.`recipient_wallet_id`;
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
END;
