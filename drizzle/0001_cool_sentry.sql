CREATE TABLE `wallets` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "wallets_id_format" CHECK(length("wallets"."id") = 47 AND substr("wallets"."id", 1, 4) = 'wlt_')
);
--> statement-breakpoint
CREATE UNIQUE INDEX `wallets_user_unique` ON `wallets` (`user_id`);--> statement-breakpoint
ALTER TABLE `transfers` ADD `sender_wallet_id` text REFERENCES wallets(id);--> statement-breakpoint
ALTER TABLE `transfers` ADD `recipient_wallet_id` text REFERENCES wallets(id);--> statement-breakpoint
CREATE INDEX `transfers_sender_wallet_idx` ON `transfers` (`sender_wallet_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `transfers_recipient_wallet_idx` ON `transfers` (`recipient_wallet_id`,`created_at`);--> statement-breakpoint
DROP TRIGGER IF EXISTS `transfers_validate_before_insert`;--> statement-breakpoint
DROP TRIGGER IF EXISTS `transfers_apply_after_insert`;--> statement-breakpoint
CREATE TRIGGER `transfers_validate_before_insert`
BEFORE INSERT ON `transfers`
BEGIN
	SELECT RAISE(ABORT, 'INVALID_SENDER_WALLET')
	WHERE NEW.`sender_wallet_id` IS NULL OR NOT EXISTS (
		SELECT 1 FROM `wallets` w JOIN `users` u ON u.`id` = w.`user_id`
		WHERE w.`id` = NEW.`sender_wallet_id`
		  AND u.`id` = NEW.`sender_id`
		  AND u.`status` = 'active'
	);
	SELECT RAISE(ABORT, 'INVALID_RECIPIENT_WALLET')
	WHERE NEW.`recipient_wallet_id` IS NULL OR NOT EXISTS (
		SELECT 1 FROM `wallets` w JOIN `users` u ON u.`id` = w.`user_id`
		WHERE w.`id` = NEW.`recipient_wallet_id`
		  AND u.`id` = NEW.`recipient_id`
		  AND u.`status` = 'active'
	);
	SELECT RAISE(ABORT, 'SELF_TRANSFER')
	WHERE NEW.`sender_wallet_id` = NEW.`recipient_wallet_id`;
	SELECT RAISE(ABORT, 'INSUFFICIENT_FUNDS')
	WHERE (
		SELECT u.`balance` FROM `users` u JOIN `wallets` w ON w.`user_id` = u.`id`
		WHERE w.`id` = NEW.`sender_wallet_id`
	) < NEW.`amount`;
END;--> statement-breakpoint
CREATE TRIGGER `transfers_apply_after_insert`
AFTER INSERT ON `transfers`
BEGIN
	UPDATE `users`
	SET `balance` = `balance` - NEW.`amount`, `updated_at` = NEW.`created_at`
	WHERE `id` = (SELECT `user_id` FROM `wallets` WHERE `id` = NEW.`sender_wallet_id`);
	UPDATE `users`
	SET `balance` = `balance` + NEW.`amount`, `updated_at` = NEW.`created_at`
	WHERE `id` = (SELECT `user_id` FROM `wallets` WHERE `id` = NEW.`recipient_wallet_id`);
END;
