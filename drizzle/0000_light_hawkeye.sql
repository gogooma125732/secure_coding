CREATE TABLE `audit_logs` (
	`id` text PRIMARY KEY NOT NULL,
	`actor_id` text,
	`action` text NOT NULL,
	`target_type` text NOT NULL,
	`target_id` text,
	`metadata` text DEFAULT '{}' NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `audit_logs_created_idx` ON `audit_logs` (`created_at`);--> statement-breakpoint
CREATE TABLE `messages` (
	`id` text PRIMARY KEY NOT NULL,
	`sender_id` text NOT NULL,
	`recipient_id` text,
	`body` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`sender_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`recipient_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE restrict
);
--> statement-breakpoint
CREATE INDEX `messages_group_idx` ON `messages` (`recipient_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `messages_sender_idx` ON `messages` (`sender_id`,`created_at`);--> statement-breakpoint
CREATE TABLE `products` (
	`id` text PRIMARY KEY NOT NULL,
	`seller_id` text NOT NULL,
	`name` text NOT NULL,
	`description` text NOT NULL,
	`price` integer NOT NULL,
	`image_key` text NOT NULL,
	`image_type` text NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`seller_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "products_price_range" CHECK("products"."price" > 0 AND "products"."price" <= 1000000000)
);
--> statement-breakpoint
CREATE INDEX `products_seller_idx` ON `products` (`seller_id`);--> statement-breakpoint
CREATE INDEX `products_status_created_idx` ON `products` (`status`,`created_at`);--> statement-breakpoint
CREATE TABLE `rate_limits` (
	`key` text PRIMARY KEY NOT NULL,
	`count` integer NOT NULL,
	`window_started_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `reports` (
	`id` text PRIMARY KEY NOT NULL,
	`reporter_id` text NOT NULL,
	`target_type` text NOT NULL,
	`target_id` text NOT NULL,
	`reason` text NOT NULL,
	`status` text DEFAULT 'open' NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`reporter_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE restrict
);
--> statement-breakpoint
CREATE UNIQUE INDEX `reports_reporter_target_unique` ON `reports` (`reporter_id`,`target_type`,`target_id`);--> statement-breakpoint
CREATE INDEX `reports_target_idx` ON `reports` (`target_type`,`target_id`,`status`);--> statement-breakpoint
CREATE TABLE `sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`token_hash` text NOT NULL,
	`csrf_hash` text NOT NULL,
	`expires_at` integer NOT NULL,
	`last_seen_at` integer NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `sessions_token_hash_unique` ON `sessions` (`token_hash`);--> statement-breakpoint
CREATE INDEX `sessions_user_idx` ON `sessions` (`user_id`);--> statement-breakpoint
CREATE INDEX `sessions_expiry_idx` ON `sessions` (`expires_at`);--> statement-breakpoint
CREATE TABLE `transfers` (
	`id` text PRIMARY KEY NOT NULL,
	`sender_id` text NOT NULL,
	`recipient_id` text NOT NULL,
	`amount` integer NOT NULL,
	`memo` text DEFAULT '' NOT NULL,
	`idempotency_key` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`sender_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE restrict,
	FOREIGN KEY (`recipient_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "transfers_positive_amount" CHECK("transfers"."amount" > 0 AND "transfers"."amount" <= 100000000),
	CONSTRAINT "transfers_different_users" CHECK("transfers"."sender_id" <> "transfers"."recipient_id")
);
--> statement-breakpoint
CREATE UNIQUE INDEX `transfers_sender_idempotency_unique` ON `transfers` (`sender_id`,`idempotency_key`);--> statement-breakpoint
CREATE INDEX `transfers_sender_idx` ON `transfers` (`sender_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `transfers_recipient_idx` ON `transfers` (`recipient_id`,`created_at`);--> statement-breakpoint
CREATE TABLE `users` (
	`id` text PRIMARY KEY NOT NULL,
	`username` text NOT NULL,
	`password_hash` text NOT NULL,
	`bio` text DEFAULT '' NOT NULL,
	`role` text DEFAULT 'user' NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`balance` integer DEFAULT 100000 NOT NULL,
	`failed_logins` integer DEFAULT 0 NOT NULL,
	`locked_until` integer,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	CONSTRAINT "users_balance_nonnegative" CHECK("users"."balance" >= 0),
	CONSTRAINT "users_failed_logins_nonnegative" CHECK("users"."failed_logins" >= 0)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `users_username_unique` ON `users` (`username`);--> statement-breakpoint
CREATE TRIGGER `transfers_validate_before_insert`
BEFORE INSERT ON `transfers`
BEGIN
	SELECT RAISE(ABORT, 'INVALID_SENDER')
	WHERE NOT EXISTS (
		SELECT 1 FROM `users`
		WHERE `id` = NEW.`sender_id` AND `status` = 'active'
	);
	SELECT RAISE(ABORT, 'INVALID_RECIPIENT')
	WHERE NOT EXISTS (
		SELECT 1 FROM `users`
		WHERE `id` = NEW.`recipient_id` AND `status` = 'active'
	);
	SELECT RAISE(ABORT, 'INSUFFICIENT_FUNDS')
	WHERE (SELECT `balance` FROM `users` WHERE `id` = NEW.`sender_id`) < NEW.`amount`;
END;--> statement-breakpoint
CREATE TRIGGER `transfers_apply_after_insert`
AFTER INSERT ON `transfers`
BEGIN
	UPDATE `users`
	SET `balance` = `balance` - NEW.`amount`, `updated_at` = NEW.`created_at`
	WHERE `id` = NEW.`sender_id`;
	UPDATE `users`
	SET `balance` = `balance` + NEW.`amount`, `updated_at` = NEW.`created_at`
	WHERE `id` = NEW.`recipient_id`;
END;--> statement-breakpoint
CREATE TRIGGER `reports_moderate_product_after_insert`
AFTER INSERT ON `reports`
WHEN NEW.`target_type` = 'product'
BEGIN
	UPDATE `products`
	SET `status` = 'blocked', `updated_at` = NEW.`created_at`
	WHERE `id` = NEW.`target_id`
	  AND `status` = 'active'
	  AND (SELECT COUNT(*) FROM `reports`
	       WHERE `target_type` = 'product'
	         AND `target_id` = NEW.`target_id`
	         AND `status` = 'open') >= 3;
END;--> statement-breakpoint
CREATE TRIGGER `reports_moderate_user_after_insert`
AFTER INSERT ON `reports`
WHEN NEW.`target_type` = 'user'
BEGIN
	UPDATE `users`
	SET `status` = 'dormant', `updated_at` = NEW.`created_at`
	WHERE `id` = NEW.`target_id`
	  AND `role` <> 'admin'
	  AND `status` = 'active'
	  AND (SELECT COUNT(*) FROM `reports`
	       WHERE `target_type` = 'user'
	         AND `target_id` = NEW.`target_id`
	         AND `status` = 'open') >= 3;
	DELETE FROM `sessions`
	WHERE `user_id` = NEW.`target_id`
	  AND (SELECT `status` FROM `users` WHERE `id` = NEW.`target_id`) = 'dormant';
END;
