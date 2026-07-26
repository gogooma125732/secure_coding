CREATE TABLE `web3_challenges` (
	`id` text PRIMARY KEY NOT NULL,
	`challenge_hash` text NOT NULL,
	`user_id` text NOT NULL,
	`chain_id` integer NOT NULL,
	`address_key` text NOT NULL,
	`message_hash` text NOT NULL,
	`expires_at` integer NOT NULL,
	`used_at` integer,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "web3_challenges_chain" CHECK("web3_challenges"."chain_id" IN (1, 11155111)),
	CONSTRAINT "web3_challenges_address_key" CHECK(length("web3_challenges"."address_key") = 42 AND "web3_challenges"."address_key" = lower("web3_challenges"."address_key")),
	CONSTRAINT "web3_challenges_message_hash" CHECK(length("web3_challenges"."message_hash") = 64)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `web3_challenges_challenge_unique` ON `web3_challenges` (`challenge_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `web3_challenges_message_unique` ON `web3_challenges` (`message_hash`);--> statement-breakpoint
CREATE INDEX `web3_challenges_expiry_idx` ON `web3_challenges` (`expires_at`);--> statement-breakpoint
CREATE TABLE `web3_wallets` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`chain_id` integer NOT NULL,
	`address` text NOT NULL,
	`address_key` text NOT NULL,
	`account_kind` text NOT NULL,
	`verified_at` integer NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE restrict,
	CONSTRAINT "web3_wallets_chain" CHECK("web3_wallets"."chain_id" IN (1, 11155111)),
	CONSTRAINT "web3_wallets_address_length" CHECK(length("web3_wallets"."address") = 42),
	CONSTRAINT "web3_wallets_address_key" CHECK(length("web3_wallets"."address_key") = 42 AND "web3_wallets"."address_key" = lower("web3_wallets"."address_key"))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `web3_wallets_chain_address_unique` ON `web3_wallets` (`chain_id`,`address_key`);--> statement-breakpoint
CREATE UNIQUE INDEX `web3_wallets_user_chain_unique` ON `web3_wallets` (`user_id`,`chain_id`);--> statement-breakpoint
CREATE INDEX `web3_wallets_user_idx` ON `web3_wallets` (`user_id`,`chain_id`);