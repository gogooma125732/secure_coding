CREATE TABLE `passkey_challenges` (
	`id` text PRIMARY KEY NOT NULL,
	`kind` text NOT NULL,
	`user_id` text,
	`challenge_hash` text NOT NULL,
	`rp_id` text NOT NULL,
	`origin` text NOT NULL,
	`expires_at` integer NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "passkey_challenges_id_length" CHECK(length("passkey_challenges"."id") = 43),
	CONSTRAINT "passkey_challenges_hash_length" CHECK(length("passkey_challenges"."challenge_hash") = 43),
	CONSTRAINT "passkey_challenges_rp_id_length" CHECK(length("passkey_challenges"."rp_id") BETWEEN 1 AND 253),
	CONSTRAINT "passkey_challenges_origin_length" CHECK(length("passkey_challenges"."origin") BETWEEN 9 AND 512),
	CONSTRAINT "passkey_challenges_kind" CHECK("passkey_challenges"."kind" IN ('registration', 'authentication'))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `passkey_challenges_hash_unique` ON `passkey_challenges` (`challenge_hash`);--> statement-breakpoint
CREATE INDEX `passkey_challenges_expiry_idx` ON `passkey_challenges` (`expires_at`);--> statement-breakpoint
CREATE TABLE `passkey_credentials` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`name` text NOT NULL,
	`public_key` text NOT NULL,
	`counter` integer DEFAULT 0 NOT NULL,
	`transports` text DEFAULT '[]' NOT NULL,
	`device_type` text NOT NULL,
	`backed_up` integer DEFAULT false NOT NULL,
	`created_at` integer NOT NULL,
	`last_used_at` integer,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "passkey_credentials_id_length" CHECK(length("passkey_credentials"."id") BETWEEN 16 AND 1024),
	CONSTRAINT "passkey_credentials_name_length" CHECK(length("passkey_credentials"."name") BETWEEN 1 AND 40),
	CONSTRAINT "passkey_credentials_public_key_length" CHECK(length("passkey_credentials"."public_key") BETWEEN 16 AND 8192),
	CONSTRAINT "passkey_credentials_transports_length" CHECK(length("passkey_credentials"."transports") <= 256),
	CONSTRAINT "passkey_credentials_counter_nonnegative" CHECK("passkey_credentials"."counter" >= 0),
	CONSTRAINT "passkey_credentials_device_type" CHECK("passkey_credentials"."device_type" IN ('singleDevice', 'multiDevice')),
	CONSTRAINT "passkey_credentials_backed_up" CHECK("passkey_credentials"."backed_up" IN (0, 1))
);
--> statement-breakpoint
CREATE INDEX `passkey_credentials_user_idx` ON `passkey_credentials` (`user_id`,`created_at`);