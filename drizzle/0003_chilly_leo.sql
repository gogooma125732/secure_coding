CREATE TABLE `pending_signups` (
	`id` text PRIMARY KEY NOT NULL,
	`challenge_hash` text NOT NULL,
	`username` text NOT NULL,
	`email` text NOT NULL,
	`password_hash` text NOT NULL,
	`bio` text DEFAULT '' NOT NULL,
	`code_hash` text NOT NULL,
	`attempts` integer DEFAULT 0 NOT NULL,
	`expires_at` integer NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT "pending_signups_attempts_range" CHECK("pending_signups"."attempts" >= 0 AND "pending_signups"."attempts" <= 5)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `pending_signups_challenge_unique` ON `pending_signups` (`challenge_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `pending_signups_username_unique` ON `pending_signups` (`username`);--> statement-breakpoint
CREATE UNIQUE INDEX `pending_signups_email_unique` ON `pending_signups` (`email`);--> statement-breakpoint
CREATE INDEX `pending_signups_expiry_idx` ON `pending_signups` (`expires_at`);--> statement-breakpoint
ALTER TABLE `users` ADD `email` text;--> statement-breakpoint
ALTER TABLE `users` ADD `email_verified_at` integer;--> statement-breakpoint
CREATE UNIQUE INDEX `users_email_unique` ON `users` (`email`);