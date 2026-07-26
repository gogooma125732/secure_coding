DELETE FROM `pending_signups`;--> statement-breakpoint
ALTER TABLE `users` ADD `platform_identity_hash` text;--> statement-breakpoint
CREATE UNIQUE INDEX `users_platform_identity_hash_unique` ON `users` (`platform_identity_hash`);
