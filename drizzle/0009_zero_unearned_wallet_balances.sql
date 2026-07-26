INSERT INTO `audit_logs`
  (`id`, `actor_id`, `action`, `target_type`, `target_id`, `metadata`, `created_at`)
SELECT
  lower(hex(randomblob(16))),
  NULL,
  'wallet.legacy_activation_grant_reversed',
  'user',
  `users`.`id`,
  '{"reason":"remove_legacy_activation_grant","previousBalance":100000}',
  1784869200000
FROM `users`
WHERE `balance` = 100000
  AND `wallet_activated_at` IS NOT NULL
  AND EXISTS (SELECT 1 FROM `wallets` w WHERE w.`user_id` = `users`.`id`)
  AND EXISTS (SELECT 1 FROM `web3_wallets` e WHERE e.`user_id` = `users`.`id`)
  AND NOT EXISTS (
    SELECT 1 FROM `transfers` t
    WHERE t.`sender_id` = `users`.`id` OR t.`recipient_id` = `users`.`id`
  );--> statement-breakpoint

UPDATE `users`
SET `balance` = 0,
    `updated_at` = 1784869200000
WHERE `balance` = 100000
  AND `wallet_activated_at` IS NOT NULL
  AND EXISTS (SELECT 1 FROM `wallets` w WHERE w.`user_id` = `users`.`id`)
  AND EXISTS (SELECT 1 FROM `web3_wallets` e WHERE e.`user_id` = `users`.`id`)
  AND NOT EXISTS (
    SELECT 1 FROM `transfers` t
    WHERE t.`sender_id` = `users`.`id` OR t.`recipient_id` = `users`.`id`
  );
