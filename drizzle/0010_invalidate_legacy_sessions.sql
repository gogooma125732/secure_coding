INSERT INTO `audit_logs`
  (`id`, `actor_id`, `action`, `target_type`, `target_id`, `metadata`, `created_at`)
VALUES
  (
    lower(hex(randomblob(16))),
    NULL,
    'auth.sessions_revoked_policy_upgrade',
    'session',
    NULL,
    '{"reason":"enforce_8h_absolute_30m_idle_session_policy"}',
    1784871000000
  );--> statement-breakpoint

DELETE FROM `sessions`;
