-- Public releases never assign administrator privileges to a source-controlled
-- identity. Use the authenticated /api/admin/bootstrap flow and a one-time
-- ADMIN_BOOTSTRAP_TOKEN configured in the runtime secret store.
SELECT 1;
