-- Privacy hardening: drop raw-IP PII columns and a dead table.
--
-- Rationale: the published privacy policy (smirk.cash/privacy, PRIVACY.md) states
-- that IP addresses are retained ONLY as a salted one-way hash (for rate limiting,
-- via login_events / restore_attempts). These columns instead stored a RAW client
-- IP tied to user_id, contradicting that promise. Dropping them makes the schema
-- enforce the policy. The hashed rate-limit path (login_events.ip_hash) is untouched.
--
-- The operator forensic trail (admin_audit_logs, admin_sessions) is intentionally
-- left as-is: a tamper-evident record of privileged actions is a different threat
-- model from end-user data and is covered separately.

-- 1. sessions.ip_address — was written raw on every user login (extension + web).
ALTER TABLE sessions DROP COLUMN IF EXISTS ip_address;

-- 2. audit_logs.ip_address — raw-IP column on the (currently unwired) user audit
--    table. If security logging is wired up later, hash the IP like login_events.
ALTER TABLE audit_logs DROP COLUMN IF EXISTS ip_address;

-- 3. Dead `wallets` table — created in the initial schema but never read or written
--    by any code path (a latent user_id -> address / view_key PII store). Remove it.
DROP TABLE IF EXISTS wallets;
