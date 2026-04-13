-- 012: Drop unused tables
-- Tables log_sources, user_permissions, incident_events, and summaries
-- are defined but never queried or populated by the application.

BEGIN;

-- Drop foreign key constraints referencing tables being removed
ALTER TABLE raw_logs DROP CONSTRAINT IF EXISTS raw_logs_source_id_fkey;
ALTER TABLE normalized_events DROP CONSTRAINT IF EXISTS normalized_events_source_id_fkey;
ALTER TABLE feedback DROP CONSTRAINT IF EXISTS feedback_summary_id_fkey;

-- Drop RLS policies on these tables
DROP POLICY IF EXISTS rls_log_sources ON log_sources;
DROP POLICY IF EXISTS rls_user_permissions ON user_permissions;
DROP POLICY IF EXISTS rls_incident_events ON incident_events;
DROP POLICY IF EXISTS rls_summaries ON summaries;

-- Drop the unused tables
DROP TABLE IF EXISTS log_sources;
DROP TABLE IF EXISTS user_permissions;
DROP TABLE IF EXISTS incident_events;
DROP TABLE IF EXISTS summaries;

COMMIT;
