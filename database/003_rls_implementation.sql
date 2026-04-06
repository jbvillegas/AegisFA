-- SUPABASE MIGRATION: Implement Row-Level Security (RLS) for multi-tenancy
-- This migration is idempotent and focuses on org-scoped access.

-- Enable RLS on key tenant tables. Service role bypasses these policies.
ALTER TABLE IF EXISTS organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS users ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS user_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS log_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS raw_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS normalized_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS correlation_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS detections ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS incident_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS summaries ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS log_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS analysis_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS analysis_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS analysis_job_items ENABLE ROW LEVEL SECURITY;

-- Raw logs policies
DROP POLICY IF EXISTS raw_logs_select_org ON raw_logs;
DROP POLICY IF EXISTS raw_logs_insert_org ON raw_logs;
DROP POLICY IF EXISTS raw_logs_update_org ON raw_logs;

CREATE POLICY raw_logs_select_org ON raw_logs
    FOR SELECT USING (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

CREATE POLICY raw_logs_insert_org ON raw_logs
    FOR INSERT WITH CHECK (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

CREATE POLICY raw_logs_update_org ON raw_logs
    FOR UPDATE USING (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    )
    WITH CHECK (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

-- Incidents policies
DROP POLICY IF EXISTS incidents_select_org ON incidents;
DROP POLICY IF EXISTS incidents_insert_org ON incidents;
DROP POLICY IF EXISTS incidents_update_org ON incidents;

CREATE POLICY incidents_select_org ON incidents
    FOR SELECT USING (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

CREATE POLICY incidents_insert_org ON incidents
    FOR INSERT WITH CHECK (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

CREATE POLICY incidents_update_org ON incidents
    FOR UPDATE USING (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    )
    WITH CHECK (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

-- Log files policies
DROP POLICY IF EXISTS log_files_select_org ON log_files;
DROP POLICY IF EXISTS log_files_insert_org ON log_files;
DROP POLICY IF EXISTS log_files_update_org ON log_files;

CREATE POLICY log_files_select_org ON log_files
    FOR SELECT USING (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

CREATE POLICY log_files_insert_org ON log_files
    FOR INSERT WITH CHECK (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

CREATE POLICY log_files_update_org ON log_files
    FOR UPDATE USING (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    )
    WITH CHECK (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

-- Analysis results policies (org inferred via related log file)
DROP POLICY IF EXISTS analysis_results_select_org ON analysis_results;
DROP POLICY IF EXISTS analysis_results_insert_org ON analysis_results;
DROP POLICY IF EXISTS analysis_results_update_org ON analysis_results;

CREATE POLICY analysis_results_select_org ON analysis_results
    FOR SELECT USING (
        EXISTS (
            SELECT 1
            FROM log_files lf
            JOIN users u ON u.org_id = lf.org_id
            WHERE lf.id = analysis_results.file_id
              AND u.id = auth.uid()
        )
    );

CREATE POLICY analysis_results_insert_org ON analysis_results
    FOR INSERT WITH CHECK (
        EXISTS (
            SELECT 1
            FROM log_files lf
            JOIN users u ON u.org_id = lf.org_id
            WHERE lf.id = analysis_results.file_id
              AND u.id = auth.uid()
        )
    );

CREATE POLICY analysis_results_update_org ON analysis_results
    FOR UPDATE USING (
        EXISTS (
            SELECT 1
            FROM log_files lf
            JOIN users u ON u.org_id = lf.org_id
            WHERE lf.id = analysis_results.file_id
              AND u.id = auth.uid()
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1
            FROM log_files lf
            JOIN users u ON u.org_id = lf.org_id
            WHERE lf.id = analysis_results.file_id
              AND u.id = auth.uid()
        )
    );

-- Analysis jobs policies
DROP POLICY IF EXISTS analysis_jobs_select_org ON analysis_jobs;
DROP POLICY IF EXISTS analysis_jobs_insert_org ON analysis_jobs;
DROP POLICY IF EXISTS analysis_jobs_update_org ON analysis_jobs;

CREATE POLICY analysis_jobs_select_org ON analysis_jobs
    FOR SELECT USING (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

CREATE POLICY analysis_jobs_insert_org ON analysis_jobs
    FOR INSERT WITH CHECK (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

CREATE POLICY analysis_jobs_update_org ON analysis_jobs
    FOR UPDATE USING (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    )
    WITH CHECK (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

-- Analysis job items policies (org inferred via parent job)
DROP POLICY IF EXISTS analysis_job_items_select_org ON analysis_job_items;
DROP POLICY IF EXISTS analysis_job_items_insert_org ON analysis_job_items;
DROP POLICY IF EXISTS analysis_job_items_update_org ON analysis_job_items;

CREATE POLICY analysis_job_items_select_org ON analysis_job_items
    FOR SELECT USING (
        EXISTS (
            SELECT 1
            FROM analysis_jobs aj
            JOIN users u ON u.org_id = aj.org_id
            WHERE aj.id = analysis_job_items.job_id
              AND u.id = auth.uid()
        )
    );

CREATE POLICY analysis_job_items_insert_org ON analysis_job_items
    FOR INSERT WITH CHECK (
        EXISTS (
            SELECT 1
            FROM analysis_jobs aj
            JOIN users u ON u.org_id = aj.org_id
            WHERE aj.id = analysis_job_items.job_id
              AND u.id = auth.uid()
        )
    );

CREATE POLICY analysis_job_items_update_org ON analysis_job_items
    FOR UPDATE USING (
        EXISTS (
            SELECT 1
            FROM analysis_jobs aj
            JOIN users u ON u.org_id = aj.org_id
            WHERE aj.id = analysis_job_items.job_id
              AND u.id = auth.uid()
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1
            FROM analysis_jobs aj
            JOIN users u ON u.org_id = aj.org_id
            WHERE aj.id = analysis_job_items.job_id
              AND u.id = auth.uid()
        )
    );
