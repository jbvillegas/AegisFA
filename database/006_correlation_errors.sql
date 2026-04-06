-- SUPABASE MIGRATION: Persist correlation engine errors for auditing and debugging
CREATE TABLE IF NOT EXISTS correlation_errors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    file_id UUID REFERENCES log_files(id) ON DELETE CASCADE,
    rule_id UUID REFERENCES correlation_rules(id) ON DELETE SET NULL,
    error_stage TEXT NOT NULL,
    error_type TEXT,
    message TEXT,
    details JSONB,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_correlation_errors_org ON correlation_errors(org_id);
CREATE INDEX IF NOT EXISTS idx_correlation_errors_file ON correlation_errors(file_id);
CREATE INDEX IF NOT EXISTS idx_correlation_errors_created_at ON correlation_errors(created_at);

-- RLS
ALTER TABLE IF EXISTS correlation_errors ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS correlation_errors_select_org ON correlation_errors;
DROP POLICY IF EXISTS correlation_errors_insert_org ON correlation_errors;
DROP POLICY IF EXISTS correlation_errors_update_org ON correlation_errors;

CREATE POLICY correlation_errors_select_org ON correlation_errors
    FOR SELECT USING (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

CREATE POLICY correlation_errors_insert_org ON correlation_errors
    FOR INSERT WITH CHECK (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

CREATE POLICY correlation_errors_update_org ON correlation_errors
    FOR UPDATE USING (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    )
    WITH CHECK (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

-- 5. Reload schema cache
NOTIFY pgrst, 'reload schema';