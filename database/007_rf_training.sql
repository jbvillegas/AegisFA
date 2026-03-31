-- SUPABASE MIGRATION: RF training model registry and run tracking

CREATE TABLE IF NOT EXISTS model_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT 'rf-cicids2019',
    version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('training', 'active', 'archived', 'failed')) DEFAULT 'training',
    artifact_bucket TEXT NOT NULL DEFAULT 'ml-models',
    artifact_path TEXT NOT NULL,
    label_classes JSONB NOT NULL DEFAULT '[]'::jsonb,
    training_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at TIMESTAMPTZ,
    UNIQUE(org_id, version)
);

CREATE TABLE IF NOT EXISTS training_runs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    model_version_id UUID REFERENCES model_versions(id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')) DEFAULT 'queued',
    dataset_name TEXT NOT NULL DEFAULT 'CICIDS2019',
    dataset_path TEXT,
    split_policy TEXT,
    seed INT,
    total_samples INT,
    class_distribution JSONB NOT NULL DEFAULT '{}'::jsonb,
    train_metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
    validation_metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
    test_metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message TEXT,
    requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_model_versions_org ON model_versions(org_id);
CREATE INDEX IF NOT EXISTS idx_model_versions_status ON model_versions(status);
CREATE INDEX IF NOT EXISTS idx_training_runs_org ON training_runs(org_id);
CREATE INDEX IF NOT EXISTS idx_training_runs_status ON training_runs(status);

ALTER TABLE IF EXISTS model_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS training_runs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS model_versions_select_org ON model_versions;
DROP POLICY IF EXISTS model_versions_insert_org ON model_versions;
DROP POLICY IF EXISTS model_versions_update_org ON model_versions;

CREATE POLICY model_versions_select_org ON model_versions
    FOR SELECT USING (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

CREATE POLICY model_versions_insert_org ON model_versions
    FOR INSERT WITH CHECK (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

CREATE POLICY model_versions_update_org ON model_versions
    FOR UPDATE USING (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    )
    WITH CHECK (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

DROP POLICY IF EXISTS training_runs_select_org ON training_runs;
DROP POLICY IF EXISTS training_runs_insert_org ON training_runs;
DROP POLICY IF EXISTS training_runs_update_org ON training_runs;

CREATE POLICY training_runs_select_org ON training_runs
    FOR SELECT USING (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

CREATE POLICY training_runs_insert_org ON training_runs
    FOR INSERT WITH CHECK (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

CREATE POLICY training_runs_update_org ON training_runs
    FOR UPDATE USING (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    )
    WITH CHECK (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );
