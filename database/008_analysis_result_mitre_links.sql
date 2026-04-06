-- SUPABASE MIGRATION: Normalize links between analysis results and MITRE techniques

CREATE TABLE IF NOT EXISTS analysis_result_mitre_links (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analysis_result_id UUID NOT NULL REFERENCES analysis_results(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    file_id UUID NOT NULL REFERENCES log_files(id) ON DELETE CASCADE,
    technique_id TEXT NOT NULL REFERENCES mitre_techniques(technique_id) ON DELETE RESTRICT,
    technique_name TEXT,
    tactic TEXT,
    relevance TEXT,
    similarity_score FLOAT,
    rank_position INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (analysis_result_id, technique_id)
);

CREATE INDEX IF NOT EXISTS idx_analysis_result_mitre_links_analysis_result
    ON analysis_result_mitre_links(analysis_result_id);

CREATE INDEX IF NOT EXISTS idx_analysis_result_mitre_links_org
    ON analysis_result_mitre_links(org_id);

CREATE INDEX IF NOT EXISTS idx_analysis_result_mitre_links_file
    ON analysis_result_mitre_links(file_id);

CREATE INDEX IF NOT EXISTS idx_analysis_result_mitre_links_technique
    ON analysis_result_mitre_links(technique_id);

ALTER TABLE IF EXISTS analysis_result_mitre_links ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS analysis_result_mitre_links_select_org ON analysis_result_mitre_links;
DROP POLICY IF EXISTS analysis_result_mitre_links_insert_org ON analysis_result_mitre_links;
DROP POLICY IF EXISTS analysis_result_mitre_links_update_org ON analysis_result_mitre_links;

CREATE POLICY analysis_result_mitre_links_select_org ON analysis_result_mitre_links
    FOR SELECT USING (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

CREATE POLICY analysis_result_mitre_links_insert_org ON analysis_result_mitre_links
    FOR INSERT WITH CHECK (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

CREATE POLICY analysis_result_mitre_links_update_org ON analysis_result_mitre_links
    FOR UPDATE USING (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    )
    WITH CHECK (
        org_id = (SELECT u.org_id FROM users u WHERE u.id = auth.uid())
    );

NOTIFY pgrst, 'reload schema';
