-- SUPABASE MIGRATION: Add correlation engine tables and columns
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'correlation_rules_name_unique'
    ) THEN
        ALTER TABLE correlation_rules ADD CONSTRAINT correlation_rules_name_unique UNIQUE (name);
    END IF;
END $$;

-- 2. Add columns to detections table
ALTER TABLE detections
    ADD COLUMN IF NOT EXISTS file_id UUID REFERENCES log_files(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS severity TEXT,
    ADD COLUMN IF NOT EXISTS description TEXT,
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT now(),
    ADD COLUMN IF NOT EXISTS matched_indices JSONB;

-- 3. Add correlation_detections to analysis_results
ALTER TABLE analysis_results
    ADD COLUMN IF NOT EXISTS correlation_detections JSONB;

-- 4. Indexes
CREATE INDEX IF NOT EXISTS idx_detections_org ON detections(org_id);
CREATE INDEX IF NOT EXISTS idx_detections_file ON detections(file_id);
CREATE INDEX IF NOT EXISTS idx_detections_rule ON detections(rule_id);
CREATE INDEX IF NOT EXISTS idx_correlation_rules_org ON correlation_rules(org_id);

-- 5. Reload schema cache
NOTIFY pgrst, 'reload schema';
