-- Sprint 2 schema extensions for collaboration and AI feedback tracking

ALTER TABLE IF EXISTS feedback
    ADD COLUMN IF NOT EXISTS suggestion_text TEXT,
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT now();

CREATE INDEX IF NOT EXISTS idx_feedback_org_created_at ON feedback(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_org_status ON incidents(org_id, status);
CREATE INDEX IF NOT EXISTS idx_tasks_org_status ON tasks(org_id, status);

NOTIFY pgrst, 'reload schema';
