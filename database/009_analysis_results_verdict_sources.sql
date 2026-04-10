-- SUPABASE MIGRATION: Persist confidence score evidence breakdown for analysis results
ALTER TABLE IF EXISTS analysis_results\n    
ADD COLUMN IF NOT EXISTS verdict_sources JSONB;
CREATE INDEX IF NOT EXISTS idx_analysis_results_verdict_sources   
ON analysis_results USING GIN (verdict_sources);