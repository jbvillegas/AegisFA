-- SUPABASE MIGRATION: Add tables for log file management and analysis results
-- This migration creates tables to track uploaded log files and store the results of the RAG analysis
-- Log Files
CREATE TABLE IF NOT EXISTS log_files (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    source_type TEXT CHECK (source_type IN ('windows', 'firewall', 'auth', 'syslog', 'custom')),
    storage_path TEXT,
    status TEXT DEFAULT 'uploaded' CHECK (status IN ('uploaded', 'analyzing', 'completed', 'failed')),
    entry_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Analysis Results
CREATE TABLE IF NOT EXISTS analysis_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    file_id UUID REFERENCES log_files(id) ON DELETE CASCADE,
    threat_level TEXT CHECK (threat_level IN ('none', 'low', 'medium', 'high', 'critical')),
    threats_found INTEGER DEFAULT 0,
    summary TEXT,
    detailed_findings JSONB,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Link raw_logs to their source file
ALTER TABLE raw_logs ADD COLUMN IF NOT EXISTS file_id UUID REFERENCES log_files(id) ON DELETE SET NULL;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_log_files_org ON log_files(org_id);
CREATE INDEX IF NOT EXISTS idx_analysis_results_file ON analysis_results(file_id);
CREATE INDEX IF NOT EXISTS idx_raw_logs_file ON raw_logs(file_id);
