CREATE TABLE IF NOT EXISTS analysis_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    status TEXT CHECK (status IN ('queued', 'running', 'completed', 'failed', 'partial')) DEFAULT 'queued',
    source_type TEXT CHECK (source_type IN ('windows', 'firewall', 'auth', 'syslog', 'custom')),
    total_files INT NOT NULL DEFAULT 0 CHECK (total_files >= 0),
    processed_files INT NOT NULL DEFAULT 0 CHECK (processed_files >= 0),
    failed_files INT NOT NULL DEFAULT 0 CHECK (failed_files >= 0),
    progress_pct NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK (progress_pct >= 0 AND progress_pct <= 100),
    created_at TIMESTAMPTZ DEFAULT now(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    output_path TEXT
);

CREATE TABLE IF NOT EXISTS analysis_job_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id UUID REFERENCES analysis_jobs(id) ON DELETE CASCADE,
    file_name TEXT NOT NULL,
    file_id UUID REFERENCES log_files(id) ON DELETE SET NULL,
    status TEXT CHECK (status IN ('queued', 'running', 'completed', 'failed')) DEFAULT 'queued',
    entry_count INT DEFAULT 0,
    result_id UUID REFERENCES analysis_results(id) ON DELETE SET NULL,
    progress_pct NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK (progress_pct >= 0 AND progress_pct <= 100),
    created_at TIMESTAMPTZ DEFAULT now(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_analysis_jobs_org ON analysis_jobs(org_id);
CREATE INDEX IF NOT EXISTS idx_analysis_jobs_status ON analysis_jobs(status);
CREATE INDEX IF NOT EXISTS idx_analysis_job_items_job ON analysis_job_items(job_id);
CREATE INDEX IF NOT EXISTS idx_analysis_job_items_status ON analysis_job_items(status);
