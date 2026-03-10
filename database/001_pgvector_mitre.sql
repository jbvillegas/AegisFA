-- ============================================================
-- AegisFA: pgvector + MITRE ATT&CK knowledge base setup
-- + missing tables (log_files, analysis_results)
-- Run this in Supabase SQL Editor (Dashboard > SQL Editor)
-- ============================================================

-- 1. Enable pgvector extension
create extension if not exists vector;

-- 2. Log Files table (tracks uploaded log files)
create table if not exists log_files (
    id uuid primary key default uuid_generate_v4(),
    org_id uuid references organizations(id) on delete cascade,
    filename text not null,
    source_type text check (source_type in ('windows', 'firewall', 'auth', 'syslog', 'custom')) not null,
    storage_path text,
    status text default 'analyzing',
    entry_count int default 0,
    created_at timestamptz default now()
);

-- Add file_id column to raw_logs so entries link back to their upload
alter table raw_logs
    add column if not exists file_id uuid references log_files(id) on delete set null;

-- 3. Analysis Results table (stores RAG pipeline output per file)
create table if not exists analysis_results (
    id uuid primary key default uuid_generate_v4(),
    file_id uuid references log_files(id) on delete cascade,
    threat_level text,
    threats_found int default 0,
    summary text,
    detailed_findings jsonb,
    mitre_techniques jsonb,
    attack_vector text,
    timeline jsonb,
    impacted_assets jsonb,
    confidence_score float,
    remediation_steps jsonb,
    created_at timestamptz default now()
);

-- 4. MITRE ATT&CK techniques table with vector embeddings
create table if not exists mitre_techniques (
    id bigint primary key generated always as identity,
    technique_id text not null unique,
    name text not null,
    description text not null,
    tactic text not null,
    platform text[],
    detection text,
    mitigation text,
    url text,
    embedding vector(1536),
    created_at timestamptz default now()
);

-- 5. HNSW index for fast cosine similarity search
create index if not exists mitre_techniques_embedding_idx
on mitre_techniques using hnsw (embedding vector_cosine_ops);

-- 6. Indexes for new tables
create index if not exists idx_log_files_org on log_files(org_id);
create index if not exists idx_analysis_results_file on analysis_results(file_id);
create index if not exists idx_raw_logs_file on raw_logs(file_id);

-- 7. Similarity search function (called via supabase.rpc())
create or replace function match_mitre_techniques(
    query_embedding vector(1536),
    match_threshold float default 0.3,
    match_count int default 5
)
returns table (
    technique_id text,
    name text,
    description text,
    tactic text,
    platform text[],
    detection text,
    mitigation text,
    url text,
    similarity float
)
language plpgsql
as $$
begin
    return query
    select
        mt.technique_id,
        mt.name,
        mt.description,
        mt.tactic,
        mt.platform,
        mt.detection,
        mt.mitigation,
        mt.url,
        1 - (mt.embedding <=> query_embedding) as similarity
    from mitre_techniques mt
    where 1 - (mt.embedding <=> query_embedding) > match_threshold
    order by mt.embedding <=> query_embedding
    limit match_count;
end;
$$;
