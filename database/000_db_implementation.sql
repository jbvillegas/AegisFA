--SUPABASE MIGRATION: Initial database schema for SIEM application
-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Organizations
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- 2. Users (extends Supabase Auth)
CREATE TABLE users (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT CHECK (role IN ('admin', 'analyst', 'viewer')) NOT NULL DEFAULT 'viewer'
);

-- 3. User Permissions
CREATE TABLE user_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    permission_name TEXT NOT NULL
);

-- 4. Log Sources
CREATE TABLE log_sources (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    type TEXT CHECK (type IN ('windows', 'firewall', 'auth', 'syslog', 'custom')) NOT NULL,
    config JSONB DEFAULT '{}'
);

-- 5. Raw Logs
CREATE TABLE raw_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    source_id UUID REFERENCES log_sources(id) ON DELETE SET NULL,
    payload JSONB NOT NULL,
    received_at TIMESTAMPTZ DEFAULT now()
);

-- 6. Normalized Events
CREATE TABLE normalized_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    raw_log_id UUID REFERENCES raw_logs(id) ON DELETE SET NULL,
    source_id UUID REFERENCES log_sources(id) ON DELETE SET NULL,
    event_type TEXT,
    severity TEXT
);

-- 7. Correlation Rules
CREATE TABLE correlation_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    mitre_technique TEXT,
    severity TEXT,
    rule_logic JSONB NOT NULL
);

-- 8. Detections
CREATE TABLE detections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    rule_id UUID REFERENCES correlation_rules(id) ON DELETE SET NULL,
    event_ids UUID[] DEFAULT '{}',
    confidence FLOAT
);

-- 9. Incidents
CREATE TABLE incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    status TEXT DEFAULT 'open',
    severity TEXT
);

-- 10. Incident Events (junction table)
CREATE TABLE incident_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    detection_id UUID REFERENCES detections(id) ON DELETE SET NULL,
    event_id UUID REFERENCES normalized_events(id) ON DELETE SET NULL
);

-- 11. Tasks
CREATE TABLE tasks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    assignee_id UUID REFERENCES users(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    status TEXT DEFAULT 'pending'
);

-- 12. Summaries
CREATE TABLE summaries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    narrative TEXT,
    model_used TEXT
);

-- 13. Feedback
CREATE TABLE feedback (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    summary_id UUID REFERENCES summaries(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    rating INT CHECK (rating >= 1 AND rating <= 5)
);

-- Indexes for common queries
CREATE INDEX idx_raw_logs_org ON raw_logs(org_id);
CREATE INDEX idx_raw_logs_received ON raw_logs(received_at);
CREATE INDEX idx_normalized_events_org ON normalized_events(org_id);
CREATE INDEX idx_normalized_events_type ON normalized_events(event_type);
CREATE INDEX idx_detections_org ON detections(org_id);
CREATE INDEX idx_incidents_org_status ON incidents(org_id, status);
CREATE INDEX idx_tasks_assignee ON tasks(assignee_id);

