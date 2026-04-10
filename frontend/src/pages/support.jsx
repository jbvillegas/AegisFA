import { Link } from 'react-router-dom';
import '../css/homepage.css';
import '../css/support.css';

const quickStartSteps = [
  { num: '01', text: 'Start backend ingestion API from backend/ingestion with python3 run.py (default port 5007).' },
  { num: '02', text: 'Start frontend from frontend with npm run dev (Vite development server).' },
  { num: '03', text: 'Confirm environment values for Supabase URL and anonymous key are set before opening authenticated pages.' },
  { num: '04', text: 'Upload a file from the Dashboard, then monitor analysis job progress and result status.' },
];

const commonIssues = [
  {
    title: 'Port 5007 already in use',
    symptom: 'Backend fails to start with Address already in use.',
    resolution:
      'Stop the existing listener on port 5007 or reuse the active process. Verify active PID with lsof -nP -iTCP:5007 -sTCP:LISTEN.',
  },
  {
    title: 'Upload completed but analysis job creation failed',
    symptom: 'Upload sessions complete call returns 500.',
    resolution:
      'Ensure org context and requested_by are valid UUID values and mapped to expected user records. Review backend validation response payload for exact error details.',
  },
  {
    title: 'Timeline preview appears empty',
    symptom: 'Admin timeline section shows no events after analysis.',
    resolution:
      'Verify /timeline/org/:orgId and /timeline/file/:fileId responses. The UI can show org-level timeline when per-file narrative timeline is missing.',
  },
  {
    title: 'Supabase log_files query returns 400',
    symptom: 'Requests fail on created_at or uploaded_at selection.',
    resolution:
      'Use schema-tolerant querying and fallback fields in the frontend. Confirm deployed schema and RLS policies for log_files visibility.',
  },
];

const diagnostics = [
  { area: 'Health and Root', endpoint: 'GET /', purpose: 'Verifies ingestion API is running and reachable.' },
  { area: 'Analysis Result', endpoint: 'GET /analysis/:fileId', purpose: 'Checks final stored analysis payload for a completed file.' },
  { area: 'File Timeline', endpoint: 'GET /timeline/file/:fileId', purpose: 'Retrieves timeline items merged from raw events, detections, and AI narrative.' },
  { area: 'Organization Timeline', endpoint: 'GET /timeline/org/:orgId', purpose: 'Retrieves cross-file timeline for organization-wide triage context.' },
  { area: 'Background Jobs', endpoint: 'GET /analysis-jobs/:jobId', purpose: 'Polls asynchronous job progress, status, and final result linkage.' },
];

const supportChecklist = [
  'Request ID from backend response payload (or server logs).',
  'Endpoint path and HTTP status code that failed.',
  'Frontend console error and corresponding Network response body.',
  'Org ID and file ID involved in the workflow.',
  'Last successful action before the failure occurred.',
];

const diagnosticsCommands = [
  { title: 'Verify backend listener', command: 'lsof -nP -iTCP:5007 -sTCP:LISTEN' },
  { title: 'Check ingestion API health', command: 'curl -sS http://127.0.0.1:5007/' },
  { title: 'Inspect org timeline payload', command: 'curl -sS "http://127.0.0.1:5007/timeline/org/<ORG_ID>?page=1&page_size=5"' },
  { title: 'Inspect file timeline payload', command: 'curl -sS "http://127.0.0.1:5007/timeline/file/<FILE_ID>?page=1&page_size=10"' },
  { title: 'Build frontend to validate routing', command: 'cd /workspaces/frontend && npm run build' },
];

function SupportPage() {
  return (
    <div className="hp support-shell">

      {/* Hero */}
      <section className="hp-hero">
        <div className="hp-hero-inner">
          <p className="hp-kicker">Support Center</p>
          <h1 className="hp-hero-title">
            Operational Support for AegisFA
          </h1>
          <p className="hp-hero-sub">
            Project-specific guidance for environment setup, ingestion diagnostics, timeline visibility, and incident analysis troubleshooting across the full frontend and backend workflow.
          </p>
        </div>
        <div className="hp-hero-glow" aria-hidden="true" />
      </section>

      {/* Quick Start */}
      <section className="hp-stats">
        <header className="hp-section-header" style={{ marginBottom: 'var(--spacing-lg)' }}>
          <p className="hp-kicker">Getting Started</p>
          <h2>Quick Start Validation</h2>
        </header>
        <div className="support-steps">
          {quickStartSteps.map((step) => (
            <div key={step.num} className="support-step">
              <span className="support-step-num">{step.num}</span>
              <p>{step.text}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Common Issues */}
      <section>
        <header className="hp-section-header">
          <p className="hp-kicker">Troubleshooting</p>
          <h2>Common Issues and Fix Paths</h2>
        </header>
      </section>

      <section>
        <div className="support-issue-grid">
          {commonIssues.map((issue) => (
            <article className="hp-feature-card" key={issue.title}>
              <h3>{issue.title}</h3>
              <p><strong>Symptom:</strong> {issue.symptom}</p>
              <p><strong>Resolution:</strong> {issue.resolution}</p>
            </article>
          ))}
        </div>
      </section>

      {/* API Diagnostics */}
      <section>
        <header className="hp-section-header">
          <p className="hp-kicker">Reference</p>
          <h2>API Diagnostics Reference</h2>
        </header>
      </section>

      <section>
        <div className="support-table-wrap">
          <table className="support-table">
            <thead>
              <tr>
                <th scope="col">Area</th>
                <th scope="col">Endpoint</th>
                <th scope="col">Purpose</th>
              </tr>
            </thead>
            <tbody>
              {diagnostics.map((item) => (
                <tr key={item.endpoint}>
                  <td>{item.area}</td>
                  <td><code>{item.endpoint}</code></td>
                  <td>{item.purpose}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Escalation Checklist */}
      <section className="hp-why">
        <header className="hp-section-header">
          <p className="hp-kicker">Escalation</p>
          <h2>Include This When Reporting Issues</h2>
          <p className="hp-section-sub">
            When reporting a failure, include the artifacts below so investigation can proceed without reproducing the issue from scratch.
          </p>
        </header>
        <div className="hp-why-grid support-checklist-grid">
          {supportChecklist.map((item, i) => (
            <article key={i} className="hp-why-card">
              <p>{item}</p>
            </article>
          ))}
        </div>
      </section>

      {/* Run Diagnostics */}
      <section>
        <header className="hp-section-header">
          <p className="hp-kicker">Diagnostics</p>
          <h2>Run Diagnostics</h2>
          <p className="hp-section-sub">
            Use these commands in the project workspace to confirm service availability, endpoint responses, and build integrity.
          </p>
        </header>
      </section>

      <section>
        <div className="support-command-grid">
          {diagnosticsCommands.map((item) => (
            <article className="hp-feature-card support-cmd-card" key={item.title}>
              <h3>{item.title}</h3>
              <pre className="support-command"><code>{item.command}</code></pre>
            </article>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="hp-cta">
        <h2>Continue in Product</h2>
        <p>Jump directly into the dashboard, admin panel, or project overview.</p>
        <div className="hp-hero-actions">
          <Link to="/dashboard" className="hp-btn hp-btn-primary">Open Dashboard</Link>
          <Link to="/admin" className="hp-btn hp-btn-secondary">Open Admin</Link>
          <Link to="/about" className="hp-btn hp-btn-secondary">Project Overview</Link>
        </div>
      </section>

    </div>
  );
}

export default SupportPage;
