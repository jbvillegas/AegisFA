import { Link } from 'react-router-dom';
import '../css/support.css';

const quickStartSteps = [
  'Start backend ingestion API from backend/ingestion with python3 run.py (default port 5007).',
  'Start frontend from frontend with npm run dev (Vite development server).',
  'Confirm environment values for Supabase URL and anonymous key are set before opening authenticated pages.',
  'Upload a file from the Dashboard, then monitor analysis job progress and result status.',
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
  {
    area: 'Health and Root',
    endpoint: 'GET /',
    purpose: 'Verifies ingestion API is running and reachable.',
  },
  {
    area: 'Analysis Result',
    endpoint: 'GET /analysis/:fileId',
    purpose: 'Checks final stored analysis payload for a completed file.',
  },
  {
    area: 'File Timeline',
    endpoint: 'GET /timeline/file/:fileId',
    purpose: 'Retrieves timeline items merged from raw events, detections, and AI narrative.',
  },
  {
    area: 'Organization Timeline',
    endpoint: 'GET /timeline/org/:orgId',
    purpose: 'Retrieves cross-file timeline for organization-wide triage context.',
  },
  {
    area: 'Background Jobs',
    endpoint: 'GET /analysis-jobs/:jobId',
    purpose: 'Polls asynchronous job progress, status, and final result linkage.',
  },
];

const supportChecklist = [
  'Request ID from backend response payload (or server logs).',
  'Endpoint path and HTTP status code that failed.',
  'Frontend console error and corresponding Network response body.',
  'Org ID and file ID involved in the workflow.',
  'Last successful action before the failure occurred.',
];

const diagnosticsCommands = [
  {
    title: 'Verify backend listener',
    command: 'lsof -nP -iTCP:5007 -sTCP:LISTEN',
  },
  {
    title: 'Check ingestion API health',
    command: 'curl -sS http://127.0.0.1:5007/',
  },
  {
    title: 'Inspect org timeline payload',
    command:
      'curl -sS "http://127.0.0.1:5007/timeline/org/<ORG_ID>?page=1&page_size=5"',
  },
  {
    title: 'Inspect file timeline payload',
    command:
      'curl -sS "http://127.0.0.1:5007/timeline/file/<FILE_ID>?page=1&page_size=10"',
  },
  {
    title: 'Build frontend to validate routing/pages',
    command: 'cd /workspaces/frontend && npm run build',
  },
];

function SupportPage() {
  return (
    <section className="panel support-page" aria-labelledby="support-title">
      <header className="support-hero">
        <p className="support-kicker">Support Center</p>
        <h1 id="support-title">Operational Support for AegisFA</h1>
        <p>
          This page provides project-specific guidance for environment setup, ingestion diagnostics, timeline visibility, and
          incident analysis troubleshooting across the full frontend and backend workflow.
        </p>
      </header>

      <section className="support-section" aria-labelledby="quickstart-title">
        <h2 id="quickstart-title">Quick Start Validation</h2>
        <ol className="support-list ordered">
          {quickStartSteps.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
      </section>

      <section className="support-section" aria-labelledby="issues-title">
        <h2 id="issues-title">Common Issues and Fix Paths</h2>
        <div className="support-issue-grid">
          {commonIssues.map((issue) => (
            <article className="support-issue-card" key={issue.title}>
              <h3>{issue.title}</h3>
              <p><strong>Symptom:</strong> {issue.symptom}</p>
              <p><strong>Resolution:</strong> {issue.resolution}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="support-section" aria-labelledby="diagnostics-title">
        <h2 id="diagnostics-title">API Diagnostics Reference</h2>
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
                  <td>{item.endpoint}</td>
                  <td>{item.purpose}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="support-section" aria-labelledby="escalation-title">
        <h2 id="escalation-title">Escalation Checklist</h2>
        <p>
          When reporting a failure, include the artifacts below so investigation can proceed quickly without reproducing the issue from scratch.
        </p>
        <ul className="support-list">
          {supportChecklist.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </section>

      <section className="support-section" aria-labelledby="diagnostics-commands-title">
        <h2 id="diagnostics-commands-title">Run Diagnostics</h2>
        <p>
          Use these commands directly in the project workspace to confirm service availability, endpoint responses, and build integrity.
        </p>
        <div className="support-command-grid">
          {diagnosticsCommands.map((item) => (
            <article className="support-command-card" key={item.title}>
              <h3>{item.title}</h3>
              <pre className="support-command"><code>{item.command}</code></pre>
            </article>
          ))}
        </div>
      </section>

      <section className="support-section support-cta" aria-labelledby="support-next-title">
        <h2 id="support-next-title">Continue in Product</h2>
        <div className="support-actions">
          <Link className="support-btn primary" to="/dashboard">Open Dashboard</Link>
          <Link className="support-btn secondary" to="/admin">Open Admin</Link>
          <Link className="support-btn secondary" to="/about">Project Overview</Link>
        </div>
      </section>
    </section>
  );
}

export default SupportPage;
