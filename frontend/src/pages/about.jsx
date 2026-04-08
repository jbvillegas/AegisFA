import { Link } from 'react-router-dom';
import '../css/about.css';

const platformCapabilities = [
  {
    title: 'Ingestion and Parsing',
    description:
      'Supports structured and unstructured security logs through direct upload, chunked upload sessions, and stream-based ingestion workflows.',
  },
  {
    title: 'Threat Correlation',
    description:
      'Applies rule-driven correlation and aggregation logic to identify suspicious behavior patterns across events.',
  },
  {
    title: 'AI-Assisted Analysis',
    description:
      'Builds analyst-ready summaries with risk context, findings, and investigation guidance from normalized evidence.',
  },
  {
    title: 'MITRE ATT&CK Alignment',
    description:
      'Maps findings to ATT&CK techniques and stores linkable references for triage and reporting.',
  },
  {
    title: 'Timeline Intelligence',
    description:
      'Constructs file-level and organization-level timelines that combine raw events, detections, and AI narrative context.',
  },
  {
    title: 'Operational Dashboards',
    description:
      'Provides analyst and admin views for job monitoring, result review, remediation actions, and timeline preview.',
  },
];

const workflowSteps = [
  'Collect logs from supported sources and upload into an org-scoped context.',
  'Parse and normalize events, then persist records in Supabase storage and tables.',
  'Run correlation and model-assisted classification to identify suspicious patterns.',
  'Generate structured analysis with threat level, findings, timeline, and remediation guidance.',
  'Expose results through dashboard views, timeline endpoints, and investigation pages.',
];

const backendHighlights = [
  'Flask ingestion API with upload, analysis, timeline, and background job endpoints.',
  'Supabase-backed persistence for files, raw logs, analysis artifacts, and job tracking.',
  'Background analysis jobs with progress polling for large files and asynchronous workflows.',
  'Random Forest training and model version loading endpoints for iterative detection improvements.',
];

function AboutPage() {
  return (
    <section className="panel about-page" aria-labelledby="about-title">
      <header className="about-hero">
        <p className="about-kicker">About AegisFA</p>
        <h1 id="about-title">Comprehensive Security Log Analysis for Investigation Teams</h1>
        <p>
          AegisFA is an end-to-end security analytics platform built to help SOC and incident response teams move from raw telemetry to actionable decisions.
          The project combines ingestion, correlation, machine-assisted analysis, MITRE mapping, and timeline reconstruction in a single workflow.
        </p>
      </header>

      <section className="about-section" aria-labelledby="platform-capabilities-title">
        <h2 id="platform-capabilities-title">Platform Capabilities</h2>
        <div className="about-capability-grid">
          {platformCapabilities.map((capability) => (
            <article key={capability.title} className="about-card">
              <h3>{capability.title}</h3>
              <p>{capability.description}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="about-section" aria-labelledby="workflow-title">
        <h2 id="workflow-title">How the System Works</h2>
        <ol className="about-workflow-list">
          {workflowSteps.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
      </section>

      <section className="about-section" aria-labelledby="architecture-title">
        <h2 id="architecture-title">Architecture Highlights</h2>
        <ul className="about-bullet-list">
          {backendHighlights.map((highlight) => (
            <li key={highlight}>{highlight}</li>
          ))}
        </ul>
      </section>

      
      
    </section>
  );
}

export default AboutPage;
