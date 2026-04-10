import { Link } from 'react-router-dom';
import '../css/homepage.css';
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
  { num: '01', text: 'Collect logs from supported sources and upload into an org-scoped context.' },
  { num: '02', text: 'Parse and normalize events, then persist records in Supabase storage and tables.' },
  { num: '03', text: 'Run correlation and model-assisted classification to identify suspicious patterns.' },
  { num: '04', text: 'Generate structured analysis with threat level, findings, timeline, and remediation guidance.' },
  { num: '05', text: 'Expose results through dashboard views, timeline endpoints, and investigation pages.' },
];

const backendHighlights = [
  'Flask ingestion API with upload, analysis, timeline, and background job endpoints.',
  'Supabase-backed persistence for files, raw logs, analysis artifacts, and job tracking.',
  'Background analysis jobs with progress polling for large files and asynchronous workflows.',
  'Random Forest training and model version loading endpoints for iterative detection improvements.',
];

function AboutPage() {
  return (
    <div className="hp about-shell">

      {/* Hero */}
      <section className="hp-hero">
        <div className="hp-hero-inner">
          <p className="hp-kicker">About AegisFA</p>
          <h1 className="hp-hero-title">
            Comprehensive Security Log Analysis for Investigation Teams
          </h1>
          <p className="hp-hero-sub">
            AegisFA is an end-to-end security analytics platform built to help SOC and incident response teams move from raw telemetry to actionable decisions. The project combines ingestion, correlation, machine-assisted analysis, MITRE mapping, and timeline reconstruction in a single workflow.
          </p>
          <div className="hp-hero-actions">
            <Link to="/dashboard" className="hp-btn hp-btn-primary">Open Dashboard</Link>
            <Link to="/support" className="hp-btn hp-btn-secondary">Visit Support</Link>
          </div>
        </div>
        <div className="hp-hero-glow" aria-hidden="true" />
      </section>

      {/* Platform Capabilities */}
      <section>
        <header className="hp-section-header">
          <p className="hp-kicker">Platform Capabilities</p>
          <h2>Everything Analysts Need in One Workflow</h2>
          <p className="hp-section-sub">
            From log ingestion to remediation guidance, AegisFA covers the full investigation lifecycle.
          </p>
        </header>
      </section>

      <section>
        <div className="hp-features-grid about-cap-grid">
          {platformCapabilities.map((cap) => (
            <article key={cap.title} className="hp-feature-card">
              <h3>{cap.title}</h3>
              <p>{cap.description}</p>
            </article>
          ))}
        </div>
      </section>

      {/* How It Works */}
      <section className="hp-stats">
        <header className="hp-section-header" style={{ marginBottom: 'var(--spacing-lg)' }}>
          <p className="hp-kicker">Investigation Pipeline</p>
          <h2>How the System Works</h2>
        </header>
        <div className="about-steps">
          {workflowSteps.map((step) => (
            <div key={step.num} className="about-step">
              <span className="about-step-num">{step.num}</span>
              <p>{step.text}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Architecture */}
      <section className="hp-why">
        <header className="hp-section-header">
          <p className="hp-kicker">Under the Hood</p>
          <h2>Architecture Highlights</h2>
        </header>
        <div className="hp-why-grid about-arch-grid">
          {backendHighlights.map((highlight, i) => (
            <article key={i} className="hp-why-card">
              <p>{highlight}</p>
            </article>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="hp-cta">
        <h2>Ready to Explore the Platform?</h2>
        <p>Upload your first log file and see the full analysis pipeline in action.</p>
        <div className="hp-hero-actions">
          <Link to="/dashboard" className="hp-btn hp-btn-primary">Open Dashboard</Link>
          <Link to="/contact" className="hp-btn hp-btn-secondary">Get in Touch</Link>
        </div>
      </section>

    </div>
  );
}

export default AboutPage;
