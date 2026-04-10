import { Link } from 'react-router-dom';
import '../css/homepage.css';
import '../css/privacy.css';

const dataCategories = [
  {
    title: 'Log and Event Data',
    details:
      'Uploaded security logs, parsed events, normalized fields, and derived detections used for investigation workflows.',
  },
  {
    title: 'Analysis Artifacts',
    details:
      'Threat summaries, findings, timeline entries, remediation guidance, model outputs, and ATT&CK mappings generated during analysis.',
  },
  {
    title: 'Operational Metadata',
    details:
      'Job IDs, request IDs, file IDs, status/progress markers, timestamps, and system diagnostics used for monitoring and troubleshooting.',
  },
  {
    title: 'Account Context',
    details:
      'User identity fields and organization scoping metadata required for access control, data isolation, and role-based workflows.',
  },
];

const processingPurposes = [
  'Ingest and parse uploaded telemetry into analyzable structures.',
  'Detect suspicious activity through correlation and model-assisted classification.',
  'Generate analyst-facing intelligence such as summaries, timelines, and remediation actions.',
  'Operate dashboards, search experiences, and job-status polling.',
  'Maintain reliability, auditability, and incident support diagnostics.',
];

const controls = [
  'Organization-scoped data access patterns across frontend and backend flows.',
  'Backend validation for request payloads and identifier integrity.',
  'Request-level tracing with request_id values for support and investigation.',
  'Row-level access concepts in the database layer for tenant isolation policies.',
  'Operational logging for error triage and service stability improvements.',
];

const thirdParties = [
  {
    name: 'Supabase',
    role: 'Database, storage, and auth-adjacent data services.',
  },
  {
    name: 'Model and Analysis Providers',
    role: 'Security analysis and classification support depending on configured backend services.',
  },
];

const userResponsibilities = [
  'Upload only data your organization is authorized to process.',
  'Avoid including unnecessary personal data in log payloads when possible.',
  'Handle exported analysis outputs according to your internal retention policies.',
  'Report suspected data exposure immediately through the Contact and Support channels.',
];

function PrivacyPage() {
  return (
    <div className="hp privacy-shell">

      {/* Hero */}
      <section className="hp-hero">
        <div className="hp-hero-inner">
          <p className="hp-kicker">Privacy</p>
          <h1 className="hp-hero-title">
            Privacy and Data Handling in AegisFA
          </h1>
          <p className="hp-hero-sub">
            This page describes how project data is handled across ingestion, analysis, storage, and support workflows. It reflects the current codebase behavior and operational architecture.
          </p>
        </div>
        <div className="hp-hero-glow" aria-hidden="true" />
      </section>

      {/* Data Categories */}
      <section>
        <header className="hp-section-header">
          <p className="hp-kicker">Data Scope</p>
          <h2>Data Categories Processed</h2>
        </header>
      </section>

      <section>
        <div className="hp-why-grid privacy-cat-grid">
          {dataCategories.map((item) => (
            <article className="hp-why-card" key={item.title}>
              <h3>{item.title}</h3>
              <p>{item.details}</p>
            </article>
          ))}
        </div>
      </section>

      {/* Processing Purposes */}
      <section className="hp-stats">
        <header className="hp-section-header" style={{ marginBottom: 'var(--spacing-lg)' }}>
          <p className="hp-kicker">Purpose</p>
          <h2>Why Data Is Processed</h2>
        </header>
        <div className="privacy-list-grid">
          {processingPurposes.map((purpose, i) => (
            <div key={i} className="privacy-list-item">
              <span className="privacy-list-num">{String(i + 1).padStart(2, '0')}</span>
              <p>{purpose}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Controls */}
      <section className="hp-why">
        <header className="hp-section-header">
          <p className="hp-kicker">Safeguards</p>
          <h2>Security and Access Controls</h2>
        </header>
        <div className="hp-why-grid privacy-controls-grid">
          {controls.map((control, i) => (
            <article key={i} className="hp-why-card">
              <p>{control}</p>
            </article>
          ))}
        </div>
      </section>

      {/* Third Parties */}
      <section>
        <header className="hp-section-header">
          <p className="hp-kicker">Integrations</p>
          <h2>Third-Party Services</h2>
        </header>
      </section>

      <section>
        <div className="privacy-third-grid">
          {thirdParties.map((service) => (
            <article className="hp-feature-card" key={service.name}>
              <h3>{service.name}</h3>
              <p>{service.role}</p>
            </article>
          ))}
        </div>
      </section>

      {/* Responsibilities */}
      <section className="hp-why">
        <header className="hp-section-header">
          <p className="hp-kicker">Your Role</p>
          <h2>Operator Responsibilities</h2>
        </header>
        <div className="hp-why-grid privacy-resp-grid">
          {userResponsibilities.map((item, i) => (
            <article key={i} className="hp-why-card">
              <p>{item}</p>
            </article>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="hp-cta">
        <h2>Need Clarification?</h2>
        <p>For policy clarifications or incident-specific concerns, use the Support and Contact pages with your request ID and relevant endpoint context.</p>
        <div className="hp-hero-actions">
          <Link to="/support" className="hp-btn hp-btn-primary">Open Support</Link>
          <Link to="/contact" className="hp-btn hp-btn-secondary">Open Contact</Link>
          <Link to="/about" className="hp-btn hp-btn-secondary">Project Overview</Link>
        </div>
      </section>

    </div>
  );
}

export default PrivacyPage;
