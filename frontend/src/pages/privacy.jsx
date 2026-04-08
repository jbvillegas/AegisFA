import { Link } from 'react-router-dom';
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
    <section className="panel privacy-page" aria-labelledby="privacy-title">
      <header className="privacy-hero">
        <p className="privacy-kicker">Privacy</p>
        <h1 id="privacy-title">Privacy and Data Handling in AegisFA</h1>
        <p>
          This page describes how project data is handled across ingestion, analysis, storage, and support workflows.
          It is written to reflect the current codebase behavior and operational architecture.
        </p>
      </header>

      <section className="privacy-section" aria-labelledby="categories-title">
        <h2 id="categories-title">Data Categories Processed</h2>
        <div className="privacy-grid">
          {dataCategories.map((item) => (
            <article className="privacy-card" key={item.title}>
              <h3>{item.title}</h3>
              <p>{item.details}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="privacy-section" aria-labelledby="purposes-title">
        <h2 id="purposes-title">Why Data Is Processed</h2>
        <ul className="privacy-list">
          {processingPurposes.map((purpose) => (
            <li key={purpose}>{purpose}</li>
          ))}
        </ul>
      </section>

      <section className="privacy-section" aria-labelledby="controls-title">
        <h2 id="controls-title">Security and Access Controls</h2>
        <ul className="privacy-list">
          {controls.map((control) => (
            <li key={control}>{control}</li>
          ))}
        </ul>
      </section>

      <section className="privacy-section" aria-labelledby="third-party-title">
        <h2 id="third-party-title">Third-Party Services</h2>
        <div className="privacy-third-party-grid">
          {thirdParties.map((service) => (
            <article className="privacy-third-party-card" key={service.name}>
              <h3>{service.name}</h3>
              <p>{service.role}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="privacy-section" aria-labelledby="responsibilities-title">
        <h2 id="responsibilities-title">Operator Responsibilities</h2>
        <ul className="privacy-list">
          {userResponsibilities.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </section>

      <section className="privacy-section privacy-cta" aria-labelledby="privacy-next-title">
        <h2 id="privacy-next-title">Need Clarification?</h2>
        <p>
          For policy clarifications or incident-specific concerns, use the Support and Contact pages with your request ID and relevant endpoint context.
        </p>
        <div className="privacy-actions">
          <Link className="privacy-btn primary" to="/support">Open Support</Link>
          <Link className="privacy-btn secondary" to="/contact">Open Contact</Link>
          <Link className="privacy-btn secondary" to="/about">Project Overview</Link>
        </div>
      </section>
    </section>
  );
}

export default PrivacyPage;
