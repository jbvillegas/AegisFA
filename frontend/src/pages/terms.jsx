import { Link } from 'react-router-dom';
import '../css/homepage.css';
import '../css/terms.css';

const acceptancePoints = [
  'By using AegisFA, you confirm authority to upload and process the provided security telemetry.',
  'You are responsible for complying with your organizational and legal obligations for data handling.',
  'Use of this platform is subject to these Terms and the Privacy page guidance.',
];

const permittedUse = [
  'Security monitoring, threat triage, incident investigation, and remediation planning.',
  'Testing and operational validation in environments you are authorized to assess.',
  'Use of generated insights as analyst assistance, not as sole decision authority.',
];

const prohibitedUse = [
  'Uploading data you do not have rights to process.',
  'Attempting to disrupt service availability, bypass controls, or access unauthorized org data.',
  'Relying on output for unlawful activities or non-security abuse cases.',
];

const serviceBoundaries = [
  'Analysis output is assistive and may include uncertainty; human review remains required.',
  'Availability can depend on backend services, model state, storage access, and infrastructure limits.',
  'Certain features may change as the project evolves (routes, models, and integration behavior).',
];

const liabilityPoints = [
  'AegisFA is provided as-is for operational support and development workflows.',
  'The platform does not guarantee prevention, detection, or elimination of all threats.',
  'Users are accountable for final incident response decisions and downstream actions.',
];

const terminationPoints = [
  'Access may be suspended for abuse, policy violations, or security risk.',
  'Service features may be modified, restricted, or retired as needed for reliability and safety.',
  'Data handling post-termination follows your configured storage and governance processes.',
];

function TermsPage() {
  return (
    <div className="hp">

      {/* Hero */}
      <section className="hp-hero">
        <div className="hp-hero-inner">
          <p className="hp-kicker">Terms</p>
          <h1 className="hp-hero-title">
            Terms of Use for AegisFA
          </h1>
          <p className="hp-hero-sub">
            These Terms define acceptable use and operational boundaries for the AegisFA platform, including ingestion workflows, analysis outputs, timeline intelligence, and support channels.
          </p>
        </div>
        <div className="hp-hero-glow" aria-hidden="true" />
      </section>

      {/* Acceptance */}
      <section className="hp-why">
        <header className="hp-section-header">
          <p className="hp-kicker">Agreement</p>
          <h2>Acceptance and Scope</h2>
        </header>
        <div className="hp-features-grid terms-accept-grid">
          {acceptancePoints.map((item, i) => (
            <article key={i} className="hp-feature-card">
              <p>{item}</p>
            </article>
          ))}
        </div>
      </section>

      {/* Permitted / Prohibited */}
      <section>
        <header className="hp-section-header">
          <p className="hp-kicker">Usage Policy</p>
          <h2>Permitted and Prohibited Use</h2>
        </header>
      </section>

      <section>
        <div className="terms-use-grid">
          <article className="hp-feature-card terms-use-card">
            <h3>Permitted Use</h3>
            <ul className="terms-list">
              {permittedUse.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </article>
          <article className="hp-feature-card terms-use-card terms-prohibited">
            <h3>Prohibited Use</h3>
            <ul className="terms-list">
              {prohibitedUse.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </article>
        </div>
      </section>

      {/* Service Boundaries */}
      <section className="hp-why">
        <header className="hp-section-header">
          <p className="hp-kicker">Expectations</p>
          <h2>Service Boundaries</h2>
        </header>
        <div className="hp-features-grid terms-boundary-grid">
          {serviceBoundaries.map((item, i) => (
            <article key={i} className="hp-feature-card">
              <p>{item}</p>
            </article>
          ))}
        </div>
      </section>

      {/* Liability */}
      <section className="hp-stats">
        <header className="hp-section-header" style={{ marginBottom: 'var(--spacing-lg)' }}>
          <p className="hp-kicker">Legal</p>
          <h2>Disclaimers and Liability</h2>
        </header>
        <div className="terms-liability-grid">
          {liabilityPoints.map((item, i) => (
            <div key={i} className="terms-liability-item">
              <span className="terms-liability-num">{String(i + 1).padStart(2, '0')}</span>
              <p>{item}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Termination */}
      <section className="hp-why">
        <header className="hp-section-header">
          <p className="hp-kicker">Enforcement</p>
          <h2>Suspension, Changes, and Termination</h2>
        </header>
        <div className="hp-features-grid terms-term-grid">
          {terminationPoints.map((item, i) => (
            <article key={i} className="hp-feature-card">
              <p>{item}</p>
            </article>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="hp-cta">
        <h2>Related Pages</h2>
        <p>Review Privacy for data handling context and Support for runbooks, diagnostics, and escalation guidance.</p>
        <div className="hp-hero-actions">
          <Link to="/privacy" className="hp-btn hp-btn-primary">Open Privacy</Link>
          <Link to="/support" className="hp-btn hp-btn-secondary">Open Support</Link>
          <Link to="/contact" className="hp-btn hp-btn-secondary">Open Contact</Link>
        </div>
      </section>

    </div>
  );
}

export default TermsPage;
