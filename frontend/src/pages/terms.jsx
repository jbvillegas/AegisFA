import { Link } from 'react-router-dom';
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
    <section className="panel terms-page" aria-labelledby="terms-title">
      <header className="terms-hero">
        <p className="terms-kicker">Terms</p>
        <h1 id="terms-title">Terms of Use for AegisFA</h1>
        <p>
          These Terms define acceptable use and operational boundaries for the AegisFA platform,
          including ingestion workflows, analysis outputs, timeline intelligence, and support channels.
        </p>
      </header>

      <section className="terms-section" aria-labelledby="acceptance-title">
        <h2 id="acceptance-title">Acceptance and Scope</h2>
        <ul className="terms-list">
          {acceptancePoints.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </section>

      <section className="terms-section" aria-labelledby="use-title">
        <h2 id="use-title">Permitted and Prohibited Use</h2>
        <div className="terms-two-col">
          <article className="terms-card">
            <h3>Permitted Use</h3>
            <ul className="terms-list compact">
              {permittedUse.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </article>
          <article className="terms-card">
            <h3>Prohibited Use</h3>
            <ul className="terms-list compact">
              {prohibitedUse.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </article>
        </div>
      </section>

      <section className="terms-section" aria-labelledby="boundaries-title">
        <h2 id="boundaries-title">Service Boundaries</h2>
        <ul className="terms-list">
          {serviceBoundaries.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </section>

      <section className="terms-section" aria-labelledby="liability-title">
        <h2 id="liability-title">Disclaimers and Liability</h2>
        <ul className="terms-list">
          {liabilityPoints.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </section>

      <section className="terms-section" aria-labelledby="termination-title">
        <h2 id="termination-title">Suspension, Changes, and Termination</h2>
        <ul className="terms-list">
          {terminationPoints.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </section>

      <section className="terms-section terms-cta" aria-labelledby="terms-next-title">
        <h2 id="terms-next-title">Related Pages</h2>
        <p>
          Review Privacy for data handling context and Support for runbooks, diagnostics, and escalation guidance.
        </p>
        <div className="terms-actions">
          <Link className="terms-btn primary" to="/privacy">Open Privacy</Link>
          <Link className="terms-btn secondary" to="/support">Open Support</Link>
          <Link className="terms-btn secondary" to="/contact">Open Contact</Link>
        </div>
      </section>
    </section>
  );
}

export default TermsPage;
