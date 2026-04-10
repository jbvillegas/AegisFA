import { Link } from 'react-router-dom';
import '../css/homepage.css';
import '../css/contact.css';

const contactChannels = [
  {
    title: 'Platform Support Requests',
    audience: 'Analysts and operators needing workflow help',
    details:
      'Use the Support page runbook first, then submit a request with request_id, endpoint, status code, and org/file context.',
    routeLabel: 'Open Support Guide',
    routeTo: '/support',
  },
  {
    title: 'Incident Escalation',
    audience: 'Critical ingestion, analysis, or timeline outages',
    details:
      'Escalate with impact scope, affected endpoints, start time, and latest backend/frontend logs so triage can begin immediately.',
    routeLabel: 'Open Admin View',
    routeTo: '/admin',
  },
  {
    title: 'Data and Access Questions',
    audience: 'Org context, Supabase access, or permissions issues',
    details:
      'Include organization ID, user ID, failing operation, and whether the issue is read visibility (RLS) or write constraints.',
    routeLabel: 'Open Dashboard',
    routeTo: '/dashboard',
  },
];

const requiredContext = [
  'Request ID and timestamp from backend response payload or logs.',
  'API endpoint and HTTP status code involved in the failure.',
  'Organization ID, file ID, and job ID (if applicable).',
  'Frontend console error + network response body.',
  'Last known successful action before the issue occurred.',
];

const severityGuide = [
  {
    level: 'P1 - Critical',
    impact: 'Core workflow unavailable (upload, analysis, or timeline blocked for active operations).',
    response: 'Immediate triage and continuous updates until containment.',
  },
  {
    level: 'P2 - High',
    impact: 'Major feature degraded with workaround available.',
    response: 'Rapid triage during same operating window.',
  },
  {
    level: 'P3 - Medium',
    impact: 'Functional issue with limited user/business impact.',
    response: 'Prioritized for scheduled fix cycle.',
  },
  {
    level: 'P4 - Low',
    impact: 'Minor UX/content issue or enhancement request.',
    response: 'Backlog review and planned iteration.',
  },
];

function ContactPage() {
  return (
    <div className="hp contact-shell">

      {/* Hero */}
      <section className="hp-hero">
        <div className="hp-hero-inner">
          <p className="hp-kicker">Contact</p>
          <h1 className="hp-hero-title">
            Get Help, Escalate Issues, and Reach the Right Team
          </h1>
          <p className="hp-hero-sub">
            This contact center is aligned to the AegisFA operating workflow. Use it to route support, escalation, and access requests with the exact technical context needed for fast resolution.
          </p>
        </div>
        <div className="hp-hero-glow" aria-hidden="true" />
      </section>

      {/* Contact Paths */}
      <section>
        <header className="hp-section-header">
          <p className="hp-kicker">Reach Out</p>
          <h2>Contact Paths</h2>
        </header>
      </section>

      <section>
        <div className="hp-features-grid">
          {contactChannels.map((channel) => (
            <article key={channel.title} className="hp-feature-card">
              <h3>{channel.title}</h3>
              <p><strong>Who:</strong> {channel.audience}</p>
              <p>{channel.details}</p>
              <Link className="contact-card-link" to={channel.routeTo}>{channel.routeLabel}</Link>
            </article>
          ))}
        </div>
      </section>

      {/* Required Context */}
      <section className="hp-why">
        <header className="hp-section-header">
          <p className="hp-kicker">Context</p>
          <h2>Include This in Every Request</h2>
        </header>
        <div className="hp-why-grid contact-context-grid">
          {requiredContext.map((item, i) => (
            <article key={i} className="hp-why-card">
              <p>{item}</p>
            </article>
          ))}
        </div>
      </section>

      {/* Severity Guide */}
      <section>
        <header className="hp-section-header">
          <p className="hp-kicker">Response SLAs</p>
          <h2>Severity and Response Expectations</h2>
        </header>
      </section>

      <section>
        <div className="contact-severity-grid">
          {severityGuide.map((item) => (
            <article key={item.level} className="hp-feature-card">
              <h3>{item.level}</h3>
              <p><strong>Impact:</strong> {item.impact}</p>
              <p><strong>Response:</strong> {item.response}</p>
            </article>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="hp-cta">
        <h2>Next Actions</h2>
        <p>Review the support playbook, explore the project overview, or return to your dashboard.</p>
        <div className="hp-hero-actions">
          <Link to="/support" className="hp-btn hp-btn-primary">Open Support Playbook</Link>
          <Link to="/about" className="hp-btn hp-btn-secondary">View Project Overview</Link>
          <Link to="/dashboard" className="hp-btn hp-btn-secondary">Return to Dashboard</Link>
        </div>
      </section>

    </div>
  );
}

export default ContactPage;
