import { Link } from 'react-router-dom';
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
    <section className="panel contact-page" aria-labelledby="contact-title">
      <header className="contact-hero">
        <p className="contact-kicker">Contact</p>
        <h1 id="contact-title">Get Help, Escalate Issues, and Reach the Right Team</h1>
        <p>
          This contact center is aligned to the AegisFA operating workflow. Use it to route support, escalation,
          and access requests with the exact technical context needed for fast resolution.
        </p>
      </header>

      <section className="contact-section" aria-labelledby="channels-title">
        <h2 id="channels-title">Contact Paths</h2>
        <div className="contact-grid">
          {contactChannels.map((channel) => (
            <article key={channel.title} className="contact-card">
              <h3>{channel.title}</h3>
              <p><strong>Who:</strong> {channel.audience}</p>
              <p>{channel.details}</p>
              <Link className="contact-card-link" to={channel.routeTo}>{channel.routeLabel}</Link>
            </article>
          ))}
        </div>
      </section>

      <section className="contact-section" aria-labelledby="required-context-title">
        <h2 id="required-context-title">Include This in Every Request</h2>
        <ul className="contact-list">
          {requiredContext.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </section>

      <section className="contact-section" aria-labelledby="severity-title">
        <h2 id="severity-title">Severity and Response Expectations</h2>
        <div className="contact-severity-grid">
          {severityGuide.map((item) => (
            <article key={item.level} className="contact-severity-card">
              <h3>{item.level}</h3>
              <p><strong>Impact:</strong> {item.impact}</p>
              <p><strong>Response:</strong> {item.response}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="contact-section contact-cta" aria-labelledby="next-actions-title">
        <h2 id="next-actions-title">Next Actions</h2>
        <div className="contact-actions">
          <Link className="contact-btn primary" to="/support">Open Support Playbook</Link>
          <Link className="contact-btn secondary" to="/about">View Project Overview</Link>
          <Link className="contact-btn secondary" to="/dashboard">Return to Dashboard</Link>
        </div>
      </section>
    </section>
  );
}

export default ContactPage;
