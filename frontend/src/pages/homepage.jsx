import { Link } from 'react-router-dom';
import '../css/homepage.css';

function HomePage() {
  return (
    <section className="homepage intro-homepage">
      <section className="hero intro-hero" aria-labelledby="hero-title">
        <div className="hero-content">
          <p className="panel-kicker">AegisFA</p>
          <h1 id="hero-title">Evidence-Driven Security Operations, Faster</h1>
          <p className="hero-subtitle">
            AegisFA helps analysts turn raw telemetry into reliable decisions through structured ingestion, threat correlation, and investigation-ready context.
          </p>
          <div className="hero-actions" aria-label="Primary navigation">
            <Link to="/dashboard" className="hero-btn primary">Open Dashboard</Link>
            <Link to="/login" className="hero-btn secondary">Analyst Sign In</Link>
          </div>
        </div>
      </section>

      <section className="content-area intro-content" aria-labelledby="intro-title">
        <header>
          <p>Platform Overview</p>
          <h2 id="intro-title">Built for SOC teams that need clarity under pressure</h2>
          <p>
            From initial triage to remediation planning, the platform consolidates technical evidence and presents it in a format analysts can trust and act on.
          </p>
        </header>

        <section aria-labelledby="capabilities-title">
          <h2 id="capabilities-title">Core Capabilities</h2>
          <ul>
            <li>Ingest and normalize event data across common network and endpoint log sources.</li>
            <li>Correlate suspicious activity with model-assisted classification and risk context.</li>
            <li>Map findings to MITRE ATT&CK techniques with timeline-based investigation support.</li>
            <li>Generate remediation guidance that can be handed directly to response teams.</li>
          </ul>
        </section>
      </section>
    </section>
  );
}

export default HomePage;
