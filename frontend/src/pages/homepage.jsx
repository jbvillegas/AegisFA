import { Link } from 'react-router-dom';
import '../css/homepage.css';

function HomePage() {
  return (
    <section className="homepage intro-homepage">
      <section className="hero intro-hero" aria-labelledby="hero-title">
        <div className="hero-content">
          <p className="panel-kicker">AegisFA</p>
          <h1 id="hero-title">Forensic Assistant for Security Operations</h1>
          <p className="hero-subtitle">
            We help security teams ingest logs, detect threats, map findings to MITRE ATT&CK, and turn analysis into actionable response.
          </p>
          <div className="hero-actions">
            <Link to="/dashboard" className="hero-btn primary">Go to Dashboard</Link>
            <Link to="/login" className="hero-btn secondary">Sign In</Link>
          </div>
        </div>
      </section>

      <section className="content-area intro-content" aria-labelledby="intro-title">
        <header>
          <p>What We Do</p>
          <h2 id="intro-title">Security analytics built for investigation speed</h2>
          <p>
            AegisFA centralizes log uploads, automated threat analysis, and investigation context so teams can move from alert to decision faster.
          </p>
        </header>

        <section aria-labelledby="capabilities-title">
          <h2 id="capabilities-title">Core Capabilities</h2>
          <ul>
            <li>Log ingestion and normalization for common security sources</li>
            <li>Threat classification and correlation-backed detection</li>
            <li>MITRE mapping, timeline context, and investigation guidance</li>
          </ul>
        </section>
      </section>
    </section>
  );
}

export default HomePage;
