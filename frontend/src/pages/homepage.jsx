import { Link } from 'react-router-dom';
import '../css/homepage.css';

function HomePage() {
  return (
    <div className="hp">

      {/* ── Hero ── */}
      <section className="hp-hero">
        <div className="hp-hero-inner">
          <p className="hp-kicker">AegisFA Platform</p>
          <h1 className="hp-hero-title">
            AI-Powered Forensic Analysis for the Modern SOC
          </h1>
          <p className="hp-hero-sub">
            Autonomous threat investigation, MITRE ATT&CK mapping, and remediation guidance — from raw logs to analyst-ready intelligence in minutes.
          </p>
          <div className="hp-hero-actions">
            <Link to="/dashboard" className="hp-btn hp-btn-primary">Open Dashboard</Link>
            <Link to="/login" className="hp-btn hp-btn-secondary">Request Access</Link>
          </div>
        </div>
        <div className="hp-hero-glow" aria-hidden="true" />
      </section>

      {/* ── Trust logos ── */}
      <section className="hp-trust">
        <p className="hp-trust-label">Built With Industry-Leading Technology</p>
        <div className="hp-trust-logos">
          <span>Supabase</span>
          <span>OpenAI</span>
          <span>MITRE ATT&CK</span>
          <span>CICIDS</span>
          <span>pgvector</span>
          <span>Flask</span>
          <span>React</span>
        </div>
      </section>

      {/* ── Platform overview ── */}
      <section className="hp-overview">
        <header className="hp-section-header">
          <p className="hp-kicker">Platform Overview</p>
          <h2>End-to-End Security Operations Lifecycle</h2>
          <p className="hp-section-sub">
            From initial log ingestion to completed incident report, AegisFA automates every stage of the forensic analysis pipeline.
          </p>
        </header>
      </section>

      {/* ── Core features — 3-column cards ── */}
      <section className="hp-features">
        <div className="hp-features-grid">
          <article className="hp-feature-card">
            <div className="hp-feature-icon hp-feature-icon-ingest" aria-hidden="true" />
            <h3>Ingest &amp; Classify</h3>
            <p>
              Upload CSV, JSON, or text logs. The RF classifier categorizes every entry across 25+ attack classes with calibrated probability scores.
            </p>
          </article>
          <article className="hp-feature-card">
            <div className="hp-feature-icon hp-feature-icon-investigate" aria-hidden="true" />
            <h3>Investigate &amp; Correlate</h3>
            <p>
              Correlation rules fire across your data while GPT-4o-mini generates threat findings. MITRE techniques are matched via semantic vector search.
            </p>
          </article>
          <article className="hp-feature-card">
            <div className="hp-feature-icon hp-feature-icon-respond" aria-hidden="true" />
            <h3>Respond &amp; Remediate</h3>
            <p>
              Receive a confidence-scored verdict, timeline graph, and step-by-step remediation plan ready to hand off to your response team.
            </p>
          </article>
        </div>
      </section>

      {/* ── Why analysts choose AegisFA — 4-column value props ── */}
      <section className="hp-why">
        <header className="hp-section-header">
          <p className="hp-kicker">Why Teams Choose AegisFA</p>
          <h2>Built for Analysts Who Need Clarity Under Pressure</h2>
        </header>
        <div className="hp-why-grid">
          <article className="hp-why-card">
            <h3>Confidence Scoring</h3>
            <p>Every prediction carries a transparent multi-signal confidence score blending RF classification, MITRE retrieval, LLM analysis, and correlation evidence.</p>
          </article>
          <article className="hp-why-card">
            <h3>Full Transparency</h3>
            <p>Inspect every verdict source — RF risk breakdown, MITRE similarity scores, correlation rule matches, and the LLM reasoning chain.</p>
          </article>
          <article className="hp-why-card">
            <h3>MITRE ATT&CK Native</h3>
            <p>Semantic vector search over the full ATT&CK knowledge base maps findings to techniques, tactics, and sub-techniques automatically.</p>
          </article>
          <article className="hp-why-card">
            <h3>Adaptive Learning</h3>
            <p>Retrain the RF model on your own data, tune correlation rules per org, and feed analyst feedback back into the pipeline.</p>
          </article>
        </div>
      </section>

      {/* ── Stats / Social proof ── */}
      <section className="hp-stats">
        <div className="hp-stats-grid">
          <div className="hp-stat">
            <span className="hp-stat-value">90%+</span>
            <span className="hp-stat-label">Prediction Confidence</span>
          </div>
          <div className="hp-stat">
            <span className="hp-stat-value">25</span>
            <span className="hp-stat-label">Attack Classes Detected</span>
          </div>
          <div className="hp-stat">
            <span className="hp-stat-value">&lt; 3 min</span>
            <span className="hp-stat-label">Log to Verdict</span>
          </div>
          <div className="hp-stat">
            <span className="hp-stat-value">100%</span>
            <span className="hp-stat-label">Alert Coverage</span>
          </div>
        </div>
      </section>

      {/* ── Capabilities detail — alternating rows ── */}
      <section className="hp-details">
        <div className="hp-detail-row">
          <div className="hp-detail-text">
            <p className="hp-kicker">AI SOC Analyst</p>
            <h3>Automated Threat Investigation</h3>
            <p>
              Upload a log file and AegisFA builds an investigation plan autonomously — classifying entries, correlating patterns, retrieving relevant MITRE techniques, and generating an incident summary with confidence-scored findings.
            </p>
          </div>
          <div className="hp-detail-visual">
            <div className="hp-detail-mock">
              <div className="hp-mock-bar" />
              <div className="hp-mock-line w80" />
              <div className="hp-mock-line w60" />
              <div className="hp-mock-line w90" />
              <div className="hp-mock-line w45" />
            </div>
          </div>
        </div>

        <div className="hp-detail-row hp-detail-row-reverse">
          <div className="hp-detail-text">
            <p className="hp-kicker">Timeline &amp; Graph</p>
            <h3>Visual Investigation Context</h3>
            <p>
              The interactive timeline graph links raw events, correlation detections, and AI-generated narrative nodes chronologically — giving analysts a visual map of the attack chain.
            </p>
          </div>
          <div className="hp-detail-visual">
            <div className="hp-detail-mock">
              <div className="hp-mock-dots">
                <span className="hp-dot hp-dot-event" />
                <span className="hp-dot hp-dot-detection" />
                <span className="hp-dot hp-dot-narrative" />
                <span className="hp-dot hp-dot-event" />
                <span className="hp-dot hp-dot-detection" />
              </div>
              <div className="hp-mock-line w70" />
              <div className="hp-mock-line w55" />
            </div>
          </div>
        </div>
      </section>

      {/* ── CTA ── */}
      <section className="hp-cta">
        <h2>Start Investigating with AegisFA</h2>
        <p>Upload your first log file and get a confidence-scored threat analysis in minutes.</p>
        <div className="hp-hero-actions">
          <Link to="/dashboard" className="hp-btn hp-btn-primary">Open Dashboard</Link>
          <Link to="/about" className="hp-btn hp-btn-secondary">Learn More</Link>
        </div>
      </section>

    </div>
  );
}

export default HomePage;
