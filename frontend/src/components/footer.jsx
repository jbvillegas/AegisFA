import { Link } from 'react-router-dom';
import '../css/footer.css';

function Footer() {
  return (
    <footer className="footer">
      <div className="footer-container">
        <div className="footer-grid">
          <div className="footer-section">
            <h3 className="footer-title">AegisFA</h3>
            <p className="footer-text">Forensic Assistant for Security Operations Centers</p>
          </div>
          <div className="footer-section">
            <h4 className="footer-heading">Navigation</h4>
            <ul className="footer-list">
              <li><Link to="/">Home</Link></li>
              <li><Link to="/dashboard">Dashboard</Link></li>
              <li><Link to="/admin">Admin</Link></li>
            </ul>
          </div>
          <div className="footer-section">
            <h4 className="footer-heading">Resources</h4>
            <ul className="footer-list">
              <li><Link to="/about" className="footer-link">About</Link></li>
              <li><Link to="/support" className="footer-link">Support</Link></li>
              <li><Link to="/contact" className="footer-link">Contact</Link></li>
            </ul>
          </div>
          <div className="footer-section">
            <h4 className="footer-heading">Legal</h4>
            <ul className="footer-list">
              <li><Link to="/privacy" className="footer-link">Privacy</Link></li>
              <li><Link to="/terms" className="footer-link">Terms</Link></li>
            </ul>
          </div>
        </div>
        <div className="footer-divider" />
        <div className="footer-bottom">
          <p className="footer-copyright">© 2026 AegisFA. All rights reserved.</p>
        </div>
      </div>
    </footer>
  );
}

export default Footer;