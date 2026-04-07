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
              <li><Link to="/dashboard">Dashboard</Link></li>
              <li><Link to="/admin">Admin</Link></li>
            </ul>
          </div>
          <div className="footer-section">
            <h4 className="footer-heading">Resources</h4>
            <ul className="footer-list">
              <li><a href="#" className="footer-link">About</a></li>
              <li><a href="#" className="footer-link">Support</a></li>
              <li><a href="#" className="footer-link">Contact</a></li>
            </ul>
          </div>
          <div className="footer-section">
            <h4 className="footer-heading">Legal</h4>
            <ul className="footer-list">
              <li><a href="#" className="footer-link">Privacy</a></li>
              <li><a href="#" className="footer-link">Terms</a></li>
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