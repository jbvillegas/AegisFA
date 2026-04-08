import './css/index.css';
import { Navigate, Route, Routes } from 'react-router-dom';
import Navbar from './components/navbar.jsx';
import Footer from './components/footer.jsx';
import AdminDashboard from './pages/admindashboard.jsx';
import HomePage from './pages/homepage.jsx';
import AboutPage from './pages/about.jsx';
import SupportPage from './pages/support.jsx';
import ContactPage from './pages/contact.jsx';
import PrivacyPage from './pages/privacy.jsx';
import TermsPage from './pages/terms.jsx';
import DashboardPage from './pages/dashboard.jsx';
import Login from './pages/login.jsx';
import RemediationView from './pages/remediation-view.jsx';


function App() {
  return (
    <>
      <div className="app-shell">
        <Navbar />
        <main className="page-wrap">
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/about" element={<AboutPage />} />
            <Route path="/support" element={<SupportPage />} />
            <Route path="/contact" element={<ContactPage />} />
            <Route path="/privacy" element={<PrivacyPage />} />
            <Route path="/terms" element={<TermsPage />} />
            <Route path="/login" element={<Login />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/admin" element={<AdminDashboard />} />
            <Route path="/remediation-view/:remediationId" element={<RemediationView />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
        <Footer />
      </div>
    </>
  );
}

export default App;