import { useEffect, useState } from 'react';
import './css/index.css';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { supabase } from './client.js';
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
import CollaborativeWorkspacePage from './pages/collaborative-workspace.jsx';
import AIFeedbackPage from './pages/ai-feedback.jsx';
import Login from './pages/login.jsx';
import RemediationView from './pages/remediation-view.jsx';

function ProtectedRoute({ children, adminOnly }) {
  const [authState, setAuthState] = useState('loading');
  const [isAdmin, setIsAdmin] = useState(false);

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      if (!session) {
        setAuthState('unauthenticated');
        return;
      }
      const role = session.user?.app_metadata?.role || session.user?.user_metadata?.role || 'user';
      setIsAdmin(role === 'admin');
      setAuthState('authenticated');
    });
  }, []);

  if (authState === 'loading') return null;
  if (authState === 'unauthenticated') return <Navigate to="/login" replace />;
  if (adminOnly && !isAdmin) return <Navigate to="/dashboard" replace />;
  return children;
}

function ScrollToTop() {
  const { pathname } = useLocation();

  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: 'auto' });
  }, [pathname]);

  return null;
}


function App() {
  return (
    <>
      <ScrollToTop />
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
            <Route path="/dashboard" element={<ProtectedRoute><DashboardPage /></ProtectedRoute>} />
            <Route path="/workspace" element={<ProtectedRoute><CollaborativeWorkspacePage /></ProtectedRoute>} />
            <Route path="/feedback" element={<ProtectedRoute><AIFeedbackPage /></ProtectedRoute>} />
            <Route path="/admin" element={<ProtectedRoute adminOnly><AdminDashboard /></ProtectedRoute>} />
            <Route path="/remediation-view/:remediationId" element={<ProtectedRoute><RemediationView /></ProtectedRoute>} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
        <Footer />
      </div>
    </>
  );
}

export default App;