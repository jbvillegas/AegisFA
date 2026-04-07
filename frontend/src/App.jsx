import './css/index.css';
import { Navigate, Route, Routes } from 'react-router-dom';
import Navbar from './components/navbar.jsx';
import Footer from './components/footer.jsx';
import AdminDashboard from './pages/admindashboard.jsx';
import HomePage from './pages/homepage.jsx';
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