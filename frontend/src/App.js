import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './services/auth';
import Login from './pages/Login';
import Register from './pages/Register';
import Home from './pages/Home';
import History from './pages/History';
import Admin from './pages/Admin';

function ProtectedRoute({ children }) {
  const { session, loading } = useAuth();
  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', background: '#0a0c0f' }}>
      <div className="spinner" />
    </div>
  );
  if (!session) return <Navigate to="/login" replace />;
  return children;
}

function PublicRoute({ children }) {
  const { session, loading } = useAuth();
  if (loading) return null;
  if (session) return <Navigate to="/home" replace />;
  return children;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Navigate to="/home" replace />} />
          <Route path="/login" element={<PublicRoute><Login /></PublicRoute>} />
          <Route path="/register" element={<PublicRoute><Register /></PublicRoute>} />
          <Route path="/home" element={<ProtectedRoute><Home /></ProtectedRoute>} />
          <Route path="/history" element={<ProtectedRoute><History /></ProtectedRoute>} />
          <Route path="/admin" element={<ProtectedRoute><Admin /></ProtectedRoute>} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
