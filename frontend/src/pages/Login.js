import { useState } from 'react';
import { useAuth } from '../services/auth';
import { Link, useNavigate } from 'react-router-dom';
import { FaShieldAlt } from 'react-icons/fa';

export default function Login() {
  const { signIn } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setError('');
    const { error } = await signIn(email, password);
    if (error) {
      setError('Invalid credentials. Access denied.');
      setLoading(false);
    } else {
      navigate('/home');
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', padding: '2rem', background: 'var(--bg)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '10px' }}>
        <div style={{ width: '56px', height: '56px', background: 'var(--accent-dim)', border: '1.5px solid var(--accent)', borderRadius: '14px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <FaShieldAlt style={{ color: 'var(--accent)', width: '28px', height: '28px' }} />
        </div>
        <h1 style={{ fontSize: '34px', fontWeight: '800', color: 'var(--text)', letterSpacing: '-1px' }}>
          Aegis<span style={{ color: 'var(--accent)' }}>FA</span>
        </h1>
      </div>
      <p style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--muted)', letterSpacing: '3px', textTransform: 'uppercase', marginBottom: '2.5rem' }}>
        Forensic Intelligence Platform
      </p>

      <div className="card" style={{ width: '100%', maxWidth: '400px', padding: '2.25rem' }}>
        <h2 style={{ fontSize: '16px', fontWeight: '600', color: 'var(--text)', marginBottom: '1.75rem' }}>Secure Access</h2>

        {error && (
          <div style={{ background: 'var(--red-dim)', border: '1px solid var(--red-border)', color: 'var(--red)', fontSize: '12px', padding: '10px 14px', borderRadius: '7px', marginBottom: '1.25rem', fontFamily: 'var(--mono)' }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div>
            <label style={{ display: 'block', fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '1.5px', marginBottom: '7px' }}>Analyst ID</label>
            <input className="input" type="email" required value={email} onChange={e => setEmail(e.target.value)} placeholder="analyst@org.com" />
          </div>
          <div>
            <label style={{ display: 'block', fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '1.5px', marginBottom: '7px' }}>Passphrase</label>
            <input className="input" type="password" required value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••••••" />
          </div>
          <button className="btn btn-primary" type="submit" disabled={loading} style={{ marginTop: '0.5rem', width: '100%', justifyContent: 'center', padding: '12px' }}>
            {loading ? 'Authenticating...' : 'Authenticate'}
          </button>
        </form>

        <p style={{ textAlign: 'center', fontSize: '12px', color: 'var(--muted)', marginTop: '1.5rem', fontFamily: 'var(--mono)' }}>
          No account? <Link to="/register" style={{ color: 'var(--accent)', textDecoration: 'none' }}>Request access</Link>
        </p>
        <p style={{ textAlign: 'center', fontSize: '10px', color: '#3a3f47', marginTop: '0.75rem', fontFamily: 'var(--mono)' }}>
          Unauthorized access is monitored and logged
        </p>
      </div>
    </div>
  );
}
