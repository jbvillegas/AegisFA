import { useState } from 'react';
import { useAuth } from '../services/auth';
import { Link, useNavigate } from 'react-router-dom';
import { FaShieldAlt } from 'react-icons/fa';
import { supabase } from '../supabaseClient';

const BACKEND = process.env.REACT_APP_BACKEND_URL || 'http://localhost:5001';

export default function Register() {
  const { signUp } = useAuth();
  const navigate = useNavigate();
  const [accessCode, setAccessCode] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    if (password !== confirm) { setError('Passwords do not match'); return; }
    setLoading(true);
    setError('');

    try {
      // Step 1 — validate access code
      const codeRes = await fetch(`${BACKEND}/validate-code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: accessCode.toUpperCase(), email }),
      });

      if (!codeRes.ok) {
        setError('Invalid or already used access code. Contact AegisFA to get access.');
        setLoading(false);
        return;
      }

      const codeData = await codeRes.json();
      const orgId = codeData.org_id;

      // Step 2 — create Supabase account
      const { data, error: signUpError } = await signUp(email, password);
      if (signUpError) throw signUpError;

      // Step 3 — link user to org directly via Supabase
      if (data?.user?.id && orgId) {
        await supabase.from('user_organizations').upsert({
          user_id: data.user.id,
          org_id: orgId,
        });
      }

      setSuccess('Account created! Check your email to confirm, then sign in.');
    } catch (err) {
      setError(err.message || 'Registration failed. Please try again.');
      setLoading(false);
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
        Request Analyst Access
      </p>

      <div className="card" style={{ width: '100%', maxWidth: '420px', padding: '2.25rem' }}>
        <h2 style={{ fontSize: '16px', fontWeight: '600', color: 'var(--text)', marginBottom: '1.75rem' }}>Create Account</h2>

        {error && <div style={{ background: 'var(--red-dim)', border: '1px solid var(--red-border)', color: 'var(--red)', fontSize: '12px', padding: '10px 14px', borderRadius: '7px', marginBottom: '1rem', fontFamily: 'var(--mono)' }}>{error}</div>}
        {success && <div style={{ background: 'var(--accent-dim)', border: '1px solid var(--accent-border)', color: 'var(--accent)', fontSize: '12px', padding: '10px 14px', borderRadius: '7px', marginBottom: '1rem', fontFamily: 'var(--mono)' }}>{success}</div>}

        {!success && (
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div>
              <label style={{ display: 'block', fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '1.5px', marginBottom: '7px' }}>Access Code</label>
              <input className="input" type="text" required value={accessCode} onChange={e => setAccessCode(e.target.value.toUpperCase())} placeholder="AEGIS-XXXX-XXXX" style={{ letterSpacing: '2px' }} />
              <p style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--muted)', marginTop: '5px' }}>Contact AegisFA to receive your access code</p>
            </div>
            <div>
              <label style={{ display: 'block', fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '1.5px', marginBottom: '7px' }}>Analyst ID (Email)</label>
              <input className="input" type="email" required value={email} onChange={e => setEmail(e.target.value)} placeholder="analyst@org.com" />
            </div>
            <div>
              <label style={{ display: 'block', fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '1.5px', marginBottom: '7px' }}>Passphrase</label>
              <input className="input" type="password" required minLength={8} value={password} onChange={e => setPassword(e.target.value)} placeholder="Min. 8 characters" />
            </div>
            <div>
              <label style={{ display: 'block', fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '1.5px', marginBottom: '7px' }}>Confirm Passphrase</label>
              <input className="input" type="password" required minLength={8} value={confirm} onChange={e => setConfirm(e.target.value)} placeholder="Repeat passphrase" />
            </div>
            <button className="btn btn-primary" type="submit" disabled={loading} style={{ marginTop: '0.5rem', width: '100%', justifyContent: 'center', padding: '12px' }}>
              {loading ? 'Verifying...' : 'Create Account'}
            </button>
          </form>
        )}

        {success && (
          <button className="btn btn-primary" onClick={() => navigate('/login')} style={{ display: 'flex', justifyContent: 'center', marginTop: '1rem', width: '100%' }}>
            Go to Login
          </button>
        )}

        {!success && (
          <p style={{ textAlign: 'center', fontSize: '12px', color: 'var(--muted)', marginTop: '1.5rem', fontFamily: 'var(--mono)' }}>
            Already have access? <Link to="/login" style={{ color: 'var(--accent)', textDecoration: 'none' }}>Sign in</Link>
          </p>
        )}
      </div>
    </div>
  );
}
