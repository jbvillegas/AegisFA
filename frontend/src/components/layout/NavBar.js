import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../../services/auth';
import { FaShieldAlt } from 'react-icons/fa';
import { FiLogOut } from 'react-icons/fi';

const tabs = [
  { href: '/home',    label: 'Dashboard' },
  { href: '/history', label: 'History' },
  { href: '/admin',   label: 'Admin' },
];

export default function NavBar({ backendOnline = true }) {
  const { session, signOut } = useAuth();
  const location = useLocation();

  return (
    <nav style={{ background: '#0d1117', borderBottom: '1px solid var(--border)', padding: '0 1.5rem', height: '54px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0, position: 'sticky', top: 0, zIndex: 100 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <div style={{ width: '32px', height: '32px', background: 'var(--accent-dim)', border: '1px solid var(--accent-border)', borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <FaShieldAlt style={{ color: 'var(--accent)', width: '15px', height: '15px' }} />
        </div>
        <span style={{ fontSize: '17px', fontWeight: '700', color: 'var(--text)', letterSpacing: '-0.3px' }}>
          Aegis<span style={{ color: 'var(--accent)' }}>FA</span>
        </span>
      </div>

      <div style={{ display: 'flex', gap: '2px' }}>
        {tabs.map(({ href, label }) => {
          const active = location.pathname === href;
          return (
            <Link key={href} to={href} style={{ padding: '6px 16px', fontSize: '12px', fontWeight: '500', borderRadius: '7px', fontFamily: 'var(--mono)', border: '1px solid', textDecoration: 'none', transition: 'all 0.15s', color: active ? 'var(--accent)' : 'var(--muted)', background: active ? 'var(--accent-dim)' : 'transparent', borderColor: active ? 'var(--accent-border)' : 'transparent' }}>
              {label}
            </Link>
          );
        })}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
          <div style={{ width: '7px', height: '7px', borderRadius: '50%', background: backendOnline ? 'var(--accent)' : 'var(--red)', boxShadow: backendOnline ? '0 0 8px #00ff9daa' : '0 0 8px #ff555588', animation: backendOnline ? 'pulse 2s infinite' : 'none' }} />
          <span style={{ fontSize: '11px', color: 'var(--muted)', fontFamily: 'var(--mono)' }}>{backendOnline ? 'LIVE' : 'OFFLINE'}</span>
        </div>
        <span style={{ fontSize: '11px', color: 'var(--muted)', fontFamily: 'var(--mono)' }}>{session?.user?.email}</span>
        <button onClick={signOut} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--muted)', cursor: 'pointer', padding: '5px 10px', border: '1px solid var(--border)', borderRadius: '6px', background: 'transparent', fontFamily: 'var(--mono)', transition: 'all 0.15s' }}
          onMouseEnter={e => { e.currentTarget.style.color = 'var(--red)'; e.currentTarget.style.borderColor = 'var(--red-border)'; }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--muted)'; e.currentTarget.style.borderColor = 'var(--border)'; }}>
          <FiLogOut size={12} /> logout
        </button>
      </div>
    </nav>
  );
}
