import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import NavBar from '../components/layout/NavBar';
import { listFiles, uploadLogFile, checkHealth } from '../services/api';
import { useAuth } from '../services/auth';

const SEV_DOT = { critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium', low: 'sev-low', none: 'sev-none' };

function timeAgo(d) {
  const diff = Math.floor((Date.now() - new Date(d)) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function Home() {
  const { session, orgId } = useAuth();
  const navigate = useNavigate();
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [backendOnline, setBackendOnline] = useState(false);
  const [lastSync, setLastSync] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [sourceType, setSourceType] = useState('windows');
  const [uploading, setUploading] = useState(false);
  const [uploadMsg, setUploadMsg] = useState('');

  const fetchData = useCallback(async () => {
    try {
      await checkHealth();
      setBackendOnline(true);
      if (orgId) {
        const data = await listFiles(orgId);
        setFiles(data || []);
      }
      setLastSync(new Date().toLocaleTimeString());
    } catch {
      setBackendOnline(false);
    } finally {
      setLoading(false);
    }
  }, [orgId]);

  useEffect(() => { fetchData(); const i = setInterval(fetchData, 30000); return () => clearInterval(i); }, [fetchData]);

  async function handleUpload() {
    if (!selectedFile || !orgId) return;
    setUploading(true);
    setUploadMsg('');
    try {
      const result = await uploadLogFile(selectedFile, sourceType, orgId);
      setUploadMsg(`✓ ${result.filename} uploaded — ${result.entry_count} entries queued for analysis`);
      setSelectedFile(null);
      await fetchData();
    } catch (err) {
      setUploadMsg(`✗ ${err.message}`);
    } finally {
      setUploading(false);
    }
  }

  const completed = files.filter(f => f.status === 'completed');
  const analyzing = files.filter(f => f.status === 'analyzing');
  const critical = files.filter(f => f.threat_level === 'critical' || f.threat_level === 'high');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', background: 'var(--bg)' }}>
      <NavBar backendOnline={backendOnline} />
      <div style={{ flex: 1, padding: '1.75rem', maxWidth: '1200px', width: '100%', margin: '0 auto' }}>

        <div style={{ marginBottom: '1.75rem' }} className="fade-in">
          <h1 style={{ fontSize: '22px', fontWeight: '700', color: 'var(--text)', marginBottom: '4px' }}>SOC Operations Center</h1>
          <p style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--muted)' }}>
            // analyst: {session?.user?.email}{lastSync && ` · last sync ${lastSync}`}{!backendOnline && ' · backend offline'}
          </p>
        </div>

        {!orgId && !loading && (
          <div className="card fade-in" style={{ padding: '1.25rem', marginBottom: '1.5rem', borderColor: 'var(--amber)' }}>
            <p style={{ fontFamily: 'var(--mono)', fontSize: '12px', color: 'var(--amber)' }}>
              ⚠ Your account is not linked to an organization yet. Contact your AegisFA administrator.
            </p>
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px', marginBottom: '1.5rem' }} className="fade-in">
          {[
            { label: 'Total Log Files', value: loading ? '—' : files.length, color: 'var(--text)' },
            { label: 'Analyzed', value: loading ? '—' : completed.length, color: 'var(--accent)' },
            { label: 'Processing', value: loading ? '—' : analyzing.length, color: analyzing.length > 0 ? 'var(--amber)' : 'var(--text)' },
            { label: 'High Severity', value: loading ? '—' : critical.length, color: critical.length > 0 ? 'var(--red)' : 'var(--text)' },
          ].map(({ label, value, color }) => (
            <div key={label} className="card" style={{ padding: '18px 20px' }}>
              <p style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '1.5px', marginBottom: '10px' }}>{label}</p>
              <p style={{ fontSize: '28px', fontWeight: '700', color }}>{value}</p>
            </div>
          ))}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
          <div className="card fade-in">
            <div className="card-header"><span className="card-title">Upload Log File</span></div>
            <div style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <label style={{ display: 'block', fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '7px' }}>Source Type</label>
                <select className="select" style={{ width: '100%' }} value={sourceType} onChange={e => setSourceType(e.target.value)}>
                  <option value="windows">Windows Event</option>
                  <option value="firewall">Firewall</option>
                  <option value="auth">Auth Log</option>
                  <option value="syslog">Syslog</option>
                  <option value="custom">Custom</option>
                </select>
              </div>
              <div>
                <label style={{ display: 'block', fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '7px' }}>Log File</label>
                <label style={{ display: 'block', border: '1px dashed var(--border2)', borderRadius: '8px', padding: '20px', textAlign: 'center', cursor: 'pointer', transition: 'all 0.15s' }}
                  onMouseEnter={e => e.currentTarget.style.borderColor = 'var(--accent-border)'}
                  onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border2)'}>
                  <input type="file" style={{ display: 'none' }} accept=".txt,.csv,.json,.log,.evtx" onChange={e => setSelectedFile(e.target.files[0])} />
                  {selectedFile
                    ? <span style={{ fontFamily: 'var(--mono)', fontSize: '12px', color: 'var(--text2)' }}>{selectedFile.name}</span>
                    : <span style={{ fontFamily: 'var(--mono)', fontSize: '12px', color: 'var(--muted)' }}>Drop file or <span style={{ color: 'var(--accent)' }}>browse</span></span>}
                </label>
              </div>
              <button className="btn btn-primary" onClick={handleUpload} disabled={!selectedFile || uploading || !backendOnline || !orgId} style={{ justifyContent: 'center' }}>
                {uploading ? 'Uploading...' : 'Upload & Analyze'}
              </button>
              {uploadMsg && <p style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: uploadMsg.startsWith('✓') ? 'var(--accent)' : 'var(--red)' }}>{uploadMsg}</p>}
            </div>s
          </div>

          <div className="card fade-in">
            <div className="card-header">
              <span className="card-title">Recent Log Files</span>
              <button className="btn" style={{ fontSize: '11px', padding: '4px 10px' }} onClick={() => navigate('/history')}>View All →</button>
            </div>
            {loading ? (
              <div style={{ display: 'flex', justifyContent: 'center', padding: '2rem' }}><div className="spinner" /></div>
            ) : !orgId ? (
              <div className="empty-state">No organization linked to your account</div>
            ) : files.length === 0 ? (
              <div className="empty-state">No log files uploaded yet</div>
            ) : (
              files.slice(0, 6).map(f => (
                <div key={f.id} onClick={() => navigate(`/history?file=${f.id}`)}
                  style={{ padding: '11px 18px', borderBottom: '1px solid var(--surface2)', display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer', transition: 'background 0.1s' }}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--surface2)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                  <div className={`sev-dot ${SEV_DOT[f.threat_level || 'none']}`} />
                  <span style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--muted)', minWidth: '70px' }}>{f.source_type?.toUpperCase()}</span>
                  <span style={{ fontSize: '12px', color: 'var(--text2)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.filename}</span>
                  <span className={`badge ${f.status === 'completed' ? 'badge-green' : f.status === 'analyzing' ? 'badge-amber' : 'badge-gray'}`}>{f.status}</span>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--muted)', flexShrink: 0 }}>{timeAgo(f.created_at)}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
