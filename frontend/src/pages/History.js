import { useState, useEffect, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import NavBar from '../components/layout/NavBar';
import { listFiles, getAnalysis, getDetections, checkHealth } from '../services/api';
import { useAuth } from '../services/auth';

const SEV_BADGE = { critical: 'badge-red', high: 'badge-amber', medium: 'badge-blue', low: 'badge-green', none: 'badge-gray' };
const SEV_DOT   = { critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium', low: 'sev-low', none: 'sev-none' };

function timeAgo(d) {
  const diff = Math.floor((Date.now() - new Date(d)) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function History() {
  const [searchParams] = useSearchParams();
  const { orgId } = useAuth();
  const [backendOnline, setBackendOnline] = useState(false);
  const [files, setFiles] = useState([]);
  const [selectedId, setSelectedId] = useState(searchParams.get('file') || '');
  const [analysis, setAnalysis] = useState(null);
  const [detections, setDetections] = useState([]);
  const [loadingFiles, setLoadingFiles] = useState(true);
  const [loadingAnalysis, setLoadingAnalysis] = useState(false);

  const fetchFiles = useCallback(async () => {
    try {
      await checkHealth();
      setBackendOnline(true);
      if (orgId) { const data = await listFiles(orgId); setFiles(data || []); }
    } catch { setBackendOnline(false); }
    finally { setLoadingFiles(false); }
  }, [orgId]);

  useEffect(() => { fetchFiles(); }, [fetchFiles]);

  useEffect(() => {
    if (!selectedId) { setAnalysis(null); setDetections([]); return; }
    setLoadingAnalysis(true);
    Promise.all([getAnalysis(selectedId), getDetections(orgId, selectedId)])
      .then(([a, d]) => { setAnalysis(a); setDetections(d || []); })
      .catch(() => { setAnalysis(null); setDetections([]); })
      .finally(() => setLoadingAnalysis(false));
  }, [selectedId, orgId]);

  const selectedFile = files.find(f => f.id === selectedId);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', background: 'var(--bg)' }}>
      <NavBar backendOnline={backendOnline} />
      <div style={{ flex: 1, padding: '1.75rem', maxWidth: '1200px', width: '100%', margin: '0 auto' }}>

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.75rem', flexWrap: 'wrap', gap: '1rem' }} className="fade-in">
          <div>
            <h1 style={{ fontSize: '22px', fontWeight: '700', color: 'var(--text)', marginBottom: '4px' }}>
              {selectedFile ? selectedFile.filename : 'Incident History'}
            </h1>
            <p style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--muted)' }}>// analysis results for your organization's log files</p>
          </div>
          <select className="select" value={selectedId} onChange={e => setSelectedId(e.target.value)} style={{ minWidth: '280px' }}>
            <option value="">— select a log file —</option>
            {files.map(f => <option key={f.id} value={f.id}>{f.filename} ({f.source_type}) — {f.status}</option>)}
          </select>
        </div>

        {!selectedId && (
          <div className="card fade-in">
            <div className="card-header">
              <span className="card-title">Your Organization's Log Files</span>
              <span className="badge badge-gray">{files.length} total</span>
            </div>
            {loadingFiles ? (
              <div style={{ display: 'flex', justifyContent: 'center', padding: '3rem' }}><div className="spinner" /></div>
            ) : !orgId ? (
              <div className="empty-state">Your account is not linked to an organization yet.</div>
            ) : files.length === 0 ? (
              <div className="empty-state">No log files found. Upload one from the Dashboard.</div>
            ) : (
              files.map(f => (
                <div key={f.id} onClick={() => setSelectedId(f.id)}
                  style={{ padding: '14px 18px', borderBottom: '1px solid var(--surface2)', display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer', transition: 'background 0.1s' }}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--surface2)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                  <div className={`sev-dot ${SEV_DOT[f.threat_level || 'none']}`} />
                  <div style={{ flex: 1 }}>
                    <p style={{ fontSize: '13px', color: 'var(--text2)', marginBottom: '3px' }}>{f.filename}</p>
                    <p style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--muted)' }}>{f.source_type} · {f.entry_count?.toLocaleString()} entries · {timeAgo(f.created_at)}</p>
                  </div>
                  <span className={`badge ${f.status === 'completed' ? 'badge-green' : f.status === 'analyzing' ? 'badge-amber' : 'badge-red'}`}>{f.status}</span>
                  {f.threat_level && f.threat_level !== 'none' && <span className={`badge ${SEV_BADGE[f.threat_level]}`}>{f.threat_level}</span>}
                </div>
              ))
            )}
          </div>
        )}

        {selectedId && (
          loadingAnalysis ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: '4rem' }}><div className="spinner" /></div>
          ) : analysis ? (
            <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>

              <div className="card">
                <div className="card-header">
                  <span className="card-title">AI Incident Summary</span>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    {analysis.threat_level && <span className={`badge ${SEV_BADGE[analysis.threat_level]}`}>{analysis.threat_level} threat</span>}
                    {analysis.confidence_score && <span className="badge badge-green">{Math.round(analysis.confidence_score * 100)}% confidence</span>}
                  </div>
                </div>
                <div style={{ padding: '1.25rem' }}>
                  <p style={{ fontSize: '13px', color: 'var(--text2)', lineHeight: 1.75 }}>{analysis.summary || 'No summary available.'}</p>
                  {analysis.attack_vector && <p style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--muted)', marginTop: '8px' }}>Attack vector: <span style={{ color: 'var(--amber)' }}>{analysis.attack_vector}</span></p>}
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
                <div className="card">
                  <div className="card-header">
                    <span className="card-title">MITRE ATT&CK</span>
                    <span className="badge badge-blue">{(analysis.mitre_techniques || []).length} techniques</span>
                  </div>
                  {!analysis.mitre_techniques?.length ? <div className="empty-state">No MITRE techniques mapped</div> : (
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', padding: '1rem' }}>
                      {analysis.mitre_techniques.map((m, i) => (
                        <div key={i} style={{ background: '#0d1117', border: '1px solid var(--border)', borderRadius: '8px', padding: '12px' }}>
                          <p style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '1.5px', marginBottom: '5px' }}>{m.tactic || 'Technique'}</p>
                          <p style={{ fontSize: '12px', color: 'var(--text2)', fontWeight: '600', marginBottom: '4px' }}>{m.name}</p>
                          <p style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--blue)' }}>{m.id || m.technique_id}</p>
                          {m.relevance && <p style={{ fontSize: '10px', color: 'var(--muted)', marginTop: '6px', lineHeight: 1.5 }}>{m.relevance}</p>}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="card">
                  <div className="card-header">
                    <span className="card-title">Remediation Steps</span>
                    <span className="badge badge-green">{(analysis.remediation_steps || []).length} steps</span>
                  </div>
                  {!analysis.remediation_steps?.length ? <div className="empty-state">No remediation steps</div> : (
                    analysis.remediation_steps.map((step, i) => (
                      <div key={i} style={{ padding: '11px 18px', borderBottom: '1px solid var(--surface2)', display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                        <span style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--accent)', minWidth: '22px', paddingTop: '1px' }}>{i + 1}.</span>
                        <span style={{ fontSize: '12px', color: 'var(--text2)', lineHeight: 1.65 }}>{step}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
                <div className="card">
                  <div className="card-header">
                    <span className="card-title">Impacted Assets</span>
                    <span className="badge badge-red">{(analysis.impacted_assets || []).length} affected</span>
                  </div>
                  {!analysis.impacted_assets?.length ? <div className="empty-state">No impacted assets identified</div> : (
                    analysis.impacted_assets.map((asset, i) => (
                      <div key={i} style={{ padding: '11px 18px', borderBottom: '1px solid var(--surface2)', display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <div style={{ width: '28px', height: '28px', background: 'var(--surface2)', borderRadius: '6px', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '13px' }}>
                          {String(asset).match(/^\d{1,3}\./) ? '🌐' : '🖥'}
                        </div>
                        <span style={{ fontSize: '12px', color: 'var(--text2)' }}>{typeof asset === 'string' ? asset : JSON.stringify(asset)}</span>
                      </div>
                    ))
                  )}
                </div>

                <div className="card">
                  <div className="card-header">
                    <span className="card-title">Attack Timeline</span>
                    <span className="badge badge-blue">{(analysis.timeline || []).length} events</span>
                  </div>
                  {!analysis.timeline?.length ? <div className="empty-state">No timeline events</div> : (
                    analysis.timeline.slice(0, 6).map((e, i) => (
                      <div key={i} style={{ padding: '10px 18px', borderBottom: '1px solid var(--surface2)', display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                        <span style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--muted)', minWidth: '75px', paddingTop: '2px', flexShrink: 0 }}>{e.timestamp || '—'}</span>
                        <span style={{ fontSize: '12px', color: 'var(--text2)', lineHeight: 1.5 }}>{e.event || e.description || '—'}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {detections.length > 0 && (
                <div className="card">
                  <div className="card-header">
                    <span className="card-title">Correlation Rule Detections</span>
                    <span className="badge badge-red">{detections.length} triggered</span>
                  </div>
                  {detections.map((d, i) => (
                    <div key={i} style={{ padding: '12px 18px', borderBottom: '1px solid var(--surface2)', display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
                      <div className={`sev-dot sev-${d.severity || 'medium'}`} />
                      <span style={{ fontSize: '12px', color: 'var(--text2)', flex: 1 }}>{d.description}</span>
                      {d.mitre_technique && <span className="badge badge-blue">{d.mitre_technique}</span>}
                      <span style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--muted)' }}>conf: {Math.round((d.confidence || 0) * 100)}%</span>
                    </div>
                  ))}
                </div>
              )}

              {analysis.detailed_findings?.length > 0 && (
                <div className="card">
                  <div className="card-header">
                    <span className="card-title">Detailed Threat Findings</span>
                    <span className="badge badge-red">{analysis.threats_found} threats</span>
                  </div>
                  {analysis.detailed_findings.map((f, i) => (
                    <div key={i} style={{ padding: '12px 18px', borderBottom: '1px solid var(--surface2)', display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                      <div className={`sev-dot sev-${f.severity || 'medium'}`} style={{ marginTop: '4px' }} />
                      <div style={{ flex: 1 }}>
                        <p style={{ fontSize: '12px', color: 'var(--text2)', fontWeight: '500', marginBottom: '4px' }}>{f.threat_type}</p>
                        <p style={{ fontSize: '12px', color: 'var(--text3)', lineHeight: 1.5 }}>{f.description}</p>
                        {f.indicators?.length > 0 && <p style={{ fontFamily: 'var(--mono)', fontSize: '10px', color: 'var(--muted)', marginTop: '6px' }}>Indicators: {f.indicators.join(', ')}</p>}
                      </div>
                      <span className={`badge badge-${f.severity === 'critical' ? 'red' : f.severity === 'high' ? 'amber' : f.severity === 'medium' ? 'blue' : 'green'}`}>{f.severity}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="card fade-in"><div className="empty-state">No analysis found. The file may still be processing.</div></div>
          )
        )}
      </div>
    </div>
  );
}
