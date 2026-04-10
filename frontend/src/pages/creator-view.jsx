import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { supabase } from '../client.js';
import '../css/admindashboard.css';

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '');

function getLocalOrgId(user) {
  return (
    user?.user_metadata?.org_id ||
    user?.app_metadata?.org_id ||
    (user?.email ? user.email.split('@')[0] : '')
  );
}

function normalizeAction(item) {
  if (!item) {
    return '';
  }

  if (typeof item === 'string') {
    return item.trim();
  }

  if (typeof item === 'object') {
    return String(item.action || item.step || item.title || item.description || '').trim();
  }

  return '';
}

function extractActions(analysis) {
  const actions = [];
  const remediation = analysis?.remediation_steps;

  if (Array.isArray(remediation)) {
    remediation.forEach((item) => {
      const normalized = normalizeAction(item);
      if (normalized) {
        actions.push(normalized);
      }
    });
  } else if (remediation && typeof remediation === 'object') {
    Object.values(remediation).forEach((value) => {
      if (Array.isArray(value)) {
        value.forEach((item) => {
          const normalized = normalizeAction(item);
          if (normalized) {
            actions.push(normalized);
          }
        });
      } else {
        const normalized = normalizeAction(value);
        if (normalized) {
          actions.push(normalized);
        }
      }
    });
  }

  if (actions.length === 0) {
    const fallback = [
      'Validate suspicious hosts and user activity from the latest analysis window.',
      'Isolate affected assets if threat level is high or critical.',
      'Collect supporting evidence and escalate to incident response.',
    ];
    return fallback;
  }

  return [...new Set(actions)].slice(0, 5);
}

async function fetchLatestCompletedFileForOrg(orgId) {
  const primary = await supabase
    .from('log_files')
    .select('id, uploaded_at')
    .eq('org_id', orgId)
    .eq('status', 'completed')
    .order('uploaded_at', { ascending: false })
    .limit(1);

  if (!primary.error) {
    return primary.data?.[0] || null;
  }

  if (!String(primary.error.message || '').includes('uploaded_at')) {
    throw primary.error;
  }

  const fallback = await supabase
    .from('log_files')
    .select('id, created_at')
    .eq('org_id', orgId)
    .eq('status', 'completed')
    .order('created_at', { ascending: false })
    .limit(1);

  if (fallback.error) {
    throw fallback.error;
  }

  return fallback.data?.[0] || null;
}

function CreatorView() {
  const { creatorId } = useParams();
  const [orgId, setOrgId] = useState('');
  const [actions, setActions] = useState([]);
  const [analysisSummary, setAnalysisSummary] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [loadError, setLoadError] = useState('');

  useEffect(() => {
    let isMounted = true;

    const loadOrgContext = async () => {
      const localOrg = window.localStorage.getItem('aegisfa-org-id');
      if (localOrg && isMounted) {
        setOrgId(localOrg);
        return;
      }

      const { data } = await supabase.auth.getUser();
      if (!isMounted) {
        return;
      }

      setOrgId(getLocalOrgId(data?.user || null));
    };

    loadOrgContext();

    return () => {
      isMounted = false;
    };
  }, []);

  useEffect(() => {
    const loadRemediationPanel = async () => {
      if (!orgId.trim()) {
        setActions([]);
        return;
      }

      setIsLoading(true);
      setLoadError('');

      try {
        const latestFile = await fetchLatestCompletedFileForOrg(orgId.trim());
        const latestFileId = latestFile?.id;
        if (!latestFileId) {
          setActions([]);
          setAnalysisSummary('No completed analyses yet.');
          return;
        }

        const analysisResponse = await fetch(`${API_BASE_URL}/analysis/${latestFileId}?include_mitre_links=false`);
        if (!analysisResponse.ok) {
          throw new Error('Failed to load remediation data from latest analysis.');
        }

        const analysis = await analysisResponse.json();
        setAnalysisSummary(analysis?.summary || 'Use these actions as the immediate response baseline.');
        setActions(extractActions(analysis));
      } catch (error) {
        setLoadError(error.message || 'Failed to load remediation panel.');
      } finally {
        setIsLoading(false);
      }
    };

    loadRemediationPanel();
  }, [orgId]);

  return (
    <section className="panel creator-page">
      <h1>Creator Detail</h1>
      <p>Viewing creator ID: {creatorId}</p>
      <p>
        This route is now available so search results have a valid destination.
      </p>

      <section className="admin-section" aria-labelledby="remediation-title">
        <h2 id="remediation-title">Remediation / Next Steps</h2>
        <p className="panel-muted">Top actions to take now from the latest analysis context.</p>
        {isLoading && <p className="panel-muted">Loading remediation guidance...</p>}
        {loadError && <p className="panel-error">{loadError}</p>}
        {!isLoading && !loadError && (
          <>
            <p className="timeline-description">{analysisSummary}</p>
            {actions.length > 0 ? (
              <ol className="remediation-list">
                {actions.map((action, index) => (
                  <li key={`action-${index}`}>{action}</li>
                ))}
              </ol>
            ) : (
              <p className="panel-muted">No remediation actions found yet.</p>
            )}
          </>
        )}
      </section>

      <Link to="/dashboard">Back to Dashboard</Link>
    </section>
  );
}

export default CreatorView;