import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { authenticatedFetch, supabase } from '../client.js';
import { usePersistentState } from '../hooks/use-persistent-state.js';
import '../css/homepage.css';
import '../css/dashboard.css';

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '');
const CHUNK_SIZE = 4 * 1024 * 1024;
const RECENT_JOBS_LIMIT = 8;

const SOURCE_TYPES = [
  { value: 'custom', label: 'Custom' },
  { value: 'syslog', label: 'Syslog' },
  { value: 'windows', label: 'Windows' },
  { value: 'firewall', label: 'Firewall' },
  { value: 'auth', label: 'Authentication' },
];

const STATUS_LABELS = {
  idle: 'Ready to upload',
  preparing: 'Preparing upload session',
  uploading: 'Uploading file parts',
  completing: 'Finalizing upload',
  queued: 'Queued for analysis',
  processing: 'Analyzing in Supabase',
  completed: 'Analysis completed',
  failed: 'Upload failed',
};

const SUMMARY_DEFAULTS = {
  threatLevel: 'pending',
  uploadsProcessed: 0,
  detectionsFound: 0,
  lastAnalysisTime: 'Not available',
  jobStatus: 'idle',
  predictionConfidence: null,
};

const SEVERITY_WEIGHT = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

function formatBytes(bytes) {
  if (!bytes && bytes !== 0) {
    return '0 B';
  }

  const sizes = ['B', 'KB', 'MB', 'GB'];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), sizes.length - 1);
  const value = bytes / 1024 ** exponent;
  return `${value.toFixed(value >= 10 || exponent === 0 ? 0 : 1)} ${sizes[exponent]}`;
}

function getErrorMessage(payload, fallback) {
  if (payload?.error?.message) {
    return payload.error.message;
  }

  if (payload?.message) {
    return payload.message;
  }

  return fallback;
}

function getLocalOrgId(user) {
  return (
    user?.user_metadata?.org_id ||
    user?.app_metadata?.org_id ||
    ''
  );
}

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || '').trim());
}

function formatTimestamp(timestamp) {
  if (!timestamp) {
    return 'Not available';
  }

  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) {
    return 'Not available';
  }

  return date.toLocaleString();
}

function titleCase(value) {
  if (!value) {
    return 'Unknown';
  }

  const normalized = String(value).replace(/[_-]/g, ' ').trim();
  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

function getFilenameFromPath(path) {
  if (!path) {
    return 'Unknown';
  }

  const parts = String(path).split('/');
  return parts[parts.length - 1] || 'Unknown';
}

function getSeverityScore(value) {
  const normalized = String(value || 'medium').toLowerCase();
  return SEVERITY_WEIGHT[normalized] || 0;
}

function clampText(value, maxLength = 120) {
  const text = String(value || '').trim();
  if (text.length <= maxLength) {
    return text;
  }
  return `${text.slice(0, maxLength - 1)}...`;
}

function normalizeConfidence(rawValue) {
  if (typeof rawValue === 'number' && Number.isFinite(rawValue)) {
    const scaled = rawValue > 1 ? rawValue / 100 : rawValue;
    return Math.max(0, Math.min(1, scaled));
  }

  if (typeof rawValue === 'string') {
    const parsed = Number.parseFloat(rawValue);
    if (Number.isFinite(parsed)) {
      const scaled = parsed > 1 ? parsed / 100 : parsed;
      return Math.max(0, Math.min(1, scaled));
    }

    const normalized = rawValue.trim().toLowerCase();
    if (normalized.includes('high')) {
      return 0.85;
    }
    if (normalized.includes('medium')) {
      return 0.6;
    }
    if (normalized.includes('low')) {
      return 0.35;
    }
  }

  return 0;
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
    return [
      'Review the flagged hosts and users from the latest analysis window.',
      'Isolate affected assets if the threat level is high or critical.',
      'Collect supporting evidence and escalate to incident response if needed.',
    ];
  }

  return [...new Set(actions)].slice(0, 5);
}

function getMitreTechniqueUrl(techniqueId) {
  if (!techniqueId) {
    return '';
  }

  const normalized = String(techniqueId).trim().toUpperCase();
  if (!normalized.startsWith('T')) {
    return '';
  }

  if (normalized.includes('.')) {
    const [base, sub] = normalized.split('.');
    if (!base || !sub) {
      return '';
    }
    return `https://attack.mitre.org/techniques/${base}/${sub}/`;
  }

  return `https://attack.mitre.org/techniques/${normalized}/`;
}

async function fetchLatestCompletedFileForOrg(orgId) {
  const candidates = ['uploaded_at', 'created_at'];

  for (const timestampField of candidates) {
    const result = await supabase
      .from('log_files')
      .select(`id, status, ${timestampField}`)
      .eq('org_id', orgId)
      .eq('status', 'completed')
      .order(timestampField, { ascending: false })
      .limit(1);

    if (!result.error) {
      return result.data?.[0] || null;
    }

    const message = String(result.error.message || '').toLowerCase();
    if (!(message.includes(timestampField) && message.includes('column'))) {
      throw result.error;
    }
  }

  const fallback = await supabase
    .from('log_files')
    .select('id, status')
    .eq('org_id', orgId)
    .eq('status', 'completed')
    .limit(1);

  if (fallback.error) {
    throw fallback.error;
  }

  return fallback.data?.[0] || null;
}

function formatDuration(totalSeconds) {
  if (!Number.isFinite(totalSeconds) || totalSeconds < 0) {
    return 'estimating...';
  }

  const seconds = Math.round(totalSeconds);
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;

  if (mins > 0) {
    return `${mins}m ${secs}s`;
  }

  return `${secs}s`;
}

function DashboardPage() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileInputKey, setFileInputKey] = useState(0);
  const [sourceType, setSourceType] = usePersistentState('aegisfa-source-type', 'custom');
  const [orgId, setOrgId] = usePersistentState('aegisfa-org-id', '');
  const [requestedBy, setRequestedBy] = useState('');
  const [requestedById, setRequestedById] = useState('');
  const [uploadStage, setUploadStage] = useState('idle');
  const [uploadMessage, setUploadMessage] = useState('Choose a log file to start.');
  const [uploadProgress, setUploadProgress] = useState(0);
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const [isUploading, setIsUploading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [jobSummary, setJobSummary] = usePersistentState('aegisfa-last-job-summary', null);
  const [analysisResult, setAnalysisResult] = usePersistentState('aegisfa-last-analysis-result', null);
  const [summarySnapshot, setSummarySnapshot] = usePersistentState('aegisfa-summary-snapshot', SUMMARY_DEFAULTS);
  const [isSummaryLoading, setIsSummaryLoading] = useState(false);
  const [summaryError, setSummaryError] = useState('');
  const [latestAnalysis, setLatestAnalysis] = useState(null);
  const [recentJobs, setRecentJobs] = usePersistentState('aegisfa-recent-jobs', []);
  const [isRecentJobsLoading, setIsRecentJobsLoading] = useState(false);
  const [recentJobsError, setRecentJobsError] = useState('');
  const [analysisStartedAt, setAnalysisStartedAt] = useState(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [expandedFindingKey, setExpandedFindingKey] = useState(null);
  const [expandedAlertKey, setExpandedAlertKey] = useState(null);
  const [promotedFindingKeys, setPromotedFindingKeys] = useState([]);
  const [promotingFindingKeys, setPromotingFindingKeys] = useState([]);

  useEffect(() => {
    let isMounted = true;

    const loadUser = async () => {
      const { data } = await supabase.auth.getUser();
      if (!isMounted) {
        return;
      }

      const user = data?.user || null;
      setRequestedBy(user?.email || '');
      setRequestedById(user?.id || '');
      setOrgId((current) => {
        if (isUuid(current)) {
          return current;
        }

        const localOrgId = getLocalOrgId(user);
        return isUuid(localOrgId) ? localOrgId : '';
      });
    };

    loadUser();

    return () => {
      isMounted = false;
    };
  }, []);

  useEffect(() => {
    if (!orgId) {
      return;
    }

    if (!isUuid(orgId)) {
      setOrgId('');
    }
  }, [orgId, setOrgId]);

  useEffect(() => {
    if (!isUploading || analysisStartedAt === null) {
      return undefined;
    }

    const interval = setInterval(() => {
      setElapsedSeconds(Math.floor((Date.now() - analysisStartedAt) / 1000));
    }, 1000);

    return () => clearInterval(interval);
  }, [isUploading, analysisStartedAt]);

  useEffect(() => {
    if (orgId && isUuid(orgId)) {
      refreshSummaryCards();
      refreshRecentJobs();
    }
  }, [orgId, setOrgId]);

  const refreshSummaryCards = async () => {
    if (!orgId.trim()) {
      setSummarySnapshot(SUMMARY_DEFAULTS);
      setLatestAnalysis(null);
      return;
    }

    setIsSummaryLoading(true);
    setSummaryError('');

    try {
      const [uploadCountResult, latestFileResult] = await Promise.all([
        supabase
          .from('log_files')
          .select('*', { count: 'exact', head: true })
          .eq('org_id', orgId.trim())
          .eq('status', 'completed'),
        fetchLatestCompletedFileForOrg(orgId.trim()),
      ]);

      if (uploadCountResult.error) {
        throw uploadCountResult.error;
      }

      const latestFile = latestFileResult || null;
      const latestFileTimestamp = latestFile?.created_at || latestFile?.uploaded_at || null;
      const nextSummary = {
        ...SUMMARY_DEFAULTS,
        uploadsProcessed: uploadCountResult.count ?? 0,
        jobStatus: latestFile?.status || 'idle',
        lastAnalysisTime: formatTimestamp(latestFileTimestamp),
        predictionConfidence: null,
      };

      if (latestFile?.id) {
        const analysisResponse = await authenticatedFetch(`${API_BASE_URL}/analysis/${latestFile.id}?include_mitre_links=false`);
        if (analysisResponse.ok) {
          const latestAnalysis = await analysisResponse.json();
          nextSummary.threatLevel = latestAnalysis?.threat_level || 'pending';
          nextSummary.detectionsFound = latestAnalysis?.threats_found ?? 0;
          nextSummary.lastAnalysisTime = formatTimestamp(latestAnalysis?.created_at || latestFileTimestamp);
          setLatestAnalysis(latestAnalysis);
        }
      }

      setSummarySnapshot(nextSummary);
    } catch (summaryLoadError) {
      setSummaryError(summaryLoadError.message || 'Failed to load dashboard summary data.');
    } finally {
      setIsSummaryLoading(false);
    }
  };

  const refreshRecentJobs = async () => {
    if (!orgId.trim()) {
      return;
    }

    setIsRecentJobsLoading(true);
    setRecentJobsError('');

    try {
      const response = await authenticatedFetch(
        `${API_BASE_URL}/analysis-jobs?org_id=${orgId.trim()}&limit=${RECENT_JOBS_LIMIT}`
      );

      if (!response.ok) {
        throw new Error('Failed to fetch recent jobs.');
      }

      const data = await response.json();
      const mapped = (data.jobs || []).map((job) => ({
        id: job.id,
        filename: job.filename || job.file_name || 'Unknown',
        status: job.status,
        progress: job.progress_pct || 0,
        startedAt: job.created_at,
        completedAt: job.completed_at,
        fileId: job.file_id,
        resultId: job.result_id,
      }));

      setRecentJobs(mapped);
    } catch (recentJobsLoadError) {
      setRecentJobsError(recentJobsLoadError.message || 'Failed to load recent jobs.');
    } finally {
      setIsRecentJobsLoading(false);
    }
  };

  const openJobResult = async (job) => {
    if (!job.fileId) {
      return;
    }

    try {
      const response = await authenticatedFetch(`${API_BASE_URL}/analysis/${job.fileId}`);

      if (!response.ok) {
        setErrorMessage('Failed to load analysis result.');
        return;
      }

      const result = await response.json();
      setAnalysisResult(result);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (openResultError) {
      setErrorMessage(openResultError.message || 'Failed to open job result.');
    }
  };

  const resetUpload = () => {
    setSelectedFile(null);
    setFileInputKey((current) => current + 1);
    setUploadStage('idle');
    setUploadMessage('Choose a log file to start.');
    setUploadProgress(0);
    setAnalysisProgress(0);
    setIsUploading(false);
    setErrorMessage('');
    setSuccessMessage('');
    setJobSummary(null);
    setAnalysisResult(null);
    setAnalysisStartedAt(null);
    setElapsedSeconds(0);
  };

  const uploadAndAnalyze = async (event) => {
    event.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');

    if (!selectedFile) {
      setErrorMessage('Select a log file first.');
      return;
    }

    if (!orgId.trim()) {
      setErrorMessage('Enter an org context before uploading.');
      return;
    }

    setIsUploading(true);
    setUploadStage('preparing');
    setAnalysisStartedAt(Date.now());
    setElapsedSeconds(0);
    setUploadMessage('Creating upload session in Supabase.');
    setUploadProgress(0);
    setAnalysisProgress(0);
    setJobSummary(null);
    setAnalysisResult(null);

    try {
      const totalParts = Math.max(1, Math.ceil(selectedFile.size / CHUNK_SIZE));
      const initResponse = await authenticatedFetch(`${API_BASE_URL}/upload-sessions/init`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          org_id: orgId.trim(),
          filename: selectedFile.name,
          source_type: sourceType,
          total_parts: totalParts,
        }),
      });

      if (!initResponse.ok) {
        throw new Error(getErrorMessage(await initResponse.json().catch(() => null), 'Failed to initialize upload session.'));
      }

      const initData = await initResponse.json();
      const sessionId = initData.session_id;

      for (let partNumber = 1; partNumber <= totalParts; partNumber += 1) {
        setUploadStage('uploading');
        setUploadMessage(`Uploading chunk ${partNumber} of ${totalParts}.`);

        const start = (partNumber - 1) * CHUNK_SIZE;
        const end = Math.min(selectedFile.size, start + CHUNK_SIZE);
        const chunk = selectedFile.slice(start, end);
        const formData = new FormData();
        formData.append('session_id', sessionId);
        formData.append('part_number', String(partNumber));
        formData.append('file', chunk, selectedFile.name);

        const partResponse = await authenticatedFetch(`${API_BASE_URL}/upload-sessions/upload-part`, {
          method: 'POST',
          body: formData,
        });

        if (!partResponse.ok) {
          throw new Error(getErrorMessage(await partResponse.json().catch(() => null), 'Failed to upload a file chunk.'));
        }

        setUploadProgress(Math.round((partNumber / totalParts) * 100));
      }

      setUploadStage('completing');
      setUploadMessage('Finalizing upload and queueing analysis.');

      const completeResponse = await authenticatedFetch(`${API_BASE_URL}/upload-sessions/complete`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          session_id: sessionId,
          requested_by: requestedById || null,
        }),
      });

      if (!completeResponse.ok) {
        throw new Error(getErrorMessage(await completeResponse.json().catch(() => null), 'Failed to complete the upload.'));
      }

      const completeData = await completeResponse.json();
      setUploadStage('queued');
      setUploadMessage(`Analysis job ${completeData.job_id} queued in Supabase.`);
      setAnalysisProgress(10);
      setJobSummary({
        id: completeData.job_id,
        status: 'queued',
        progress_pct: 10,
      });

      let finished = false;
      let attempts = 0;
      let latestProgress = 10;

      while (!finished && attempts < 60) {
        attempts += 1;
        const jobResponse = await authenticatedFetch(`${API_BASE_URL}/analysis-jobs/${completeData.job_id}`);

        if (!jobResponse.ok) {
          const statusPayload = await jobResponse.json().catch(() => null);
          const statusMessage = getErrorMessage(statusPayload, 'Failed to fetch analysis job status.');
          setUploadMessage(`${statusMessage} Retrying status check.`);
          // eslint-disable-next-line no-await-in-loop
          await new Promise((resolve) => setTimeout(resolve, 2000));
          continue;
        }

        const jobData = await jobResponse.json();
        const currentJob = jobData.job || {};
        const progress = typeof currentJob.progress_pct === 'number' ? currentJob.progress_pct : latestProgress;
        latestProgress = progress;

        setJobSummary(currentJob);
        setAnalysisProgress(progress);

        if (currentJob.status === 'failed') {
          throw new Error(currentJob.error_message || 'Analysis failed inside Supabase.');
        }

        if (currentJob.status === 'completed') {
          setUploadStage('completed');
          setUploadMessage('Analysis completed and stored in Supabase.');
          setAnalysisProgress(100);
          setAnalysisResult(jobData.result || null);
          setSuccessMessage('Upload processed successfully.');
          finished = true;
          break;
        }

        setUploadStage(currentJob.status === 'running' ? 'processing' : 'queued');
        setUploadMessage(currentJob.status === 'running' ? 'Supabase is analyzing the file.' : 'Waiting for the analysis worker.');
        // eslint-disable-next-line no-await-in-loop
        await new Promise((resolve) => setTimeout(resolve, 2000));
      }

      if (!finished) {
        setUploadStage('processing');
        setUploadMessage('Upload finished, analysis is still running in the backend.');
        setSuccessMessage('Upload queued successfully. Refresh the page later to see the final result.');
      }

      await refreshSummaryCards();
      await refreshRecentJobs();
    } catch (uploadError) {
      setUploadStage('failed');
      setUploadMessage('Upload did not complete.');
      setErrorMessage(uploadError.message || 'Upload failed.');
    } finally {
      setIsUploading(false);
    }
  };

  const promoteFindingToIncident = async (finding, findingKey) => {
    if (!orgId.trim()) {
      setErrorMessage('Enter an org context before promoting an alert.');
      return;
    }

    if (promotedFindingKeys.includes(findingKey) || promotingFindingKeys.includes(findingKey)) {
      return;
    }

    const title = finding?.threat_type || finding?.description || 'Alert review item';

    try {
      setPromotingFindingKeys((current) => [...current, findingKey]);
      const response = await authenticatedFetch(`${API_BASE_URL}/incidents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          org_id: orgId.trim(),
          title,
          severity: finding?.severity || 'medium',
          status: 'open',
        }),
      });

      if (!response.ok) {
        throw new Error(getErrorMessage(await response.json().catch(() => null), 'Failed to promote alert to incident.'));
      }

      setPromotedFindingKeys((current) => (current.includes(findingKey) ? current : [...current, findingKey]));
      setSuccessMessage(`Promoted ${title} to an incident.`);
    } catch (error) {
      setErrorMessage(error.message || 'Failed to promote alert to incident.');
    } finally {
      setPromotingFindingKeys((current) => current.filter((key) => key !== findingKey));
    }
  };

  const currentStatus = STATUS_LABELS[uploadStage] || STATUS_LABELS.idle;
  const progressValue = uploadStage === 'uploading' || uploadStage === 'completing' ? uploadProgress : analysisProgress;
  const safeProgress = Math.max(0, Math.min(100, progressValue));
  const statusTone = uploadStage === 'failed' ? 'danger' : uploadStage === 'completed' ? 'success' : 'neutral';
  const threatLevel = analysisResult?.threat_level || 'pending';
  const detectionCount = analysisResult?.threats_found ?? 0;
  const mitreCount = analysisResult?.mitre_techniques?.length ?? 0;
  const summaryThreatLevel = analysisResult?.threat_level || summarySnapshot.threatLevel;
  const summaryDetectionsFound = analysisResult?.threats_found ?? summarySnapshot.detectionsFound;
  const summaryUploadsProcessed = summarySnapshot.uploadsProcessed;
  const summaryPredictionConfidence = normalizeConfidence(
    analysisResult?.confidence_score ?? analysisResult?.confidence ?? summarySnapshot.predictionConfidence,
  );
  const hasSummaryPredictionConfidence = Number.isFinite(summaryPredictionConfidence);
  const summaryLastAnalysis = analysisResult?.created_at
    ? formatTimestamp(analysisResult.created_at)
    : summarySnapshot.lastAnalysisTime;
  const summaryJobStatus = jobSummary?.status || summarySnapshot.jobStatus || uploadStage;
  const activeAnalysis = analysisResult || latestAnalysis;
  const verdictSources = activeAnalysis?.verdict_sources && typeof activeAnalysis.verdict_sources === 'object'
    ? activeAnalysis.verdict_sources
    : null;
  const hasConfidenceBreakdown = Boolean(verdictSources && (
    typeof verdictSources.llm_confidence === 'number'
    || typeof verdictSources.retrieval_strength === 'number'
    || typeof verdictSources.rf_risk_score === 'number'
    || typeof verdictSources.correlation_strength === 'number'
    || typeof verdictSources.evidence_consistency_bonus === 'number'
  ));
  const nextStepActions = extractActions(activeAnalysis);
  const topFindings = (activeAnalysis?.detailed_findings || [])
    .filter((item) => item && typeof item === 'object')
    .sort((left, right) => {
      const severityDelta = getSeverityScore(right.severity) - getSeverityScore(left.severity);
      if (severityDelta !== 0) {
        return severityDelta;
      }

      return normalizeConfidence(right.confidence_score ?? right.confidence)
        - normalizeConfidence(left.confidence_score ?? left.confidence);
    })
    .slice(0, 5);

  const getFindingKey = (finding, index) => finding?.id || finding?.threat_type || finding?.rule_name || `finding-${index}`;

  const toggleFinding = (findingKey) => {
    setExpandedFindingKey((current) => (current === findingKey ? null : findingKey));
  };

  const toggleAlert = (alertKey) => {
    setExpandedAlertKey((current) => (current === alertKey ? null : alertKey));
  };

  const mitreTechniques = (activeAnalysis?.mitre_links || activeAnalysis?.mitre_techniques || [])
    .filter((item) => item && typeof item === 'object')
    .map((item, index) => {
      const confidence = normalizeConfidence(
        item.similarity_score ?? item.similarity ?? item.confidence ?? item.relevance,
      );

      return {
        key: item.technique_id || item.id || `technique-${index}`,
        techniqueId: item.technique_id || item.id || 'Unknown',
        name: item.technique_name || item.name || 'Unnamed technique',
        tactic: item.tactic || 'Unknown tactic',
        confidence,
        confidenceLabel: `${Math.round(confidence * 100)}%`,
        attackUrl: getMitreTechniqueUrl(item.technique_id || item.id),
      };
    })
    .sort((left, right) => right.confidence - left.confidence)
    .slice(0, 6);
  const etaSeconds = safeProgress > 4
    ? Math.max(0, elapsedSeconds * ((100 / safeProgress) - 1))
    : Number.NaN;
  const progressCircleStyle = {
    background: `conic-gradient(var(--accent) ${safeProgress * 3.6}deg, rgba(255, 255, 255, 0.08) 0deg)`,
  };

  return (
    <div className="hp dash-shell">

      {/* Hero */}
      <section className="hp-hero">
        <div className="hp-hero-inner">
          <p className="hp-kicker">Security Operations</p>
          <h1 className="hp-hero-title">Analysis Dashboard</h1>
          <p className="hp-hero-sub">
            Upload log files, track analysis jobs, review detections, and act on AI-generated intelligence from one place.
          </p>
          <div className="hp-hero-actions">
            <Link to="/workspace" className="hp-btn hp-btn-secondary">Open Workspace</Link>
            <Link to="/feedback" className="hp-btn hp-btn-secondary">AI Feedback</Link>
          </div>
        </div>
        <div className="hp-hero-glow" aria-hidden="true" />
      </section>

      <section className="upload-panel" aria-labelledby="upload-panel-title">
        <div className="upload-panel-copy">
          <p className="hp-kicker">Primary Upload</p>
          <h2 id="upload-panel-title">Ingest a file into Supabase</h2>
          <p>
            Pick a file, choose the source type, attach it to an org context, and watch the upload move into analysis.
          </p>
          <div className="upload-context">
            <span>Signed in as: {requestedBy || 'Unknown user'}</span>
            <span>Database path: Supabase-backed analysis jobs</span>
          </div>
        </div>

        <form className="upload-form" onSubmit={uploadAndAnalyze}>
          <label className="field">
            <span className="field-label">Log file</span>
            <input
              key={fileInputKey}
              id="upload-file"
              className={selectedFile ? 'file-selected' : ''}
              type="file"
              accept=".csv,.log,.txt,.json"
              onChange={(event) => setSelectedFile(event.target.files?.[0] || null)}
              disabled={isUploading}
            />
            <span className="field-hint">
              {selectedFile ? `${selectedFile.name} • ${formatBytes(selectedFile.size)}` : 'CSV, TXT, LOG, or JSON files up to your backend limit.'}
            </span>
          </label>

          <div className="upload-form-grid">
            <label className="field">
              <span className="field-label">Source type</span>
              <select value={sourceType} onChange={(event) => setSourceType(event.target.value)} disabled={isUploading}>
                {SOURCE_TYPES.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              <span className="field-hint">Stored in the backend as source_type and used for Supabase records.</span>
            </label>

            <label className="field">
              <span className="field-label">Org context</span>
              <input
                type="text"
                value={orgId}
                onChange={(event) => setOrgId(event.target.value)}
                placeholder="organization-id"
                disabled={isUploading}
              />
              <span className="field-hint">Stored in the backend as org_id and used for Supabase records.</span>
            </label>
          </div>

          <div className="upload-progress-card" aria-live="polite">
            <div className="progress-circle-wrap">
              <div className="progress-circle" style={progressCircleStyle}>
                <div className="progress-circle-inner">
                  <span className="progress-circle-value">{Math.round(safeProgress)}%</span>
                </div>
              </div>
              <div className="progress-circle-meta">
                <p>Elapsed: {formatDuration(elapsedSeconds)}</p>
                <p>ETA: {formatDuration(etaSeconds)}</p>
              </div>
            </div>
            <div className="progress-track">
              <div className="progress-fill" style={{ width: `${safeProgress}%` }} />
            </div>
            <div className="upload-status-row">
              <span className={`status-pill ${statusTone}`}>{currentStatus}</span>
              <span className="upload-message">{uploadMessage}</span>
              <span className="upload-percentage">{Math.round(progressValue)}%</span>
            </div>
          </div>

          <div className="upload-actions-row">
            <button type="submit" className="upload-submit" disabled={isUploading || !selectedFile}>
              {isUploading ? 'Uploading...' : 'Start upload'}
            </button>
            <button type="button" className="upload-reset" onClick={resetUpload} disabled={isUploading}>
              Reset
            </button>
          </div>

          {errorMessage && <p className="upload-feedback error">{errorMessage}</p>}
          {successMessage && <p className="upload-feedback success">{successMessage}</p>}
        </form>
      </section>

      <section className="summary-cards" aria-label="Dashboard summary cards">
        <article className="summary-card">
          <p className="summary-label">Threat Level</p>
          <p className="summary-value">{titleCase(summaryThreatLevel)}</p>
          <p className="summary-subtext">Most recent completed analysis</p>
        </article>
        <article className="summary-card">
          <p className="summary-label">Uploads Processed</p>
          <p className="summary-value">{summaryUploadsProcessed}</p>
          <p className="summary-subtext">Completed files for this org</p>
        </article>
        <article className="summary-card">
          <p className="summary-label">Detections Found</p>
          <p className="summary-value">{summaryDetectionsFound}</p>
          <p className="summary-subtext">Threats in latest analysis</p>
        </article>
        <article className="summary-card">
          <p className="summary-label">Last Analysis Time</p>
          <p className="summary-value summary-value-time">{summaryLastAnalysis}</p>
          <p className="summary-subtext">Timestamp from stored result</p>
        </article>
        <article className="summary-card">
          <p className="summary-label">Job Status</p>
          <p className="summary-value">{titleCase(summaryJobStatus)}</p>
          <p className="summary-subtext">Live worker status when active</p>
        </article>
        <article className="summary-card summary-card-confidence">
          <p className="summary-label">Prediction Confidence</p>
          <p className="summary-value">{hasSummaryPredictionConfidence ? `${Math.round(summaryPredictionConfidence * 100)}%` : 'Not available'}</p>
          <div className="confidence-bar" aria-hidden="true">
            <div className="confidence-bar-fill" style={{ width: `${Math.round(summaryPredictionConfidence * 100)}%` }} />
          </div>
          <p className="summary-subtext">Confidence reported by the latest analysis model</p>
        </article>
      </section>
      {isSummaryLoading && <p className="summary-loading">Refreshing summary cards...</p>}
      {summaryError && <p className="summary-error">{summaryError}</p>}

      <section className="content-area" aria-labelledby="overview-title">
        <header>
          <p className="hp-kicker">Overview</p>
          <h2 id="overview-title">Security Operations Home</h2>
          <p>
            Track uploads, review detections, and jump into analysis from one place.
          </p>
        </header>

        <section aria-labelledby="metrics-title">
          <h2 id="metrics-title">Current Status</h2>
          <ul>
            <li>Files processed today: {jobSummary ? 1 : 0}</li>
            <li>Open detections: {detectionCount}</li>
            <li>Analysis queue: {currentStatus}</li>
            <li>Last upload: {selectedFile ? selectedFile.name : 'Not available'}</li>
          </ul>
        </section>

        <section aria-labelledby="recent-title">
          <h2 id="recent-title">Recent Analysis</h2>
          {analysisResult ? (
            <article>
              <h3>{titleCase(threatLevel)}</h3>
              <p>{analysisResult.summary || 'The backend has stored a new analysis result.'}</p>
              <p>
                Threats found: {detectionCount} • MITRE mappings: {mitreCount}
              </p>
              <p>
                Prediction confidence: {hasSummaryPredictionConfidence ? `${Math.round(summaryPredictionConfidence * 100)}%` : 'Not available'}
              </p>
              <div className="confidence-bar confidence-bar-inline" aria-hidden="true">
                <div className="confidence-bar-fill" style={{ width: `${Math.round(summaryPredictionConfidence * 100)}%` }} />
              </div>
              {hasConfidenceBreakdown && (
                <div className="confidence-breakdown" aria-label="Confidence score breakdown">
                  <p className="confidence-breakdown-title">Confidence Breakdown</p>
                  <ul className="confidence-breakdown-list">
                    <li>LLM signal: {Math.round((verdictSources.llm_confidence || 0) * 100)}%</li>
                    <li>MITRE retrieval: {Math.round((verdictSources.retrieval_strength || 0) * 100)}%</li>
                    <li>RF risk: {Math.round((verdictSources.rf_risk_score || 0) * 100)}%</li>
                    <li>Correlation evidence: {Math.round((verdictSources.correlation_strength || 0) * 100)}%</li>
                    <li>Consistency bonus: {Math.round((verdictSources.evidence_consistency_bonus || 0) * 100)}%</li>
                  </ul>
                </div>
              )}
            </article>
          ) : (
            <article>
              <h3>No analysis yet</h3>
              <p>Upload a log file to generate detections, timelines, and remediation guidance.</p>
            </article>
          )}
          {jobSummary && (
            <article>
              <h3>Latest job status</h3>
              <p>Status: {jobSummary.status || 'unknown'}</p>
              <p>Progress: {typeof jobSummary.progress_pct === 'number' ? `${jobSummary.progress_pct}%` : 'N/A'}</p>
            </article>
          )}
        </section>

        <section className="intel-grid" aria-label="Findings and MITRE intelligence">
          <article className="intel-panel top-findings-panel" aria-labelledby="top-findings-title">
            <h2 id="top-findings-title">Top Findings</h2>
            {topFindings.length === 0 ? (
              <p className="intel-empty">No threat findings yet. Upload and analyze a file to populate this panel.</p>
            ) : (
              <ul className="findings-list top-findings-list">
                {topFindings.map((finding, index) => (
                  <li key={`${finding.threat_type || 'finding'}-${index}`} className="finding-item">
                    {(() => {
                      const findingKey = getFindingKey(finding, index);
                      const isExpanded = expandedFindingKey === findingKey;
                      const isPromoted = promotedFindingKeys.includes(findingKey);
                      const isPromoting = promotingFindingKeys.includes(findingKey);
                      const findingDescription = finding.description || 'Threat summary unavailable.';
                      const indicators = Array.isArray(finding.indicators) ? finding.indicators.filter(Boolean) : [];

                      return (
                        <>
                          <div className="finding-toggle">
                            <div className="finding-head">
                              <span
                                className="finding-title finding-title-toggle"
                                role="button"
                                tabIndex={0}
                                onClick={() => toggleFinding(findingKey)}
                                onKeyDown={(event) => {
                                  if (event.key === 'Enter' || event.key === ' ') {
                                    event.preventDefault();
                                    toggleFinding(findingKey);
                                  }
                                }}
                                aria-expanded={isExpanded}
                                aria-controls={`finding-report-${findingKey}`}
                              >
                                {titleCase(finding.threat_type || 'Threat finding')}
                              </span>
                              <span className={`severity-pill severity-${String(finding.severity || 'medium').toLowerCase()}`}>
                                {titleCase(finding.severity || 'medium')}
                              </span>
                            </div>
                            <p className="finding-summary">
                              {isExpanded ? findingDescription : clampText(findingDescription)}
                            </p>
                          </div>

                          {isExpanded && (
                            <div className="finding-details" id={`finding-report-${findingKey}`}>
                              <div className="finding-details-grid">
                                <div>
                                  <p className="finding-details-label">Report</p>
                                  <p className="finding-details-text">{findingDescription}</p>
                                </div>

                                {indicators.length > 0 && (
                                  <div>
                                    <p className="finding-details-label">Indicators</p>
                                    <ul className="finding-indicators-list">
                                      {indicators.map((indicator, indicatorIndex) => (
                                        <li key={`${findingKey}-indicator-${indicatorIndex}`}>{indicator}</li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                              </div>

                              <button
                                type="button"
                                className={`finding-action ${isPromoted ? 'finding-action-success' : ''}`}
                                onClick={() => promoteFindingToIncident(finding, findingKey)}
                                disabled={isPromoted || isPromoting}
                              >
                                {isPromoted ? 'Promoted ✓' : isPromoting ? 'Promoting...' : 'Promote to Incident'}
                              </button>
                            </div>
                          )}
                        </>
                      );
                    })()}
                  </li>
                ))}
              </ul>
            )}
          </article>

          <article className="intel-panel mitre-panel" aria-labelledby="mitre-panel-title">
            <h2 id="mitre-panel-title">MITRE Techniques</h2>
            {mitreTechniques.length === 0 ? (
              <p className="intel-empty">No MITRE mappings yet. Techniques appear after completed analysis.</p>
            ) : (
              <ul className="mitre-list mitre-findings-list">
                {mitreTechniques.map((technique) => (
                  <li key={technique.key} className="mitre-item">
                    <div className="finding-toggle">
                      <div className="mitre-head">
                        {technique.attackUrl ? (
                          <a className="finding-title finding-title-toggle mitre-name mitre-direct-link" href={technique.attackUrl} target="_blank" rel="noreferrer">
                            {technique.name}
                          </a>
                        ) : (
                          <p className="finding-title mitre-name">{technique.name}</p>
                        )}
                        <span className="mitre-confidence-label">{technique.confidenceLabel}</span>
                      </div>
                      <p className="mitre-tactic">{`${technique.techniqueId} • ${technique.tactic}`}</p>
                      <div className="mitre-confidence-track" aria-hidden="true">
                        <div className="mitre-confidence-fill" style={{ width: `${Math.round(technique.confidence * 100)}%` }} />
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </article>

          <article className="intel-panel alert-review-panel" aria-labelledby="alert-review-title">
            <h2 id="alert-review-title">Alert Review</h2>
            {topFindings.length === 0 ? (
              <p className="intel-empty">No alerts to review yet. Completed analyses will appear here.</p>
            ) : (
              <ul className="findings-list alert-findings-list">
                {topFindings.map((finding, index) => (
                  <li key={`alert-${finding.threat_type || 'finding'}-${index}`} className="finding-item">
                    {(() => {
                      const alertKey = getFindingKey(finding, index);
                      const isExpanded = expandedAlertKey === alertKey;
                      const isPromoted = promotedFindingKeys.includes(alertKey);
                      const isPromoting = promotingFindingKeys.includes(alertKey);
                      const findingDescription = finding.description || 'Threat summary unavailable.';
                      const indicators = Array.isArray(finding.indicators) ? finding.indicators.filter(Boolean) : [];

                      return (
                        <>
                          <div className="finding-toggle">
                            <div className="finding-head">
                              <span
                                className="finding-title finding-title-toggle"
                                role="button"
                                tabIndex={0}
                                onClick={() => toggleAlert(alertKey)}
                                onKeyDown={(event) => {
                                  if (event.key === 'Enter' || event.key === ' ') {
                                    event.preventDefault();
                                    toggleAlert(alertKey);
                                  }
                                }}
                                aria-expanded={isExpanded}
                                aria-controls={`alert-report-${alertKey}`}
                              >
                                {titleCase(finding.threat_type || 'Threat finding')}
                              </span>
                              <span className={`severity-pill severity-${String(finding.severity || 'medium').toLowerCase()}`}>
                                {titleCase(finding.severity || 'medium')}
                              </span>
                            </div>
                            <p className="finding-summary">
                              {isExpanded ? findingDescription : clampText(findingDescription)}
                            </p>
                          </div>

                          {isExpanded && (
                            <div className="finding-details" id={`alert-report-${alertKey}`}>
                              <div className="finding-details-grid">
                                <div>
                                  <p className="finding-details-label">Report</p>
                                  <p className="finding-details-text">{findingDescription}</p>
                                </div>

                                {indicators.length > 0 && (
                                  <div>
                                    <p className="finding-details-label">Indicators</p>
                                    <ul className="finding-indicators-list">
                                      {indicators.map((indicator, indicatorIndex) => (
                                        <li key={`${alertKey}-indicator-${indicatorIndex}`}>{indicator}</li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                              </div>

                              <button
                                type="button"
                                className={`finding-action ${isPromoted ? 'finding-action-success' : ''}`}
                                onClick={() => promoteFindingToIncident(finding, alertKey)}
                                disabled={isPromoted || isPromoting}
                              >
                                {isPromoted ? 'Promoted ✓' : isPromoting ? 'Promoting...' : 'Promote to Incident'}
                              </button>
                            </div>
                          )}
                        </>
                      );
                    })()}
                  </li>
                ))}
              </ul>
            )}
          </article>
        </section>

        <section aria-labelledby="recent-jobs-title">
          <h2 id="recent-jobs-title">Recent Jobs</h2>
          {isRecentJobsLoading && <p className="jobs-state">Loading recent jobs...</p>}
          {recentJobsError && <p className="jobs-state jobs-state-error">{recentJobsError}</p>}
          {!isRecentJobsLoading && !recentJobsError && recentJobs.length === 0 && (
            <p className="jobs-state">No jobs yet. Upload a file to start analysis.</p>
          )}
          {recentJobs.length > 0 && (
            <div className="jobs-feed">
              <table className="jobs-table">
                <thead>
                  <tr>
                    <th>Filename</th>
                    <th>Status</th>
                    <th>Progress</th>
                    <th>Started</th>
                    <th>Completed</th>
                    <th>Result</th>
                  </tr>
                </thead>
                <tbody>
                  {recentJobs.map((job) => (
                    <tr key={job.id}>
                      <td>{job.filename}</td>
                      <td>
                        <span className="job-status-pill">{titleCase(job.status)}</span>
                      </td>
                      <td>{Math.round(job.progress)}%</td>
                      <td>{formatTimestamp(job.startedAt)}</td>
                      <td>{formatTimestamp(job.completedAt)}</td>
                      <td>
                        {(job.fileId || job.resultId) ? (
                          <button type="button" className="job-result-link" onClick={() => openJobResult(job)}>
                            Open in app
                          </button>
                        ) : (
                          <span className="job-result-link disabled">Pending</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section aria-labelledby="next-steps-title">
          <h2 id="next-steps-title">Next Steps</h2>
          {activeAnalysis ? (
            <>
              <p>
                Recommended follow-up actions based on the latest analysis result.
              </p>
              <ol className="next-steps-list">
                {nextStepActions.map((action, index) => (
                  <li key={`next-step-${index}`} className="next-step-item">
                    <span className="next-step-index">{index + 1}</span>
                    <span className="next-step-text">{action}</span>
                  </li>
                ))}
              </ol>
            </>
          ) : (
            <p>
              Upload a log file to generate remediation guidance, timelines, and findings.
            </p>
          )}
        </section>

        <section aria-labelledby="dashboard-shortcuts-title">
          <h2 id="dashboard-shortcuts-title">Workspaces</h2>
          <p>Open the dedicated collaboration and feedback pages when you need to manage SOC work or review AI responses.</p>
          <div className="dashboard-shortcuts">
            <Link className="upload-submit" to="/workspace">Open Collaborative Workspace</Link>
            <Link className="upload-reset" to="/feedback">Open AI Feedback</Link>
          </div>
        </section>
      </section>
    </div>
  );
}

export default DashboardPage;
