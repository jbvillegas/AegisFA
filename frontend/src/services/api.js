const BASE = process.env.REACT_APP_BACKEND_URL || 'http://localhost:5001';

async function apiFetch(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }));
    throw new Error(err.error?.message || err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

export const checkHealth = () => apiFetch('/health');
export const listFiles = (orgId) => apiFetch(`/files?org_id=${orgId}`);
export const getAnalysis = (fileId) => apiFetch(`/analysis/${fileId}`);
export const getDetections = (orgId, fileId) => {
  const params = new URLSearchParams({ org_id: orgId });
  if (fileId) params.append('file_id', fileId);
  return apiFetch(`/detections?${params}`);
};

export const uploadLogFile = async (file, sourceType, orgId) => {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('source_type', sourceType);
  formData.append('org_id', orgId);
  const res = await fetch(`${BASE}/upload`, { method: 'POST', body: formData });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Upload failed' }));
    throw new Error(err.error?.message || err.error || `HTTP ${res.status}`);
  }
  return res.json();
};
