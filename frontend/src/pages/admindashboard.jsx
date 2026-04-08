import { useEffect, useState } from 'react';
import SearchBar from '../components/search-bar.jsx';
import { supabase } from '../client.js';
import { usePersistentState } from '../hooks/use-persistent-state.js';
import '../css/admindashboard.css';

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '');

const SEVERITY_WEIGHT = {
	critical: 4,
	high: 3,
	medium: 2,
	low: 1,
};

function formatTimestamp(timestamp) {
	if (!timestamp) {
		return 'Unknown time';
	}

	const date = new Date(timestamp);
	if (Number.isNaN(date.getTime())) {
		return String(timestamp);
	}

	return date.toLocaleString();
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

function getSeverityScore(value) {
	return SEVERITY_WEIGHT[String(value || 'medium').toLowerCase()] || 0;
}

async function fetchLatestCompletedFileForOrg(orgId) {
	const candidates = ['uploaded_at', 'created_at'];

	for (const timestampField of candidates) {
		const result = await supabase
			.from('log_files')
			.select(`id, ${timestampField}`)
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
		.select('id')
		.eq('org_id', orgId)
		.eq('status', 'completed')
		.limit(1);

	if (fallback.error) {
		throw fallback.error;
	}

	return fallback.data?.[0] || null;
}

function AdminDashboard() {
	const [orgId, setOrgId] = usePersistentState('aegisfa-org-id', '');
	const [timelineEvents, setTimelineEvents] = useState([]);
	const [importantFindings, setImportantFindings] = useState([]);
	const [isLoading, setIsLoading] = useState(false);
	const [loadError, setLoadError] = useState('');
	const [latestFileId, setLatestFileId] = useState('');

	useEffect(() => {
		let isMounted = true;

		const loadContext = async () => {
			if (orgId && isMounted) {
				return;
			}

			const { data } = await supabase.auth.getUser();
			if (!isMounted) {
				return;
			}

			const derivedOrgId = getLocalOrgId(data?.user || null);
			if (isUuid(derivedOrgId)) {
				setOrgId(derivedOrgId);
			}
		};

		loadContext();

		return () => {
			isMounted = false;
		};
	}, [orgId, setOrgId]);

	useEffect(() => {
		const loadTimelinePreview = async () => {
			if (!orgId.trim()) {
				setTimelineEvents([]);
				setImportantFindings([]);
				return;
			}

			setIsLoading(true);
			setLoadError('');

			try {
				const latestFile = await fetchLatestCompletedFileForOrg(orgId.trim());
				if (!latestFile?.id) {
					setTimelineEvents([]);
					setImportantFindings([]);
					setLatestFileId('');
					return;
				}

				setLatestFileId(latestFile.id);
				let analysis = null;
				const analysisResponse = await fetch(`${API_BASE_URL}/analysis/${latestFile.id}?include_mitre_links=false`);
				if (analysisResponse.ok) {
					analysis = await analysisResponse.json();
				}

				let timeline = Array.isArray(analysis?.timeline) ? analysis.timeline : [];
				const findings = Array.isArray(analysis?.detailed_findings) ? analysis.detailed_findings : [];

				if (timeline.length === 0) {
					const timelineResponse = await fetch(`${API_BASE_URL}/timeline/file/${latestFile.id}?page=1&page_size=20`);
					if (timelineResponse.ok) {
						const timelinePayload = await timelineResponse.json();
						timeline = (timelinePayload.items || []).map((item) => ({
							event: item.summary || item.type || 'Timeline event',
							timestamp: item.timestamp,
							description: item.details?.description || '',
						}));
					}
				}

				if (timeline.length === 0) {
					const orgTimelineResponse = await fetch(`${API_BASE_URL}/timeline/org/${orgId.trim()}?page=1&page_size=20`);
					if (orgTimelineResponse.ok) {
						const orgTimelinePayload = await orgTimelineResponse.json();
						timeline = (orgTimelinePayload.items || []).map((item) => ({
							event: item.summary || item.type || 'Timeline event',
							timestamp: item.timestamp,
							description: item.details?.description || '',
						}));
					}
				}

				const recentTimeline = timeline
					.map((item, index) => ({
						id: `timeline-${index}`,
						title: item.event || 'Timeline event',
						timestamp: item.timestamp || analysis?.created_at,
						description: item.description || item.details || '',
					}))
					.sort((left, right) => {
						const leftTime = new Date(left.timestamp).getTime();
						const rightTime = new Date(right.timestamp).getTime();
						if (Number.isNaN(leftTime) || Number.isNaN(rightTime)) {
							return 0;
						}
						return rightTime - leftTime;
					})
					.slice(0, 4);

				const topFindings = findings
					.map((finding, index) => ({
						id: `finding-${index}`,
						threatType: finding.threat_type || 'Threat finding',
						severity: finding.severity || 'medium',
						description: finding.description || 'No summary available.',
					}))
					.sort((left, right) => getSeverityScore(right.severity) - getSeverityScore(left.severity))
					.slice(0, 3);

				setTimelineEvents(recentTimeline);
				setImportantFindings(topFindings);
			} catch (error) {
				setLoadError(error.message || 'Failed to load timeline preview.');
			} finally {
				setIsLoading(false);
			}
		};

		loadTimelinePreview();
	}, [orgId]);

	return (
		<section className="panel admin-page">
			<h1>Admin Dashboard</h1>
			<p>Monitor file timeline and key events.</p>
			<SearchBar />

			<section className="admin-section" aria-labelledby="timeline-preview-title">
				<h2 id="timeline-preview-title">Timeline Preview</h2>
				{isLoading && <p className="panel-muted">Loading recent events...</p>}
				{loadError && <p className="panel-error">{loadError}</p>}
				{!isLoading && !loadError && timelineEvents.length === 0 && (
					<p className="panel-muted">No timeline events available yet.</p>
				)}
				{timelineEvents.length > 0 && (
					<ul className="timeline-list">
						{timelineEvents.map((event) => (
							<li key={event.id} className="timeline-item">
								<p className="timeline-title">{event.title}</p>
								<p className="timeline-time">{formatTimestamp(event.timestamp)}</p>
								{event.description && <p className="timeline-description">{event.description}</p>}
							</li>
						))}
					</ul>
				)}
			</section>

			<section className="admin-section" aria-labelledby="important-events-title">
				<h2 id="important-events-title">Most Important Events</h2>
				{importantFindings.length === 0 ? (
					<p className="panel-muted">No high-priority findings available for the latest file.</p>
				) : (
					<ul className="finding-preview-list">
						{importantFindings.map((finding) => (
							<li key={finding.id} className="finding-preview-item">
								<div className="finding-preview-head">
									<p>{finding.threatType}</p>
									<span className={`severity-tag severity-${String(finding.severity).toLowerCase()}`}>
										{finding.severity}
									</span>
								</div>
								<p className="timeline-description">{finding.description}</p>
							</li>
						))}
					</ul>
				)}
				{latestFileId && (
					<a className="panel-action-link" href={`${API_BASE_URL}/analysis/${latestFileId}`} target="_blank" rel="noreferrer">
						Open latest full result
					</a>
				)}
			</section>
		</section>
	);
}

export default AdminDashboard;
