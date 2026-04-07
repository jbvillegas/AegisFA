import { useEffect, useState } from 'react';
import SearchBar from '../components/search-bar.jsx';
import { supabase } from '../client.js';
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
		(user?.email ? user.email.split('@')[0] : '')
	);
}

function getSeverityScore(value) {
	return SEVERITY_WEIGHT[String(value || 'medium').toLowerCase()] || 0;
}

async function fetchLatestCompletedFileForOrg(orgId) {
	const primary = await supabase
		.from('log_files')
		.select('id, created_at')
		.eq('org_id', orgId)
		.eq('status', 'completed')
		.order('created_at', { ascending: false })
		.limit(1);

	if (!primary.error) {
		return primary.data?.[0] || null;
	}

	if (!String(primary.error.message || '').includes('created_at')) {
		throw primary.error;
	}

	const fallback = await supabase
		.from('log_files')
		.select('id, uploaded_at')
		.eq('org_id', orgId)
		.eq('status', 'completed')
		.order('uploaded_at', { ascending: false })
		.limit(1);

	if (fallback.error) {
		throw fallback.error;
	}

	return fallback.data?.[0] || null;
}

function AdminDashboard() {
	const [orgId, setOrgId] = useState('');
	const [timelineEvents, setTimelineEvents] = useState([]);
	const [importantFindings, setImportantFindings] = useState([]);
	const [isLoading, setIsLoading] = useState(false);
	const [loadError, setLoadError] = useState('');
	const [latestFileId, setLatestFileId] = useState('');

	useEffect(() => {
		let isMounted = true;

		const loadContext = async () => {
			const localOrgId = window.localStorage.getItem('aegisfa-org-id');
			if (localOrgId && isMounted) {
				setOrgId(localOrgId);
				return;
			}

			const { data } = await supabase.auth.getUser();
			if (!isMounted) {
				return;
			}

			setOrgId(getLocalOrgId(data?.user || null));
		};

		loadContext();

		return () => {
			isMounted = false;
		};
	}, []);

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
				const analysisResponse = await fetch(`${API_BASE_URL}/analysis/${latestFile.id}?include_mitre_links=false`);
				if (!analysisResponse.ok) {
					throw new Error('Failed to load analysis timeline.');
				}

				const analysis = await analysisResponse.json();
				const timeline = Array.isArray(analysis.timeline) ? analysis.timeline : [];
				const findings = Array.isArray(analysis.detailed_findings) ? analysis.detailed_findings : [];

				const recentTimeline = timeline
					.map((item, index) => ({
						id: `timeline-${index}`,
						title: item.event || 'Timeline event',
						timestamp: item.timestamp || analysis.created_at,
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
