import { useEffect, useRef, useState } from 'react';
import SearchBar from '../components/search-bar.jsx';
import { authenticatedFetch, supabase } from '../client.js';
import { usePersistentState } from '../hooks/use-persistent-state.js';
import '../css/homepage.css';
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

async function resolveOrgId(user) {
	const localOrgId = getLocalOrgId(user);
	if (isUuid(localOrgId)) {
		return localOrgId;
	}

	const userId = user?.id;
	if (!isUuid(userId)) {
		return '';
	}

	const orgLookup = await supabase
		.from('users')
		.select('org_id')
		.eq('id', userId)
		.limit(1);

	if (orgLookup.error) {
		return '';
	}

	const dbOrgId = orgLookup.data?.[0]?.org_id || '';
	return isUuid(dbOrgId) ? dbOrgId : '';
}

function isUuid(value) {
	return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || '').trim());
}

function getSeverityScore(value) {
	return SEVERITY_WEIGHT[String(value || 'medium').toLowerCase()] || 0;
}

function buildGraphLayout(nodes, width = 760, height = 260) {
	const lanes = {
		event: 0,
		detection: 1,
		ai_narrative: 2,
	};
	const ordered = [...nodes].sort((left, right) => {
		const leftTime = new Date(left.timestamp || '').getTime();
		const rightTime = new Date(right.timestamp || '').getTime();
		if (Number.isFinite(leftTime) && Number.isFinite(rightTime) && leftTime !== rightTime) {
			return leftTime - rightTime;
		}
		return String(left.label || '').localeCompare(String(right.label || ''));
	});

	const positioned = {};
	ordered.forEach((node, index) => {
		const lane = lanes[node.kind] ?? 1;
		const x = ((index + 1) / (ordered.length + 1)) * width;
		const laneY = ((lane + 1) / 4) * height;
		const yOffset = ((index % 5) - 2) * 6;
		positioned[node.id] = {
			...node,
			x,
			y: laneY + yOffset,
		};
	});

	return positioned;
}

function buildDisplayEdges(nodes, edges) {
	if (Array.isArray(edges) && edges.length > 0) {
		return edges;
	}

	if (!Array.isArray(nodes) || nodes.length < 2) {
		return [];
	}

	const ordered = [...nodes].sort((left, right) => {
		const leftTime = new Date(left.timestamp || '').getTime();
		const rightTime = new Date(right.timestamp || '').getTime();
		if (Number.isFinite(leftTime) && Number.isFinite(rightTime) && leftTime !== rightTime) {
			return leftTime - rightTime;
		}
		return String(left.label || '').localeCompare(String(right.label || ''));
	});

	const fallbackEdges = [];
	for (let index = 1; index < ordered.length; index += 1) {
		fallbackEdges.push({
			id: `fallback-${index}`,
			source: ordered[index - 1].id,
			target: ordered[index].id,
			relation: 'fallback',
		});
	}

	return fallbackEdges;
}

function formatNodeKind(kind) {
	if (kind === 'ai_narrative') {
		return 'AI Narrative';
	}
	if (kind === 'detection') {
		return 'Detection';
	}
	if (kind === 'event') {
		return 'Event';
	}
	return 'Timeline Node';
}

function buildGraphNodeDescription(node) {
	if (!node) {
		return '';
	}

	const pieces = [];
	if (node.label) {
		pieces.push(String(node.label));
	}
	if (node.severity) {
		pieces.push(`Severity: ${String(node.severity)}`);
	}
	if (node.timestamp) {
		pieces.push(`Time: ${formatTimestamp(node.timestamp)}`);
	}

	return pieces.join(' | ');
}

function buildGraphNodeMetadata(node) {
	if (!node) {
		return [];
	}

	return [
		{ label: 'Node ID', value: node.id || 'Unknown' },
		{ label: 'Type', value: formatNodeKind(node.kind) },
		{ label: 'Severity', value: node.severity || 'Not set' },
		{ label: 'Timestamp', value: formatTimestamp(node.timestamp) },
		{ label: 'Source file', value: node.file_id || 'Unknown' },
	];
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

	if (fallback.data?.[0]) {
		return fallback.data[0];
	}

	// Final fallback: use the most recent file regardless of status.
	for (const timestampField of candidates) {
		const anyRecent = await supabase
			.from('log_files')
			.select(`id, status, ${timestampField}`)
			.eq('org_id', orgId)
			.order(timestampField, { ascending: false })
			.limit(1);

		if (!anyRecent.error) {
			return anyRecent.data?.[0] || null;
		}

		const message = String(anyRecent.error.message || '').toLowerCase();
		if (!(message.includes(timestampField) && message.includes('column'))) {
			throw anyRecent.error;
		}
	}

	const minimalRecent = await supabase
		.from('log_files')
		.select('id, status')
		.eq('org_id', orgId)
		.limit(1);

	if (minimalRecent.error) {
		throw minimalRecent.error;
	}

	return minimalRecent.data?.[0] || null;
}

async function fetchCompletedFilesForOrg(orgId, sortOrder = 'newest') {
	const ascending = sortOrder === 'oldest';
	for (const timestampField of ['uploaded_at', 'created_at']) {
		const primary = await supabase
			.from('log_files')
			.select(`id, filename, status, ${timestampField}`)
			.eq('org_id', orgId)
			.eq('status', 'completed')
			.order(timestampField, { ascending })
			.limit(50);

		if (!primary.error) {
			return primary.data || [];
		}

		const message = String(primary.error.message || '').toLowerCase();
		if (!(message.includes(timestampField) && message.includes('column'))) {
			throw primary.error;
		}
	}

	const fallback = await supabase
		.from('log_files')
		.select('id, filename, status')
		.eq('org_id', orgId)
		.eq('status', 'completed')
		.limit(50);

	if (fallback.error) {
		throw fallback.error;
	}

	return fallback.data || [];
}

function AdminDashboard() {
	const [orgId, setOrgId] = usePersistentState('aegisfa-org-id', '');
	const [timelineEvents, setTimelineEvents] = useState([]);
	const [importantFindings, setImportantFindings] = useState([]);
	const [isLoading, setIsLoading] = useState(false);
	const [loadError, setLoadError] = useState('');
	const [latestFileId, setLatestFileId] = useState('');
	const [graphNodes, setGraphNodes] = useState([]);
	const [graphEdges, setGraphEdges] = useState([]);
	const [graphMessage, setGraphMessage] = useState('');
	const [availableFiles, setAvailableFiles] = useState([]);
	const [selectedFileId, setSelectedFileId] = useState('latest');
	const [fileSortOrder, setFileSortOrder] = useState('newest');
	const [hoveredGraphNode, setHoveredGraphNode] = useState(null);
	const [selectedGraphNodeId, setSelectedGraphNodeId] = useState('');
	const [graphTooltipPos, setGraphTooltipPos] = useState({ x: 0, y: 0 });
	const graphWrapRef = useRef(null);

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

			const derivedOrgId = await resolveOrgId(data?.user || null);
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
		const loadFileOptions = async () => {
			if (!orgId.trim()) {
				setAvailableFiles([]);
				setSelectedFileId('latest');
				return;
			}

			try {
				const files = await fetchCompletedFilesForOrg(orgId.trim(), fileSortOrder);
				setAvailableFiles(files);
			} catch (_error) {
				setAvailableFiles([]);
			}
		};

		loadFileOptions();
	}, [orgId, fileSortOrder]);

	useEffect(() => {
		const loadTimelinePreview = async () => {
			if (!orgId.trim()) {
				setTimelineEvents([]);
				setImportantFindings([]);
				return;
			}

			setIsLoading(true);
			setLoadError('');
			setGraphMessage('');

			try {
				let timeline = [];

				const orgTimelineResponse = await authenticatedFetch(`${API_BASE_URL}/timeline/org/${orgId.trim()}?page=1&page_size=20`);
				if (orgTimelineResponse.ok) {
					const orgTimelinePayload = await orgTimelineResponse.json();
					timeline = (orgTimelinePayload.items || []).map((item) => ({
						event: item.summary || item.type || 'Timeline event',
						timestamp: item.timestamp,
						description: item.details?.description || '',
					}));
				}

				const latestFile = await fetchLatestCompletedFileForOrg(orgId.trim());
				const explicitSelectedFile = selectedFileId !== 'latest'
					? availableFiles.find((file) => file.id === selectedFileId)
					: null;
				const targetFile = explicitSelectedFile || latestFile;
				if (!targetFile?.id) {
					let orgGraphPayload = null;
					try {
						const orgGraphResponse = await authenticatedFetch(`${API_BASE_URL}/timeline/org/${orgId.trim()}/graph?max_nodes=100`);
						if (orgGraphResponse.ok) {
							orgGraphPayload = await orgGraphResponse.json();
						}
					} catch (_graphError) {
						orgGraphPayload = null;
					}

					const recentTimeline = timeline
						.map((item, index) => ({
							id: `timeline-${index}`,
							title: item.event || 'Timeline event',
							timestamp: item.timestamp,
							description: item.description || '',
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

					setTimelineEvents(recentTimeline);
					setImportantFindings([]);
					setGraphNodes(Array.isArray(orgGraphPayload?.graph?.nodes) ? orgGraphPayload.graph.nodes : []);
					setGraphEdges(Array.isArray(orgGraphPayload?.graph?.edges) ? orgGraphPayload.graph.edges : []);
					if (!orgGraphPayload?.graph?.nodes?.length) {
						setGraphMessage('Graph unavailable for current org context. This can happen when there are no linked detections or narrative edges yet.');
					}
					setLatestFileId('');
					return;
				}

				setLatestFileId(targetFile.id);
				let analysis = null;
				const analysisResponse = await authenticatedFetch(`${API_BASE_URL}/analysis/${targetFile.id}?include_mitre_links=false`);
				if (analysisResponse.ok) {
					analysis = await analysisResponse.json();
				}

				timeline = timeline.length > 0
					? timeline
					: (Array.isArray(analysis?.timeline) ? analysis.timeline : []);
				const findings = Array.isArray(analysis?.detailed_findings) ? analysis.detailed_findings : [];

				if (timeline.length === 0) {
					const timelineResponse = await authenticatedFetch(`${API_BASE_URL}/timeline/file/${targetFile.id}?page=1&page_size=20`);
					if (timelineResponse.ok) {
						const timelinePayload = await timelineResponse.json();
						timeline = (timelinePayload.items || []).map((item) => ({
							event: item.summary || item.type || 'Timeline event',
							timestamp: item.timestamp,
							description: item.details?.description || '',
						}));
					}
				}

				let graphPayload = null;
				try {
					const fileGraphResponse = await authenticatedFetch(`${API_BASE_URL}/timeline/file/${targetFile.id}/graph?max_nodes=80`);
					if (fileGraphResponse.ok) {
						graphPayload = await fileGraphResponse.json();
					}

					const fileGraphNodeCount = Array.isArray(graphPayload?.graph?.nodes) ? graphPayload.graph.nodes.length : 0;
					if (!fileGraphResponse.ok || fileGraphNodeCount === 0) {
						const orgGraphResponse = await authenticatedFetch(`${API_BASE_URL}/timeline/org/${orgId.trim()}/graph?max_nodes=100`);
						if (orgGraphResponse.ok) {
							graphPayload = await orgGraphResponse.json();
						}
					}
				} catch (_graphError) {
					// Graph errors should not block timeline and findings preview.
					graphPayload = null;
				}

				if (timeline.length === 0) {
					const orgTimelineRetryResponse = await authenticatedFetch(`${API_BASE_URL}/timeline/org/${orgId.trim()}?page=1&page_size=20`);
					if (orgTimelineRetryResponse.ok) {
						const orgTimelinePayload = await orgTimelineRetryResponse.json();
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
				setGraphNodes(Array.isArray(graphPayload?.graph?.nodes) ? graphPayload.graph.nodes : []);
				setGraphEdges(Array.isArray(graphPayload?.graph?.edges) ? graphPayload.graph.edges : []);
				if (!graphPayload?.graph?.nodes?.length) {
					setGraphMessage('No relationship graph nodes were returned. Timeline events exist, but relationship links may not have been generated yet.');
				}
			} catch (error) {
				setLoadError(error.message || 'Failed to load timeline preview.');
				setGraphMessage('Graph loading failed due to request or permission issues.');
			} finally {
				setIsLoading(false);
			}
		};

		loadTimelinePreview();
	}, [orgId, selectedFileId, availableFiles]);

	const positionedNodes = buildGraphLayout(graphNodes, 760, 260);
	const displayEdges = buildDisplayEdges(graphNodes, graphEdges);
	const eventNodeCount = graphNodes.filter((node) => node.kind === 'event').length;
	const detectionNodeCount = graphNodes.filter((node) => node.kind === 'detection').length;
	const narrativeNodeCount = graphNodes.filter((node) => node.kind === 'ai_narrative').length;
	const hasEvidenceGap = graphNodes.length > 0 && (eventNodeCount === 0 || detectionNodeCount === 0);
	const selectedGraphNode = graphNodes.find((node) => node.id === selectedGraphNodeId) || null;
	const activeGraphNode = hoveredGraphNode || selectedGraphNode;
	const activeGraphNodeEdgeCount = activeGraphNode
		? graphEdges.filter((edge) => edge.source === activeGraphNode.id || edge.target === activeGraphNode.id).length
		: 0;

	useEffect(() => {
		if (selectedGraphNodeId && !graphNodes.some((node) => node.id === selectedGraphNodeId)) {
			setSelectedGraphNodeId('');
		}
	}, [graphNodes, selectedGraphNodeId]);

	const updateTooltipPosition = (event) => {
		const wrapEl = graphWrapRef.current;
		if (!wrapEl) {
			return;
		}
		const rect = wrapEl.getBoundingClientRect();
		setGraphTooltipPos({
			x: event.clientX - rect.left + 12,
			y: event.clientY - rect.top + 12,
		});
	};

	const handleNodeMouseEnter = (node, event) => {
		setHoveredGraphNode(node);
		updateTooltipPosition(event);
	};

	const handleNodeClick = (node) => {
		setSelectedGraphNodeId(node.id);
	};

	const handleNodeMouseMove = (event) => {
		updateTooltipPosition(event);
	};

	const clearNodeHover = () => {
		setHoveredGraphNode(null);
	};

	const clearSelectedGraphNode = () => {
		setSelectedGraphNodeId('');
	};

	return (
		<div className="hp admin-shell">

			{/* Hero */}
			<section className="hp-hero">
				<div className="hp-hero-inner">
					<p className="hp-kicker">Administration</p>
					<h1 className="hp-hero-title">Admin Dashboard</h1>
					<p className="hp-hero-sub">
						Monitor file timelines, review key events, and inspect relationship graphs across your organization.
					</p>
				</div>
				<div className="hp-hero-glow" aria-hidden="true" />
			</section>
			
			<section className="admin-section" aria-labelledby="timeline-preview-title">
				<h2 id="timeline-preview-title">Timeline Preview</h2>
				<div className="timeline-controls">
					<label>
						<span>File order</span>
						<select value={fileSortOrder} onChange={(event) => setFileSortOrder(event.target.value)}>
							<option value="newest">Newest analyzed first</option>
							<option value="oldest">Oldest analyzed first</option>
						</select>
					</label>
					<label>
						<span>Timeline file</span>
						<select value={selectedFileId} onChange={(event) => setSelectedFileId(event.target.value)}>
							<option value="latest">Latest analyzed file</option>
							{availableFiles.map((file) => (
								<option key={file.id} value={file.id}>
									{file.filename || file.id}
								</option>
							))}
						</select>
					</label>
				</div>
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

			<section className="admin-section" aria-labelledby="timeline-graph-title">
				<h2 id="timeline-graph-title">Relationship Graph</h2>
				{graphNodes.length > 0 && (
					<div className="graph-breakdown" aria-label="Graph node breakdown">
						<span>Events: {eventNodeCount}</span>
						<span>Detections: {detectionNodeCount}</span>
						<span>AI Narrative: {narrativeNodeCount}</span>
						<span>Edges: {displayEdges.length}</span>
					</div>
				)}
				{hasEvidenceGap && (
					<p className="panel-warning">
						Graph has limited evidence linkage for this file: {eventNodeCount === 0 ? 'no raw event nodes' : 'raw events present'} and {detectionNodeCount === 0 ? 'no detection nodes' : 'detections present'}.
					</p>
				)}
				{graphNodes.length === 0 ? (
					<p className="panel-muted">{graphMessage || 'Graph is not available yet for the selected context.'}</p>
				) : (
					<div
						className="timeline-graph-wrap"
						role="img"
						aria-label="Event relationship graph"
						onMouseLeave={clearNodeHover}
						ref={graphWrapRef}
					>
						{hoveredGraphNode && (
							<div
								className="graph-node-tooltip"
								style={{ left: `${graphTooltipPos.x}px`, top: `${graphTooltipPos.y}px` }}
							>
								<p className="graph-node-tooltip-title">{formatNodeKind(hoveredGraphNode.kind)}</p>
								<p className="graph-node-tooltip-body">{buildGraphNodeDescription(hoveredGraphNode)}</p>
							</div>
						)}
						<svg viewBox="0 0 760 260" className="timeline-graph-svg">
							{displayEdges.map((edge) => {
								const source = positionedNodes[edge.source];
								const target = positionedNodes[edge.target];
								if (!source || !target) {
									return null;
								}
								return (
									<line
										key={edge.id}
										x1={source.x}
										y1={source.y}
										x2={target.x}
										y2={target.y}
										className={`graph-edge graph-edge-${edge.relation}`}
									/>
								);
							})}

							{graphNodes.map((node) => {
								const point = positionedNodes[node.id];
								if (!point) {
									return null;
								}
								return (
									<g key={node.id}>
										<circle
											cx={point.x}
											cy={point.y}
											r="8"
											className={`graph-node graph-node-${node.kind}`}
											onMouseEnter={(event) => handleNodeMouseEnter(node, event)}
											onMouseMove={handleNodeMouseMove}
											onMouseLeave={clearNodeHover}
											onClick={() => handleNodeClick(node)}
											role="button"
											tabIndex={0}
											aria-pressed={selectedGraphNodeId === node.id}
											onKeyDown={(event) => {
												if (event.key === 'Enter' || event.key === ' ') {
													event.preventDefault();
													handleNodeClick(node);
												}
											}}
										/>
										<title>{buildGraphNodeDescription(node)}</title>
									</g>
								);
							})}
						</svg>
						{selectedGraphNode && (
							<div className="graph-node-detail">
								<div className="graph-node-detail-head">
									<div>
										<p className="graph-node-detail-kicker">Selected Node</p>
										<h3>{formatNodeKind(selectedGraphNode.kind)}</h3>
									</div>
									<button type="button" className="graph-node-detail-clear" onClick={clearSelectedGraphNode}>
										Clear
									</button>
								</div>
								<p className="graph-node-detail-summary">{buildGraphNodeDescription(selectedGraphNode)}</p>
								<div className="graph-node-detail-meta">
									{buildGraphNodeMetadata(selectedGraphNode).map((item) => (
										<div key={item.label}>
											<span>{item.label}</span>
											<strong>{item.value}</strong>
										</div>
									))}
									<div>
										<span>Connected edges</span>
										<strong>{activeGraphNodeEdgeCount}</strong>
									</div>
								</div>
							</div>
						)}
						<div className="timeline-graph-legend">
							<span><i className="legend-dot event" /> Events</span>
							<span><i className="legend-dot detection" /> Detections</span>
							<span><i className="legend-dot ai" /> AI Narrative</span>
						</div>
					</div>
				)}
			</section>
		</div>
	);
}

export default AdminDashboard;
