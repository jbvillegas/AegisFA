import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { authenticatedFetch, supabase } from '../client.js';
import { usePersistentState } from '../hooks/use-persistent-state.js';
import '../css/homepage.css';
import '../css/dashboard.css';
import '../css/workspace.css';

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '');

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

function titleCase(value) {
	if (!value) {
		return 'Unknown';
	}

	const normalized = String(value).replace(/[_-]/g, ' ').trim();
	return normalized.charAt(0).toUpperCase() + normalized.slice(1);
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

function CollaborativeWorkspacePage() {
	const [orgId, setOrgId] = usePersistentState('aegisfa-org-id', '');
	const [incidents, setIncidents] = useState([]);
	const [tasks, setTasks] = useState([]);
	const [feedbackItems, setFeedbackItems] = useState([]);
	const [opsLoading, setOpsLoading] = useState(false);
	const [opsError, setOpsError] = useState('');
	const [incidentTitle, setIncidentTitle] = useState('');
	const [incidentSeverity, setIncidentSeverity] = useState('medium');
	const [taskTitle, setTaskTitle] = useState('');
	const [taskIncidentId, setTaskIncidentId] = useState('');
	const [taskAssigneeId, setTaskAssigneeId] = useState('');
	const [successMessage, setSuccessMessage] = useState('');
	const [requestedById, setRequestedById] = useState('');

	useEffect(() => {
		let isMounted = true;

		const loadContext = async () => {
			const { data } = await supabase.auth.getUser();
			if (!isMounted) {
				return;
			}

			const user = data?.user || null;
			setRequestedById(user?.id || '');
			setOrgId((current) => {
				if (isUuid(current)) {
					return current;
				}

				const localOrgId = getLocalOrgId(user);
				return isUuid(localOrgId) ? localOrgId : '';
			});
		};

		loadContext();

		return () => {
			isMounted = false;
		};
	}, [setOrgId]);

	const refreshWorkspace = async () => {
		if (!orgId.trim()) {
			setIncidents([]);
			setTasks([]);
			setFeedbackItems([]);
			return;
		}

		setOpsLoading(true);
		setOpsError('');

		try {
			const [incidentResponse, taskResponse, feedbackResponse] = await Promise.all([
				authenticatedFetch(`${API_BASE_URL}/incidents?org_id=${encodeURIComponent(orgId.trim())}&limit=20`),
				authenticatedFetch(`${API_BASE_URL}/tasks?org_id=${encodeURIComponent(orgId.trim())}&limit=20`),
				authenticatedFetch(`${API_BASE_URL}/feedback?org_id=${encodeURIComponent(orgId.trim())}&limit=10`),
			]);

			if (!incidentResponse.ok) {
				throw new Error('Failed to load incidents.');
			}
			if (!taskResponse.ok) {
				throw new Error('Failed to load tasks.');
			}
			if (!feedbackResponse.ok) {
				throw new Error('Failed to load feedback.');
			}

			const incidentPayload = await incidentResponse.json();
			const taskPayload = await taskResponse.json();
			const feedbackPayload = await feedbackResponse.json();

			setIncidents(Array.isArray(incidentPayload.items) ? incidentPayload.items : []);
			setTasks(Array.isArray(taskPayload.items) ? taskPayload.items : []);
			setFeedbackItems(Array.isArray(feedbackPayload.items) ? feedbackPayload.items : []);
		} catch (error) {
			setOpsError(error.message || 'Failed to load collaborative workspace.');
		} finally {
			setOpsLoading(false);
		}
	};

	useEffect(() => {
		refreshWorkspace();
	}, [orgId]);

	const createIncident = async (event) => {
		event.preventDefault();
		setOpsError('');

		if (!incidentTitle.trim()) {
			setOpsError('Incident title is required.');
			return;
		}

		try {
			const response = await authenticatedFetch(`${API_BASE_URL}/incidents`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({
					org_id: orgId.trim(),
					title: incidentTitle.trim(),
					severity: incidentSeverity,
					status: 'open',
				}),
			});

			if (!response.ok) {
				throw new Error('Failed to create incident.');
			}

			setIncidentTitle('');
			setSuccessMessage('Incident created successfully.');
			await refreshWorkspace();
		} catch (error) {
			setOpsError(error.message || 'Failed to create incident.');
		}
	};

	const createTask = async (event) => {
		event.preventDefault();
		setOpsError('');

		if (!taskTitle.trim()) {
			setOpsError('Task title is required.');
			return;
		}

		if (!taskIncidentId) {
			setOpsError('Select an incident before creating a task.');
			return;
		}

		try {
			const response = await authenticatedFetch(`${API_BASE_URL}/tasks`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({
					org_id: orgId.trim(),
					incident_id: taskIncidentId,
					title: taskTitle.trim(),
					assignee_id: taskAssigneeId.trim() || requestedById || null,
					status: 'pending',
				}),
			});

			if (!response.ok) {
				throw new Error('Failed to create task.');
			}

			setTaskTitle('');
			setTaskAssigneeId('');
			setSuccessMessage('Task created successfully.');
			await refreshWorkspace();
		} catch (error) {
			setOpsError(error.message || 'Failed to create task.');
		}
	};

	const updateIncidentStatus = async (incidentId, status) => {
		setOpsError('');
		try {
			const response = await authenticatedFetch(`${API_BASE_URL}/incidents/${incidentId}`, {
				method: 'PATCH',
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({ status }),
			});

			if (!response.ok) {
				throw new Error('Failed to update incident status.');
			}

			await refreshWorkspace();
		} catch (error) {
			setOpsError(error.message || 'Failed to update incident status.');
		}
	};

	const updateTaskStatus = async (taskId, status) => {
		setOpsError('');
		try {
			const response = await authenticatedFetch(`${API_BASE_URL}/tasks/${taskId}`, {
				method: 'PATCH',
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({ status }),
			});

			if (!response.ok) {
				throw new Error('Failed to update task status.');
			}

			await refreshWorkspace();
		} catch (error) {
			setOpsError(error.message || 'Failed to update task status.');
		}
	};

	return (
		<div className="hp workspace-shell">

			{/* Hero */}
			<section className="hp-hero">
				<div className="hp-hero-inner">
					<p className="hp-kicker">Collaboration</p>
					<h1 className="hp-hero-title">Collaborative Workspace</h1>
					<p className="hp-hero-sub">
						Assign tasks, review alerts, and track incident status in one place. All data is scoped to your organization.
					</p>
					<div className="upload-context">
						<span>Org context: {orgId || 'Not set'}</span>
						<span>Live data from incidents, tasks, and feedback endpoints</span>
					</div>
				</div>
				<div className="hp-hero-glow" aria-hidden="true" />
			</section>

			{opsLoading && <p className="jobs-state">Refreshing workspace...</p>}
			{opsError && <p className="jobs-state jobs-state-error">{opsError}</p>}
			{successMessage && <p className="upload-feedback success">{successMessage}</p>}

			<div className="upload-form-grid workspace-form-grid">
				<form className="field" onSubmit={createIncident}>
					<span className="field-label">New Incident</span>
					<input
						type="text"
						value={incidentTitle}
						onChange={(event) => setIncidentTitle(event.target.value)}
						placeholder="Incident title"
					/>
					<select value={incidentSeverity} onChange={(event) => setIncidentSeverity(event.target.value)}>
						<option value="low">Low</option>
						<option value="medium">Medium</option>
						<option value="high">High</option>
						<option value="critical">Critical</option>
					</select>
					<button type="submit" className="upload-submit">Create Incident</button>
				</form>

				<form className="field" onSubmit={createTask}>
					<span className="field-label">New Task</span>
					<input
						type="text"
						value={taskTitle}
						onChange={(event) => setTaskTitle(event.target.value)}
						placeholder="Task title"
					/>
					<select value={taskIncidentId} onChange={(event) => setTaskIncidentId(event.target.value)}>
						<option value="">Select incident</option>
						{incidents.map((incident) => (
							<option key={incident.id} value={incident.id}>{incident.title}</option>
						))}
					</select>
					<input
						type="text"
						value={taskAssigneeId}
						onChange={(event) => setTaskAssigneeId(event.target.value)}
						placeholder="Assignee user id (optional)"
					/>
					<button type="submit" className="upload-submit">Create Task</button>
				</form>
			</div>

			<div className="jobs-feed">
				<table className="jobs-table">
					<thead>
						<tr>
							<th>Incident</th>
							<th>Status</th>
							<th>Severity</th>
						</tr>
					</thead>
					<tbody>
						{incidents.map((incident) => (
							<tr key={incident.id}>
								<td>{incident.title}</td>
								<td>
									<select
										value={incident.status || 'open'}
										onChange={(event) => updateIncidentStatus(incident.id, event.target.value)}
									>
										<option value="open">Open</option>
										<option value="in_progress">In Progress</option>
										<option value="resolved">Resolved</option>
										<option value="closed">Closed</option>
									</select>
								</td>
								<td>{titleCase(incident.severity)}</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>

			<div className="jobs-feed">
				<table className="jobs-table">
					<thead>
						<tr>
							<th>Task</th>
							<th>Status</th>
							<th>Assignee</th>
							<th>Action</th>
						</tr>
					</thead>
					<tbody>
						{tasks.map((task) => (
							<tr key={task.id}>
								<td>{task.title}</td>
								<td>{titleCase(task.status)}</td>
								<td>{task.assignee_id ? 'Assigned' : 'Unassigned'}</td>
								<td>
									<select
										value={task.status || 'pending'}
										onChange={(event) => updateTaskStatus(task.id, event.target.value)}
									>
										<option value="pending">Pending</option>
										<option value="in_progress">In Progress</option>
										<option value="done">Done</option>
									</select>
								</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>

			<section className="ws-section" aria-labelledby="collab-feedback-title">
				<h2 id="collab-feedback-title">Recent Feedback</h2>
				{feedbackItems.length === 0 ? (
					<p className="panel-muted">No feedback submitted yet.</p>
				) : (
					<ul className="feedback-list">
						{feedbackItems.map((item) => (
							<li key={item.id} className="feedback-item">
								<div className="finding-head">
									<p className="finding-title">Rating {item.rating}/5</p>
									<span className="severity-pill">{formatTimestamp(item.created_at)}</span>
								</div>
								<p className="finding-summary">{item.suggestion_text || 'No written suggestion provided.'}</p>
							</li>
						))}
					</ul>
				)}
			</section>

			<section className="hp-cta">
				<h2>Return to Dashboard</h2>
				<p>Jump back to the main analysis dashboard to upload files and review results.</p>
				<div className="hp-hero-actions">
					<Link to="/dashboard" className="hp-btn hp-btn-primary">Open Dashboard</Link>
					<Link to="/feedback" className="hp-btn hp-btn-secondary">AI Feedback</Link>
				</div>
			</section>
		</div>
	);
}

export default CollaborativeWorkspacePage;