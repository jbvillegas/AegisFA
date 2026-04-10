import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { authenticatedFetch, supabase } from '../client.js';
import { usePersistentState } from '../hooks/use-persistent-state.js';
import '../css/homepage.css';
import '../css/feedback.css';

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

function AIFeedbackPage() {
	const [orgId, setOrgId] = usePersistentState('aegisfa-org-id', '');
	const [feedbackRating, setFeedbackRating] = useState('5');
	const [feedbackSuggestion, setFeedbackSuggestion] = useState('');
	const [feedbackItems, setFeedbackItems] = useState([]);
	const [isLoading, setIsLoading] = useState(false);
	const [errorMessage, setErrorMessage] = useState('');
	const [successMessage, setSuccessMessage] = useState('');

	useEffect(() => {
		let isMounted = true;

		const loadContext = async () => {
			const { data } = await supabase.auth.getUser();
			if (!isMounted) {
				return;
			}

			const user = data?.user || null;
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

	const refreshFeedback = async () => {
		if (!orgId.trim()) {
			setFeedbackItems([]);
			return;
		}

		setIsLoading(true);
		setErrorMessage('');

		try {
			const response = await authenticatedFetch(`${API_BASE_URL}/feedback?org_id=${encodeURIComponent(orgId.trim())}&limit=20`);
			if (!response.ok) {
				throw new Error('Failed to load feedback.');
			}

			const payload = await response.json();
			setFeedbackItems(Array.isArray(payload.items) ? payload.items : []);
		} catch (error) {
			setErrorMessage(error.message || 'Failed to load feedback.');
		} finally {
			setIsLoading(false);
		}
	};

	useEffect(() => {
		refreshFeedback();
	}, [orgId]);

	const submitFeedback = async (event) => {
		event.preventDefault();
		setErrorMessage('');
		setSuccessMessage('');

		try {
			const response = await authenticatedFetch(`${API_BASE_URL}/feedback`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({
					org_id: orgId.trim(),
					rating: Number.parseInt(feedbackRating, 10),
					suggestion_text: feedbackSuggestion.trim(),
				}),
			});

			if (!response.ok) {
				throw new Error('Failed to submit feedback.');
			}

			setFeedbackSuggestion('');
			setFeedbackRating('5');
			setSuccessMessage('Feedback submitted. Thank you.');
			await refreshFeedback();
		} catch (error) {
			setErrorMessage(error.message || 'Failed to submit feedback.');
		}
	};

	return (
		<div className="hp feedback-shell">

			{/* Hero */}
			<section className="hp-hero">
				<div className="hp-hero-inner">
					<p className="hp-kicker">AI Improvement</p>
					<h1 className="hp-hero-title">AI Feedback</h1>
					<p className="hp-hero-sub">
						Rate AI-generated explanations and suggest improvements for future analysis runs. Your feedback helps refine the pipeline.
					</p>
					<div className="upload-context">
						<span>Org context: {orgId || 'Not set'}</span>
						<span>Used to store feedback against your tenant</span>
					</div>
				</div>
				<div className="hp-hero-glow" aria-hidden="true" />
			</section>

			<form className="fb-form" onSubmit={submitFeedback}>
				<label className="field">
					<span className="field-label">Rating (1-5)</span>
					<select value={feedbackRating} onChange={(event) => setFeedbackRating(event.target.value)}>
						<option value="5">5 - Excellent</option>
						<option value="4">4 - Good</option>
						<option value="3">3 - Neutral</option>
						<option value="2">2 - Needs Improvement</option>
						<option value="1">1 - Poor</option>
					</select>
				</label>
				<label className="field">
					<span className="field-label">Suggestion</span>
					<textarea
						value={feedbackSuggestion}
						onChange={(event) => setFeedbackSuggestion(event.target.value)}
						placeholder="Tell us what explanation should improve."
						rows={4}
					/>
				</label>
				<button type="submit" className="upload-submit">Submit Feedback</button>
			</form>

			{isLoading && <p className="jobs-state">Loading feedback history...</p>}
			{errorMessage && <p className="jobs-state jobs-state-error">{errorMessage}</p>}
			{successMessage && <p className="upload-feedback success">{successMessage}</p>}

			<section className="fb-history" aria-labelledby="feedback-history-title">
				<h2 id="feedback-history-title">Recent Feedback</h2>
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
					<Link to="/workspace" className="hp-btn hp-btn-secondary">Open Workspace</Link>
				</div>
			</section>
		</div>
	);
}

export default AIFeedbackPage;