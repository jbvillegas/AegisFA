import { createClient } from '@supabase/supabase-js';

const supabaseURL =
	import.meta.env.VITE_SUPABASE_URL ||
	import.meta.env.REACT_APP_SUPABASE_URL;
const apiKey =
	import.meta.env.VITE_API_KEY ||
	import.meta.env.VITE_SUPABASE_ANON_KEY ||
	import.meta.env.REACT_APP_SUPABASE_ANON_KEY ||
	'';

if (!supabaseURL) {
	throw new Error(
		'Missing Supabase URL. Set VITE_SUPABASE_URL or REACT_APP_SUPABASE_URL in your env file.'
	);
}

if (!apiKey) {
	throw new Error(
		'Missing Supabase anonymous key. Set VITE_SUPABASE_ANON_KEY, VITE_API_KEY, or REACT_APP_SUPABASE_ANON_KEY in your env file.'
	);
}

export const supabase = createClient(supabaseURL, apiKey);

class HttpAuthError extends Error {
	constructor(message, status) {
		super(message);
		this.name = 'HttpAuthError';
		this.status = status;
	}
}

async function parseApiErrorMessage(response) {
	try {
		const payload = await response.clone().json();
		return payload?.error?.message || payload?.message || '';
	} catch (_error) {
		return '';
	}
}

export async function authenticatedFetch(input, init = {}) {
	const { skipAuthHandling, ...requestInit } = init;
	const { data } = await supabase.auth.getSession();
	const token = data?.session?.access_token || '';
	const headers = new Headers(requestInit.headers || {});

	if (token) {
		headers.set('Authorization', `Bearer ${token}`);
	}

	const response = await fetch(input, {
		...requestInit,
		headers,
	});

	if (skipAuthHandling) {
		return response;
	}

	if (response.status === 401) {
		const message = await parseApiErrorMessage(response);
		if (typeof window !== 'undefined' && !window.location.pathname.startsWith('/login')) {
			window.location.assign('/login?reason=expired');
		}
		throw new HttpAuthError(message || 'Your session expired. Please sign in again.', 401);
	}

	if (response.status === 403) {
		const message = await parseApiErrorMessage(response);
		throw new HttpAuthError(message || 'You do not have permission to perform this action.', 403);
	}

	return response;
}

export default supabase;