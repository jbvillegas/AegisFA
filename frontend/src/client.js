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

export default supabase;