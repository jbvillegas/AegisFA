import { useState } from 'react';
import '../css/login.css';
import { supabase } from '../client.js';

function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
	const [isGithubLoading, setIsGithubLoading] = useState(false);
	const [authError, setAuthError] = useState('');

  const handleSubmit = (event) => {
    event.preventDefault();
  };

	const handleGitHubLogin = async () => {
		setAuthError('');
		setIsGithubLoading(true);

		const { error } = await supabase.auth.signInWithOAuth({
			provider: 'github',
			options: {
				redirectTo: `${window.location.origin}/dashboard`
			}
		});

		if (error) {
			setAuthError(error.message);
			setIsGithubLoading(false);
		}
	};

	return (
		<section className="login-page">
			<h1>Login</h1>
			<button
				type="button"
				onClick={handleGitHubLogin}
				disabled={isGithubLoading}
			>
				{isGithubLoading ? 'Redirecting to GitHub...' : 'Continue with GitHub'}
			</button>
			{authError && <p className="login-error">{authError}</p>}

			<form onSubmit={handleSubmit}>
				<div>
					<label htmlFor="email">Email</label>
					<input
						id="email"
						type="email"
						value={email}
						onChange={(event) => setEmail(event.target.value)}
						required
					/>
				</div>
				<div>
					<label htmlFor="password">Password</label>
					<input
						id="password"
						type="password"
						value={password}
						onChange={(event) => setPassword(event.target.value)}
						required
					/>
				</div>
				<button type="submit">Sign In</button>
			</form>
		</section>
	);
}

export default Login;
