import { useState } from 'react';
import { Link } from 'react-router-dom';
import '../css/homepage.css';
import '../css/login.css';
import '../css/feedback.css';
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
    <div className="hp login-shell">
      
      {/* Login Card */}
      <section className="login-card">
        <h2 className="login-card-title">Welcome Back</h2>

        <button
          type="button"
          className="login-oauth-btn"
          onClick={handleGitHubLogin}
          disabled={isGithubLoading}
        >
          {isGithubLoading ? 'Redirecting to GitHub...' : 'Continue with GitHub'}
        </button>

        {authError && <p className="login-error">{authError}</p>}

        <div className="login-divider">
          <span>or sign in with email</span>
        </div>

        <form className="login-form" onSubmit={handleSubmit}>
          <div className="login-field">
            <label htmlFor="email">Email</label>
            <input
              id="email"
              type="email"
              placeholder="you@company.com"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              required
            />
          </div>
          <div className="login-field">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              placeholder="Enter your password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
          </div>
          <button type="submit" className="hp-btn hp-btn-primary login-submit">
            Sign In
          </button>
        </form>

        <p className="login-footer">
          By signing in you agree to our{' '}
          <Link to="/terms">Terms</Link> and{' '}
          <Link to="/privacy">Privacy Policy</Link>.
        </p>
      </section>

    </div>
  );
}

export default Login;
