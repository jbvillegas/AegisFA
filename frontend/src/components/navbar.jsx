import { useState, useEffect, useRef } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import { supabase } from '../client.js';
import SearchBar from './search-bar.jsx';
import '../css/navbar.css';

function Navbar() {
	const [isLoggedIn, setIsLoggedIn] = useState(false);
	const [user, setUser] = useState(null);
	const [isDropdownOpen, setIsDropdownOpen] = useState(false);
	const dropdownRef = useRef(null);
	const userRole = user?.app_metadata?.role || user?.user_metadata?.role || 'user';
	const location = useLocation();
	const isLoginPage = location.pathname === '/login';
	const navigate = useNavigate();

	useEffect(() => {
		// Check current session and get user data
		const checkSession = async () => {
			const { data: { session } } = await supabase.auth.getSession();
			setIsLoggedIn(!!session);
			
			if (session?.user) {
				setUser(session.user);
			}
		};

		checkSession();

		// Listen for auth state changes
		const { data: { subscription } } = supabase.auth.onAuthStateChange(
			(event, session) => {
				setIsLoggedIn(!!session);
				if (session?.user) {
					setUser(session.user);
				} else {
					setUser(null);
				}
			}
		);

		// Cleanup subscription
		return () => {
			subscription?.unsubscribe();
		};
	}, []);

	// Close dropdown when clicking outside
	useEffect(() => {
		const handleClickOutside = (event) => {
			if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
				setIsDropdownOpen(false);
			}
		};

		if (isDropdownOpen) {
			document.addEventListener('mousedown', handleClickOutside);
		}

		return () => {
			document.removeEventListener('mousedown', handleClickOutside);
		};
	}, [isDropdownOpen]);

	const handleLogout = async () => {
		await supabase.auth.signOut();
		setIsDropdownOpen(false);
		navigate('/login', { replace: true });
	};

	const getProfileImage = () => {
		// Try to get avatar_url from user metadata
		if (user?.user_metadata?.avatar_url) {
			return user.user_metadata.avatar_url;
		}
		// Fallback to a default avatar
		return `https://ui-avatars.com/api/?name=${encodeURIComponent(user?.email || 'User')}&background=random`;
	};

	const handleNavigate = () => {
		setIsDropdownOpen(false);
	};

	return (
		<nav className="navbar" aria-label="Primary navigation">
		  <div className="navbar-container">
		    <div className="navbar-content">
		      <NavLink to="/" className="navbar-logo">
		        AegisFA
		      </NavLink>
		      <div className="navbar-links">
				{isLoggedIn ? (
					<div className="navbar-user-controls">
						<div className="navbar-search">
							<SearchBar />
						</div>
					<div className="profile-dropdown" ref={dropdownRef}>
						<button
							className="profile-btn"
							onClick={() => setIsDropdownOpen(!isDropdownOpen)}
							aria-label="User profile menu"
						>
							<img 
								src={getProfileImage()} 
								alt="User avatar" 
								className="profile-image"
							/>
						</button>
						{isDropdownOpen && (
							<div className="dropdown-menu">
								<div className="dropdown-header">
									<p className="user-email">{user?.email}</p>
								</div>
								<NavLink
									to="/"
									end
									className={({ isActive }) => `dropdown-item ${isActive ? 'active' : ''}`}
									onClick={handleNavigate}
								>
									Home
								</NavLink>
								<NavLink
									to="/dashboard"
									className={({ isActive }) => `dropdown-item ${isActive ? 'active' : ''}`}
									onClick={handleNavigate}
								>
									Dashboard
								</NavLink>
								<NavLink
									to="/workspace"
									className={({ isActive }) => `dropdown-item ${isActive ? 'active' : ''}`}
									onClick={handleNavigate}
								>
									Workspace
								</NavLink>
								<NavLink
									to="/feedback"
									className={({ isActive }) => `dropdown-item ${isActive ? 'active' : ''}`}
									onClick={handleNavigate}
								>
									Feedback
								</NavLink>
								<NavLink
									to="/about"
									className={({ isActive }) => `dropdown-item ${isActive ? 'active' : ''}`}
									onClick={handleNavigate}
								>
									About
								</NavLink>
								<NavLink
									to="/support"
									className={({ isActive }) => `dropdown-item ${isActive ? 'active' : ''}`}
									onClick={handleNavigate}
								>
									Support
								</NavLink>
								<NavLink
									to="/contact"
									className={({ isActive }) => `dropdown-item ${isActive ? 'active' : ''}`}
									onClick={handleNavigate}
								>
									Contact
								</NavLink>
								{userRole === 'admin' && (
									<NavLink
										to="/admin"
										className={({ isActive }) => `dropdown-item ${isActive ? 'active' : ''}`}
										onClick={handleNavigate}
									>
										Admin
									</NavLink>
								)}
									                                                <div className="dropdown-divider"></div>
								<button 
									onClick={handleLogout} 
									className="dropdown-item logout-item"
								>
									Logout
								</button>
							</div>
						)}
					</div>
					</div>
				) : (
					!isLoginPage && (
						<>
							<NavLink to="/about" className={({ isActive }) => (isActive ? 'navbar-link active' : 'navbar-link')}>
								About
							</NavLink>
							<NavLink to="/support" className={({ isActive }) => (isActive ? 'navbar-link active' : 'navbar-link')}>
								Support
							</NavLink>
							<NavLink to="/contact" className={({ isActive }) => (isActive ? 'navbar-link active' : 'navbar-link')}>
								Contact
							</NavLink>
							<NavLink to="/login" className={({ isActive }) => (isActive ? 'navbar-link active' : 'navbar-link')}>
								Login
							</NavLink>
						</>
					)
				)}
		        
		      </div>
		    </div>
		  </div>
		</nav>
  );
}

export default Navbar;
