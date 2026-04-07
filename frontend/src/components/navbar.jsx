import { NavLink } from 'react-router-dom';
import '../css/navbar.css';

function Navbar() {
	return (
		<nav className="navbar" aria-label="Primary navigation">
		  <div className="navbar-container">
		    <div className="navbar-content">
		      <NavLink to="/" className="navbar-logo">
		        AegisFA
		      </NavLink>
		      <div className="navbar-links">
		        <NavLink to="/" end className={({ isActive }) => (isActive ? 'navbar-link active' : 'navbar-link')}>
		          Home
		        </NavLink>
		        <NavLink to="/login" className={({ isActive }) => (isActive ? 'navbar-link active' : 'navbar-link')}>
		          Login
		        </NavLink>
		        <NavLink to="/dashboard" className={({ isActive }) => (isActive ? 'navbar-link active' : 'navbar-link')}>
		          Dashboard
		        </NavLink>
		        <NavLink to="/admin" className={({ isActive }) => (isActive ? 'navbar-link active' : 'navbar-link')}>
		          Admin
		        </NavLink>
		      </div>
		    </div>
		  </div>
		</nav>
  );
}

export default Navbar;
