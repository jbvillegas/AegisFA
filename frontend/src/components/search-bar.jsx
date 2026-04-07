import { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { supabase } from '../client';
import '../css/searchbar.css';

function SearchBar() {
  const [searchParams, setSearchParams] = useSearchParams();
  const param = searchParams.get('search') ?? '';
  const [searchTerm, setSearchTerm] = useState(param);
  const [suggestions, setSuggestions] = useState([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const navigate = useNavigate();
  const storedOrgId = window.localStorage.getItem('aegisfa-org-id') || '';

  useEffect(() => {
    setSearchTerm(param);
  }, [param]);

  useEffect(() => {
    const fetchSuggestions = async () => {
      if (searchTerm.trim().length === 0) {
        setSuggestions([]);
        setShowSuggestions(false);
        return;
      }

      let query = supabase
        .from('log_files')
        .select('id, filename, source_type, status, created_at')
        .eq('status', 'completed')
        .ilike('filename', `%${searchTerm}%`)
        .order('created_at', { ascending: false })
        .limit(5);

      if (storedOrgId.trim()) {
        query = query.eq('org_id', storedOrgId.trim());
      }

      const { data, error } = await query;

      if (!error && data) {
        setSuggestions(data);
        setShowSuggestions(true);
      }
    };

    const debounceTimer = setTimeout(fetchSuggestions, 300);
    return () => clearTimeout(debounceTimer);
  }, [searchTerm, storedOrgId]);

  const handleSearch = (term = searchTerm) => {
    const trimmedTerm = term.trim();
    if (trimmedTerm) {
      setSearchParams({ search: trimmedTerm });
      setShowSuggestions(false);
    } else {
      setSearchParams({});
    }
  };

  const handleSuggestionClick = (remediationId) => {
    navigate(`/remediation-view/${remediationId}`);
    setShowSuggestions(false);
  };

  const handleClear = () => {
    setSearchTerm('');
    setSuggestions([]);
    setShowSuggestions(false);
    setSearchParams({});
  };

  return (
    <div className="search-container">
      <div className="search-input-wrap">
        <span className="search-icon" aria-hidden="true">
          
        </span>
        <input
          type="text"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') handleSearch();
            if (e.key === 'Escape') {
              handleClear();
              setShowSuggestions(false);
            }
          }}
          onFocus={() => searchTerm && setShowSuggestions(true)}
          placeholder="Search..."
          className="search-input"
          aria-label="Search"
          autoComplete="off"
        />
        {showSuggestions && suggestions.length > 0 && (
          <div className="search-dropdown">
            {suggestions.map((file) => (
              <button
                key={file.id}
                className="search-suggestion"
                type="button"
                onClick={() => handleSuggestionClick(file.id)}
              >
                {file.filename}
              </button>
            ))}
          </div>
        )}
      </div>
      <button className="search-button" onClick={() => handleSearch()}>
        Search
      </button>
      <button className="clear-button" onClick={handleClear}>
        Clear
      </button>
    </div>
  );
}

export default SearchBar;