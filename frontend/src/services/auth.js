import { createContext, useContext, useEffect, useState } from 'react';
import { supabase } from '../supabaseClient';

const AuthContext = createContext({});
const BACKEND = process.env.REACT_APP_BACKEND_URL || 'http://localhost:5001';

export function AuthProvider({ children }) {
  const [session, setSession] = useState(null);
  const [orgId, setOrgId] = useState(null);
  const [loading, setLoading] = useState(true);

  async function fetchOrgId(userId) {
    try {
      const res = await fetch(`${BACKEND}/user-org/${userId}`);
      if (res.ok) {
        const data = await res.json();
        setOrgId(data.org_id);
      } else {
        setOrgId(null);
      }
    } catch {
      setOrgId(null);
    }
  }

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      if (session?.user?.id) fetchOrgId(session.user.id);
      setLoading(false);
    });

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_e, session) => {
      setSession(session);
      if (session?.user?.id) {
        fetchOrgId(session.user.id);
      } else {
        setOrgId(null);
      }
    });

    return () => subscription.unsubscribe();
  }, []);

  const signIn = async (email, password) => {
    const result = await supabase.auth.signInWithPassword({ email, password });
    if (result.data?.user?.id) await fetchOrgId(result.data.user.id);
    return result;
  };

  const signUp = (email, password) => supabase.auth.signUp({ email, password });

  const signOut = async () => {
    await supabase.auth.signOut();
    setOrgId(null);
  };

  return (
    <AuthContext.Provider value={{ session, orgId, loading, signIn, signUp, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
