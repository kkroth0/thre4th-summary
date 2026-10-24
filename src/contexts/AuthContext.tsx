import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from "react";
import { useQueryClient } from '@tanstack/react-query';
import { resetSessionCache, sessionScope } from '@/lib/sessionCache';
import { fetchAuth, logout as apiLogout, loginUrl, signupUrl, type AuthState } from "@/services/threatApi";
import { identify } from "@/lib/analytics";

interface AuthContextType {
  /** Estado da sessão. `authenticated` false enquanto `loading` = ainda checando /me. */
  auth: AuthState;
  /** true até a primeira resposta de /api/auth/me. */
  loading: boolean;
  /** Re-busca /api/auth/me (ex.: depois de salvar a chave OpenRouter). */
  refresh: () => Promise<void>;
  /** Logout + refresh. */
  signOut: () => Promise<void>;
  /** URL de início do OAuth do GitHub. */
  loginUrl: string;
  /** URL de início do OAuth do GitHub permitindo cadastro no GitHub. */
  signupUrl: string;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Sessão única compartilhada por toda a app (cookie httpOnly — o front só sabe
// via /me). Evita cada página buscar /me por conta própria.
export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [auth, setAuth] = useState<AuthState>({ authenticated: false });
  const [loading, setLoading] = useState(true);
  const queryClient = useQueryClient();
  const currentAuth = useRef<AuthState>({ authenticated: false });
  const refreshSequence = useRef(0);

  const refresh = useCallback(async () => {
    const sequence = ++refreshSequence.current;
    const a = await fetchAuth();
    if (sequence !== refreshSequence.current) return;
    resetSessionCache(queryClient, currentAuth.current, a);
    currentAuth.current = a;
    setAuth(a);
    setLoading(false);
    // Identify the signed-in user to Himetrica. The browser only knows the
    // GitHub login (email/name are never sent to the client), so that's all we
    // pass — no PII is invented here.
    if (a.authenticated && a.login) {
      identify({ name: a.login, metadata: { login: a.login } });
    }
  }, [queryClient]);

  useEffect(() => { refresh(); }, [refresh]);

  const signOut = useCallback(async () => {
    await apiLogout();
    await refresh();
  }, [refresh]);

  return (
    <AuthContext.Provider value={{ auth, loading, refresh, signOut, loginUrl, signupUrl }}>
      <React.Fragment key={sessionScope(auth)}>{children}</React.Fragment>
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (ctx === undefined) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
};
