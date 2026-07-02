import React, { createContext, useContext, useState, useEffect, useCallback } from "react";
import { fetchAuth, logout as apiLogout, loginUrl, type AuthState } from "@/services/threatApi";

interface AuthContextType {
  /** Estado da sessão. `authenticated` false enquanto `loading` = ainda checando /me. */
  auth: AuthState;
  /** true até a primeira resposta de /api/auth/me. */
  loading: boolean;
  /** Re-busca /api/auth/me (ex.: depois de salvar a chave Groq). */
  refresh: () => Promise<void>;
  /** Logout + refresh. */
  signOut: () => Promise<void>;
  /** URL de início do OAuth do GitHub. */
  loginUrl: string;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Sessão única compartilhada por toda a app (cookie httpOnly — o front só sabe
// via /me). Evita cada página buscar /me por conta própria.
export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [auth, setAuth] = useState<AuthState>({ authenticated: false });
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    const a = await fetchAuth();
    setAuth(a);
    setLoading(false);
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const signOut = useCallback(async () => {
    await apiLogout();
    await refresh();
  }, [refresh]);

  return (
    <AuthContext.Provider value={{ auth, loading, refresh, signOut, loginUrl }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (ctx === undefined) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
};
