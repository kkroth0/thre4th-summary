import React, { createContext, useContext, useState, useEffect } from "react";
import { useToast } from "@/hooks/use-toast";

interface User {
  username: string;
  name: string;
  avatar_url: string;
  id: number;
}

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  loginWithGithub: () => Promise<void>;
  loginMock: () => Promise<boolean>;
  logout: () => void;
  githubConfigured: boolean;
  allowMock: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [githubConfigured, setGithubConfigured] = useState<boolean>(false);
  const [clientId, setClientId] = useState<string>("");
  const [allowMock, setAllowMock] = useState<boolean>(true);
  const { toast } = useToast();

  const checkAuth = async () => {
    const token = localStorage.getItem("auth_token");
    if (!token) {
      setIsLoading(false);
      return;
    }

    try {
      const response = await fetch("/api/auth/me");
      if (response.ok) {
        const data = await response.json();
        if (data.authenticated) {
          setUser(data.user);
          setIsAuthenticated(true);
        } else {
          localStorage.removeItem("auth_token");
        }
      } else if (response.status === 401) {
        localStorage.removeItem("auth_token");
      }
    } catch (error) {
      console.error("Auth check failed:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const fetchConfig = async () => {
    try {
      const response = await fetch("/api/auth/config");
      if (response.ok) {
        const data = await response.json();
        setGithubConfigured(data.githubConfigured);
        setClientId(data.clientId || "");
        setAllowMock(data.allowMock);
      }
    } catch (error) {
      console.error("Failed to fetch auth configuration:", error);
    }
  };

  useEffect(() => {
    fetchConfig();
    checkAuth();
  }, []);

  // Intercept window.fetch to automatically add auth token
  useEffect(() => {
    const originalFetch = window.fetch;
    window.fetch = async (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      
      // Only modify local relative API requests
      if (url.startsWith("/api/") && !url.includes("/api/auth/")) {
        const token = localStorage.getItem("auth_token");
        if (token) {
          init = init || {};
          init.headers = init.headers || {};
          
          if (init.headers instanceof Headers) {
            init.headers.set("Authorization", `Bearer ${token}`);
          } else if (Array.isArray(init.headers)) {
            const authIdx = init.headers.findIndex(([k]) => k.toLowerCase() === "authorization");
            if (authIdx !== -1) {
              init.headers[authIdx][1] = `Bearer ${token}`;
            } else {
              init.headers.push(["Authorization", `Bearer ${token}`]);
            }
          } else {
            (init.headers as Record<string, string>)["Authorization"] = `Bearer ${token}`;
          }
        }
      }
      
      const response = await originalFetch(input, init);
      
      // Auto-logout on unauthorized
      if (response.status === 401 && url.startsWith("/api/") && !url.includes("/api/auth/")) {
        localStorage.removeItem("auth_token");
        setUser(null);
        setIsAuthenticated(false);
        // Force redirect to login page if currently on protected route
        const path = window.location.pathname;
        if (path === "/" || path === "/cves" || path === "/dns-visualizer") {
          window.location.href = `/login?redirect=${encodeURIComponent(path)}`;
        }
      }
      
      return response;
    };

    return () => {
      window.fetch = originalFetch;
    };
  }, []);

  const loginWithGithub = async () => {
    if (githubConfigured && clientId) {
      const redirectUri = `${window.location.origin}/auth/callback`;
      window.location.href = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=read:user`;
    } else {
      toast({
        title: "Erro de Configuração",
        description: "GitHub OAuth não configurado no backend. Use o Mock Auth em desenvolvimento.",
        variant: "destructive",
      });
    }
  };

  const loginMock = async (): Promise<boolean> => {
    setIsLoading(true);
    try {
      const response = await fetch("/api/auth/mock", {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      });
      if (response.ok) {
        const data = await response.json();
        localStorage.setItem("auth_token", data.token);
        setUser(data.user);
        setIsAuthenticated(true);
        toast({
          title: "Login efetuado com sucesso",
          description: `Bem-vindo (Modo Dev): ${data.user.name}`,
        });
        return true;
      } else {
        const err = await response.json();
        toast({
          title: "Falha no login mock",
          description: err.error || "Ocorreu um erro.",
          variant: "destructive",
        });
        return false;
      }
    } catch (error) {
      toast({
        title: "Erro de Conexão",
        description: "Não foi possível conectar ao servidor backend.",
        variant: "destructive",
      });
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    localStorage.removeItem("auth_token");
    setUser(null);
    setIsAuthenticated(false);
    toast({
      title: "Logoff efetuado",
      description: "Você foi desconectado com sucesso.",
    });
    window.location.href = "/login";
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated,
        isLoading,
        loginWithGithub,
        loginMock,
        logout,
        githubConfigured,
        allowMock,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
