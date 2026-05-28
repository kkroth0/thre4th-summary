import React, { useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useToast } from "@/hooks/use-toast";
import { Loader2 } from "lucide-react";

export default function AuthCallback() {
  const navigate = useNavigate();
  const location = useLocation();
  const { toast } = useToast();

  useEffect(() => {
    const searchParams = new URLSearchParams(location.search);
    const code = searchParams.get("code");
    const state = searchParams.get("state");
    const savedState = sessionStorage.getItem("oauth_state");

    // Verify CSRF state parameter
    if (state && savedState && state !== savedState) {
      sessionStorage.removeItem("oauth_state");
      toast({
        title: "Erro de Segurança",
        description: "Parâmetro de estado OAuth inválido. Possível ataque CSRF.",
        variant: "destructive",
      });
      navigate("/login");
      return;
    }
    sessionStorage.removeItem("oauth_state");

    if (!code) {
      toast({
        title: "Erro de Autenticação",
        description: "Não foi possível obter o código de autorização do GitHub.",
        variant: "destructive",
      });
      navigate("/login");
      return;
    }

    const exchangeCode = async () => {
      try {
        const response = await fetch("/api/auth/github", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ code }),
        });

        if (response.ok) {
          const data = await response.json();
          localStorage.setItem("auth_token", data.token);
          
          toast({
            title: "Autenticado com Sucesso!",
            description: `Seja bem-vindo, ${data.user.name || data.user.username}!`,
          });
          
          // Force auth check update or just redirect (our App AuthProvider will capture the local token)
          // Wait, to ensure the state refreshes correctly, redirecting to "/" will force reload or state update
          window.location.href = "/";
        } else {
          const err = await response.json();
          toast({
            title: "Falha na Autenticação",
            description: err.error || "Não foi possível autenticar com o GitHub.",
            variant: "destructive",
          });
          navigate("/login");
        }
      } catch (error) {
        console.error("Auth callback error:", error);
        toast({
          title: "Erro de Conexão",
          description: "Ocorreu um erro ao comunicar com o servidor backend.",
          variant: "destructive",
        });
        navigate("/login");
      }
    };

    exchangeCode();
  }, [location, navigate, toast]);

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center space-y-4">
      <div className="relative flex items-center justify-center">
        {/* Glow effects */}
        <div className="absolute w-16 h-16 rounded-full border border-primary/20 animate-ping opacity-70" />
        <div className="absolute w-24 h-24 rounded-full border border-primary/10 animate-pulse opacity-40" />
        <Loader2 className="h-10 w-10 text-primary animate-spin" />
      </div>
      <p className="text-muted-foreground text-sm font-semibold tracking-wider uppercase animate-pulse">
        Finalizando login com GitHub...
      </p>
    </div>
  );
}
