import React, { useState } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { useLocation, useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, Github, AlertTriangle, Key, Loader2, Sparkles, HelpCircle, CheckCircle } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

export default function Login() {
  const { loginWithGithub, loginMock, githubConfigured, allowMock } = useAuth();
  const [isLoggingIn, setIsLoggingIn] = useState<boolean>(false);
  const [clickCount, setClickCount] = useState<number>(0);
  const [devMode, setDevMode] = useState<boolean>(false);
  const [showHelp, setShowHelp] = useState<boolean>(false);
  const location = useLocation();
  const navigate = useNavigate();
  const { toast } = useToast();

  const searchParams = new URLSearchParams(location.search);
  const redirect = searchParams.get("redirect") || "/";

  const handleMockLogin = async () => {
    setIsLoggingIn(true);
    const success = await loginMock();
    setIsLoggingIn(false);
    if (success) {
      navigate(redirect);
    }
  };

  const handleGithubLogin = async () => {
    setIsLoggingIn(true);
    await loginWithGithub();
    setIsLoggingIn(false);
  };

  // Developer easter egg: click the logo 5 times to enable developer tools
  const handleLogoClick = () => {
    const nextCount = clickCount + 1;
    if (nextCount >= 5) {
      setDevMode(!devMode);
      setClickCount(0);
      toast({
        title: !devMode ? "Modo Desenvolvedor Ativado" : "Modo Desenvolvedor Desativado",
        description: !devMode ? "Ferramentas locais de teste agora estão visíveis." : "Interface limpa de produção restaurada.",
      });
    } else {
      setClickCount(nextCount);
      // Reset count after 2 seconds of inactivity
      const timer = setTimeout(() => setClickCount(0), 2000);
      return () => clearTimeout(timer);
    }
  };

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col items-center justify-center p-4 relative">
      <div className="absolute inset-0 bg-gradient-to-tr from-muted/20 via-background to-background pointer-events-none" />

      <div className="w-full max-w-md relative z-10 space-y-6">
        {/* Branding header with custom logo */}
        <div className="flex flex-col items-center text-center space-y-3">
          <button 
            onClick={handleLogoClick}
            className="h-16 w-16 rounded-full bg-muted border border-border flex items-center justify-center p-2.5 overflow-hidden shadow-sm hover:scale-[1.02] active:scale-[0.98] transition-transform focus:outline-none"
            title="ThreatSumm4ry Logo"
          >
            <img src="/logo.png" alt="Logo" className="h-full w-full object-contain" />
          </button>
          <div className="space-y-1">
            <h1 className="text-2xl font-bold tracking-tight text-foreground">
              ThreatSumm4ry
            </h1>
            <p className="text-muted-foreground text-xs font-medium uppercase tracking-wider">
              Threat Intelligence Dashboard
            </p>
          </div>
        </div>

        {/* Login Card */}
        <Card className="border border-border bg-card text-card-foreground shadow-md rounded-xl relative overflow-hidden">
          <CardHeader className="space-y-1.5 pb-6 text-center">
            <CardTitle className="text-base font-bold flex items-center justify-center gap-2 uppercase tracking-wider">
              <Shield className="h-4 w-4 text-muted-foreground" />
              Acesso Restrito
            </CardTitle>
            <CardDescription className="text-muted-foreground text-xs">
              Autenticação requerida para acessar os painéis de CVE e CTI.
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-4 pb-6">
            {isLoggingIn ? (
              <div className="flex flex-col items-center justify-center py-8 space-y-3">
                <Loader2 className="h-8 w-8 text-muted-foreground animate-spin" />
                <p className="text-xs text-muted-foreground animate-pulse font-semibold">Autenticando analista...</p>
              </div>
            ) : (
              <div className="space-y-4">
                {/* GitHub Authentication Button - Always enabled in production for UX, backend handles missing keys */}
                <Button 
                  onClick={handleGithubLogin}
                  className="w-full gap-3 h-11 text-xs font-bold bg-primary text-primary-foreground hover:bg-primary/95 transition-all rounded-xl"
                >
                  <Github className="h-4 w-4 fill-primary-foreground text-primary-foreground" />
                  Entrar com o GitHub
                </Button>

                {/* Developer Mode UI (Only visible after clicking logo 5 times) */}
                {devMode && (
                  <div className="pt-2 border-t border-border space-y-4 animate-fade-in">
                    <div className="bg-amber-500/10 text-amber-500 border border-amber-500/20 rounded-xl p-3 text-[11px] font-semibold text-center">
                      🔧 MODO DESENVOLVEDOR ATIVADO
                    </div>

                    {allowMock && (
                      <Button 
                        onClick={handleMockLogin} 
                        variant="outline"
                        className="w-full gap-3 h-11 border-border hover:bg-muted/80 text-foreground font-semibold transition-all duration-200 rounded-xl"
                      >
                        <Sparkles className="h-4 w-4 text-muted-foreground" />
                        Ignorar com Conta de Teste
                      </Button>
                    )}

                    <div className="rounded-xl bg-muted/40 border border-border p-3.5 space-y-2">
                      <div className="flex items-start gap-2.5">
                        <AlertTriangle className="h-4 w-4 text-muted-foreground shrink-0 mt-0.5" />
                        <div className="text-left space-y-1">
                          <p className="text-foreground text-xs font-bold">Status do Servidor OAuth</p>
                          <p className="text-muted-foreground text-[11px] leading-relaxed">
                            {githubConfigured 
                              ? "O GitHub OAuth está configurado com sucesso no backend." 
                              : "Chaves OAuth ausentes no arquivo .env do backend."}
                          </p>
                        </div>
                      </div>
                      <button 
                        onClick={() => setShowHelp(!showHelp)}
                        className="w-full text-center text-[10px] font-bold text-muted-foreground hover:text-foreground transition-colors flex items-center justify-center gap-1 mt-1 hover:underline"
                      >
                        <HelpCircle className="h-3 w-3" />
                        {showHelp ? "Ocultar Guia de Configuração" : "Como configurar o GitHub OAuth?"}
                      </button>
                    </div>

                    {showHelp && (
                      <div className="rounded-xl bg-muted/30 border border-border p-4 text-left text-xs leading-relaxed space-y-3">
                        <p className="font-bold text-foreground border-b border-border pb-1.5 flex items-center gap-1.5">
                          <Shield className="h-3.5 w-3.5 text-muted-foreground" />
                          Guia de Configuração
                        </p>
                        <ol className="list-decimal list-inside space-y-2 text-muted-foreground text-[11px]">
                          <li>Acesse seu GitHub: <strong>Settings &gt; Developer settings &gt; OAuth Apps</strong>.</li>
                          <li>Clique em <strong>Register a new application</strong>.</li>
                          <li>Defina a Homepage URL como: <code className="bg-muted px-1.5 py-0.5 rounded">http://localhost:8080</code>.</li>
                          <li>Defina a Authorization Callback URL como: <code className="bg-muted px-1.5 py-0.5 rounded">http://localhost:8080/auth/callback</code>.</li>
                          <li>Gere um <strong>Client Secret</strong>.</li>
                          <li>Adicione ao arquivo <code className="bg-muted px-1 py-0.5 rounded font-mono text-[10px]">.env</code> na raiz do projeto:</li>
                        </ol>
                        <pre className="bg-muted p-2.5 rounded-lg text-[10px] font-mono text-foreground overflow-x-auto border border-border">
{`GITHUB_CLIENT_ID=seu_client_id
GITHUB_CLIENT_SECRET=seu_client_secret`}
                        </pre>
                        <p className="text-[10px] text-muted-foreground text-center font-semibold italic">
                          Reinicie o servidor backend após editar o arquivo .env.
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
