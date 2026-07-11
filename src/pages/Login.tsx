import { useEffect } from "react";
import { Navigate, Link, useLocation } from "react-router-dom";
import { Github, ShieldCheck, KeyRound, ArrowLeft, Loader2, FileText, Crosshair, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/ThemeToggle";
import { LanguageToggle } from "@/components/LanguageToggle";
import { useLanguage } from "@/contexts/LanguageContext";
import { useAuth } from "@/contexts/AuthContext";
import { toast } from "sonner";

const Login = () => {
  const { language } = useLanguage();
  const { auth, loading, loginUrl, signupUrl } = useAuth();
  const location = useLocation();
  const pt = language === "pt";
  const signupMode = location.pathname === "/cadastro" || location.pathname === "/signup";
  const authUrl = signupMode ? signupUrl : loginUrl;

  // Feedback caso o callback do OAuth mande pra cá com erro (?auth=erro).
  useEffect(() => {
    const p = new URLSearchParams(window.location.search).get("auth");
    if (p === "erro") toast.error(pt ? "Falha no login. Tente de novo." : "Sign-in failed. Please try again.");
    if (p) window.history.replaceState({}, "", window.location.pathname);
  }, [pt]);

  if (!loading && auth.authenticated) return <Navigate to="/profile" replace />;

  const perks = [
    { icon: Search, label: pt ? "Busca de IOCs em fontes de reputacao, DNS, WHOIS e vendors." : "IOC search across reputation, DNS, WHOIS and vendor sources." },
    { icon: FileText, label: pt ? "Analises de phishing, DNSBL, CVEs, atores e advisories." : "Phishing, DNSBL, CVE, actor and advisory analysis." },
    { icon: Crosshair, label: pt ? "Um fluxo mais rapido para triagem, contexto e resposta." : "A faster workflow for triage, context and response." },
  ];

  return (
    <div className="min-h-screen w-full bg-background lg:grid lg:grid-cols-2">
      {/* Toggles no canto */}
      <div className="absolute top-4 right-4 z-20 flex items-center gap-1">
        <LanguageToggle />
        <ThemeToggle />
      </div>

      {/* Painel hero (esquerda) */}
      <div className="relative hidden lg:flex flex-col justify-between overflow-hidden bg-gradient-to-br from-primary/12 via-primary/5 to-background p-12 border-r border-border/50">
        <div className="absolute inset-0 bg-[radial-gradient(60%_60%_at_30%_20%,hsl(var(--primary)/0.10),transparent)]" />
        <Link to="/" className="relative flex items-center gap-2.5 w-fit">
          <div className="h-8 w-8 rounded-lg bg-primary flex items-center justify-center font-black text-primary-foreground text-sm shadow-sm shadow-primary/30">T</div>
          <span className="font-bold tracking-tight text-xl bg-gradient-to-r from-primary via-primary/80 to-primary/50 bg-clip-text text-transparent">ThreatSumm4ry</span>
        </Link>

        <div className="relative max-w-md">
          <h1 className="text-4xl font-bold leading-tight tracking-tight">
            {pt ? "Entre no console ThreatSumm4ry." : "Access the ThreatSumm4ry console."}
          </h1>
          <p className="mt-4 text-muted-foreground text-lg">
            {pt
              ? "Busque indicadores, investigue sinais e transforme achados em inteligencia operacional."
              : "Search indicators, investigate signals and turn findings into operational intelligence."}
          </p>
          <ul className="mt-8 space-y-3">
            {perks.map((p) => (
              <li key={p.label} className="flex items-center gap-3 text-[15px]">
                <span className="h-9 w-9 rounded-xl bg-primary/10 ring-1 ring-inset ring-primary/20 flex items-center justify-center shrink-0">
                  <p.icon className="h-4 w-4 text-primary" />
                </span>
                {p.label}
              </li>
            ))}
          </ul>
        </div>

        <p className="relative text-xs text-muted-foreground/70">
          © {new Date().getFullYear()} ThreatSumm4ry
        </p>
      </div>

      {/* Painel de login (direita) */}
      <div className="flex min-h-screen lg:min-h-0 flex-col items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm">
          {/* Brand no mobile */}
          <Link to="/" className="lg:hidden flex items-center justify-center gap-2.5 mb-8">
            <div className="h-8 w-8 rounded-lg bg-primary flex items-center justify-center font-black text-primary-foreground text-sm">T</div>
            <span className="font-bold tracking-tight text-xl bg-gradient-to-r from-primary via-primary/80 to-primary/50 bg-clip-text text-transparent">ThreatSumm4ry</span>
          </Link>

          <div className="text-center mb-8">
            <div className="mx-auto mb-4 h-14 w-14 rounded-xl bg-primary/10 ring-1 ring-inset ring-primary/20 flex items-center justify-center">
              <ShieldCheck className="h-7 w-7 text-primary" />
            </div>
            <h2 className="text-2xl font-bold">{signupMode ? (pt ? "Cadastro" : "Sign up") : (pt ? "Entrar" : "Sign in")}</h2>
            <p className="text-muted-foreground mt-1.5 text-sm">
              {pt
                ? "Use sua conta GitHub para continuar com seguranca."
                : "Use your GitHub account to continue securely."}
            </p>
          </div>

          <Button asChild size="lg" className="w-full h-12 text-[15px]">
            <a href={authUrl}>
              {loading ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Github className="h-5 w-5 mr-2" />}
              {signupMode
                ? (pt ? "Cadastrar com GitHub" : "Sign up with GitHub")
                : (pt ? "Entrar com GitHub" : "Continue with GitHub")}
            </a>
          </Button>

          <div className="mt-4 text-center text-sm text-muted-foreground">
            {signupMode ? (
              <>
                {pt ? "Já tem conta?" : "Already have an account?"}{" "}
                <Link to="/login" className="font-semibold text-foreground hover:text-primary">{pt ? "Entrar" : "Sign in"}</Link>
              </>
            ) : (
              <>
                {pt ? "Ainda não tem conta?" : "No account yet?"}{" "}
                <Link to="/cadastro" className="font-semibold text-foreground hover:text-primary">{pt ? "Cadastrar" : "Sign up"}</Link>
              </>
            )}
          </div>

          <div className="mt-6 space-y-2.5 text-sm text-muted-foreground border-t border-border/60 pt-5">
            <div className="flex items-start gap-2.5">
              <ShieldCheck className="h-4 w-4 mt-0.5 text-primary shrink-0" />
              <span>{pt ? "Sessao protegida por GitHub OAuth." : "Session protected by GitHub OAuth."}</span>
            </div>
            <div className="flex items-start gap-2.5">
              <KeyRound className="h-4 w-4 mt-0.5 text-primary shrink-0" />
              <span>{pt ? "Preferencias e chaves de API ficam no seu perfil." : "Preferences and API keys stay in your profile."}</span>
            </div>
          </div>

          <div className="mt-8 text-center">
            <Link to="/" className="text-xs text-muted-foreground hover:text-foreground inline-flex items-center gap-1">
              <ArrowLeft className="h-3 w-3" /> {pt ? "Voltar para o início" : "Back to home"}
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
