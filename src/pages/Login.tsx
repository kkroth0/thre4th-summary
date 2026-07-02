import { useEffect } from "react";
import { Navigate, Link } from "react-router-dom";
import { Github, ShieldCheck, KeyRound, ArrowRight, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";
import { useAuth } from "@/contexts/AuthContext";
import { toast } from "sonner";

const Login = () => {
  const { language } = useLanguage();
  const { isCollapsed } = useSidebar();
  const { auth, loading, loginUrl } = useAuth();
  const pt = language === "pt";

  // Feedback caso o callback do OAuth mande pra cá com erro (?auth=negado|erro).
  useEffect(() => {
    const p = new URLSearchParams(window.location.search).get("auth");
    if (p === "negado") toast.error(pt ? "Conta não está na lista autorizada" : "Account is not on the allow-list");
    else if (p === "erro") toast.error(pt ? "Falha no login. Tente de novo." : "Sign-in failed. Please try again.");
    if (p) window.history.replaceState({}, "", window.location.pathname);
  }, [pt]);

  // Já logado? vai pro perfil.
  if (!loading && auth.authenticated) return <Navigate to="/profile" replace />;

  return (
    <div className={`min-h-screen bg-background flex flex-col transition-all duration-300 ${isCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
      <Header showBackButton />
      <main className="flex-1 container mx-auto px-4 py-10 max-w-md w-full flex flex-col justify-center">
        <Card className="border-primary/10 shadow-lg shadow-primary/5">
          <CardHeader className="text-center items-center gap-2 pb-3">
            <div className="h-14 w-14 rounded-2xl bg-primary/10 ring-1 ring-inset ring-primary/20 flex items-center justify-center mb-1">
              <ShieldCheck className="h-7 w-7 text-primary" />
            </div>
            <CardTitle className="text-2xl">{pt ? "Entrar no ThreatSumm4ry" : "Sign in to ThreatSumm4ry"}</CardTitle>
            <CardDescription className="max-w-xs">
              {pt
                ? "Acesso restrito à lista autorizada. Entre com sua conta do GitHub."
                : "Access is restricted to the allow-list. Continue with your GitHub account."}
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-5">
            <Button asChild size="lg" className="w-full h-11 text-[15px]">
              <a href={loginUrl}>
                {loading
                  ? <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  : <Github className="h-4 w-4 mr-2" />}
                {pt ? "Entrar com GitHub" : "Continue with GitHub"}
              </a>
            </Button>
            <div className="space-y-2.5 text-sm text-muted-foreground border-t border-border/60 pt-4">
              <div className="flex items-start gap-2.5">
                <ShieldCheck className="h-4 w-4 mt-0.5 text-primary shrink-0" />
                <span>{pt ? "Somente contas autorizadas conseguem entrar." : "Only allow-listed accounts can sign in."}</span>
              </div>
              <div className="flex items-start gap-2.5">
                <KeyRound className="h-4 w-4 mt-0.5 text-primary shrink-0" />
                <span>{pt ? "Você usa sua própria chave Groq (BYOK), cifrada no servidor." : "You bring your own Groq key (BYOK), encrypted server-side."}</span>
              </div>
            </div>
          </CardContent>
        </Card>
        <p className="text-center text-xs text-muted-foreground mt-4">
          <Link to="/features" className="hover:text-foreground underline underline-offset-2 inline-flex items-center gap-1">
            {pt ? "O que é o Threat Brief?" : "What is Threat Brief?"} <ArrowRight className="h-3 w-3" />
          </Link>
        </p>
      </main>
      <Footer />
    </div>
  );
};

export default Login;
