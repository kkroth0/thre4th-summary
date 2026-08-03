import { useEffect } from "react";
import { Navigate, Link, useLocation } from "react-router-dom";
import { Github, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { BrandMark } from "@/components/BrandMark";
import { useLanguage } from "@/contexts/LanguageContext";
import { useAuth } from "@/contexts/AuthContext";
import { toast } from "sonner";

// A página faz uma coisa: mandar pro OAuth do GitHub. Tudo que não ajuda a
// clicar naquele botão saiu.
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

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background px-6 py-12">
      <div className="w-full max-w-xs text-center">
        <Link to="/" className="inline-flex items-center gap-2.5">
          <BrandMark className="h-9 w-9 rounded-md" />
          <span className="text-lg font-bold tracking-tight">threatsumm4ry</span>
        </Link>

        <h1 className="mt-8 text-xl font-bold">
          {signupMode ? (pt ? "Criar conta" : "Create account") : (pt ? "Entrar" : "Sign in")}
        </h1>
        <p className="mt-1.5 text-sm text-muted-foreground">
          {pt ? "A conta é o seu GitHub. Nada de senha nova." : "Your account is your GitHub. No new password."}
        </p>

        <Button asChild size="lg" className="mt-6 h-11 w-full">
          <a href={authUrl}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Github className="h-4 w-4" />}
            {signupMode
              ? (pt ? "Continuar com GitHub" : "Continue with GitHub")
              : (pt ? "Entrar com GitHub" : "Sign in with GitHub")}
          </a>
        </Button>

        <p className="mt-4 text-sm text-muted-foreground">
          {signupMode ? (
            <>
              {pt ? "Já tem conta?" : "Already have an account?"}{" "}
              <Link to="/login" className="font-semibold text-foreground hover:text-primary">{pt ? "Entrar" : "Sign in"}</Link>
            </>
          ) : (
            <>
              {pt ? "Primeira vez aqui?" : "First time here?"}{" "}
              <Link to="/cadastro" className="font-semibold text-foreground hover:text-primary">{pt ? "Criar conta" : "Create account"}</Link>
            </>
          )}
        </p>

        <p className="mt-10 text-xs text-muted-foreground">
          {pt
            ? "As ferramentas abertas liberam na hora. As restritas dependem de liberação."
            : "Open tools work right away. Restricted areas need to be granted."}
        </p>
      </div>
    </div>
  );
};

export default Login;
