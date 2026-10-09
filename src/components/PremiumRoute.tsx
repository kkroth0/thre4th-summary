import { Link } from "react-router-dom";
import { Lock, Github, Loader2, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { useLanguage } from "@/contexts/LanguageContext";
import { useAuth } from "@/contexts/AuthContext";

type Feature = "threat-brief" | "advisory-feed" | "exposure-watchlist" | "knowledge";

const COPY: Record<Feature, { pt: [string, string]; en: [string, string] }> = {
  "threat-brief": {
    pt: ["Geração de Relatórios", "Resumo pronto a partir de um link."],
    en: ["Report Generation", "Ready-made summary from a link."],
  },
  "advisory-feed": {
    pt: ["Notícias de Segurança", "Notícias de segurança da semana."],
    en: ["Security News", "This week's security news."],
  },
  "exposure-watchlist": {
    pt: ["Superfície de Ataque", "Ativos expostos na internet."],
    en: ["Attack Surface", "Assets exposed to the internet."],
  },
  knowledge: {
    pt: ["Biblioteca de Fontes", "Notícias e relatórios salvos."],
    en: ["Source Library", "Saved news and reports."],
  },
};

// Não é paywall: o cadastro é livre e esta área é liberada na mão, login a
// login. O card diz isso — sem preço, sem plano, sem "faça upgrade".
export function PremiumRoute({ children, feature }: { children: React.ReactNode; feature: Feature }) {
  const { auth, loading } = useAuth();
  const { language } = useLanguage();
  const pt = language === "pt";

  if (!loading && auth.authenticated && auth.isPremium) return <>{children}</>;

  const [title, blurb] = COPY[feature][pt ? "pt" : "en"];
  const anonymous = !loading && !auth.authenticated;

  return (
    <div
      className="soc-shell relative min-h-screen bg-background flex flex-col"
    >
      <div className="soc-grid pointer-events-none absolute inset-0 z-0" />
      <Header />
      <main className="relative z-10 flex-1 container mx-auto px-4 py-12 max-w-lg w-full flex flex-col justify-center">
        {loading ? (
          <Card><CardContent className="p-6 flex items-center gap-2 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> {pt ? "Verificando sessão…" : "Checking session…"}
          </CardContent></Card>
        ) : (
          <Card>
            <CardContent className="flex flex-col items-center gap-4 p-7 text-center">
              <span className="flex h-11 w-11 items-center justify-center rounded-lg border border-border bg-secondary">
                <Lock className="h-5 w-5 text-muted-foreground" />
              </span>

              <div>
                <Badge variant="outline" className="mb-2 font-normal">
                  {pt ? "Acesso restrito" : "Restricted access"}
                </Badge>
                <h1 className="text-xl font-bold">{title}</h1>
                <p className="mt-1.5 text-sm text-muted-foreground">{blurb}</p>
              </div>

              {anonymous ? (
                <>
                  <div className="grid w-full gap-2 sm:grid-cols-2">
                    <Button asChild className="w-full">
                      <Link to="/login"><Github className="h-4 w-4" /> {pt ? "Entrar" : "Sign in"}</Link>
                    </Button>
                    <Button asChild variant="outline" className="w-full">
                      <Link to="/cadastro">{pt ? "Criar conta" : "Create account"} <ArrowRight className="h-4 w-4" /></Link>
                    </Button>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {pt
                      ? "A conta é gratuita e leva um clique. Esta área depende de liberação."
                      : "The account is free and takes one click. This area needs to be granted."}
                  </p>
                </>
              ) : (
                <>
                  <p className="text-sm text-muted-foreground">
                    {pt ? "Sua conta está ativa, mas ainda sem acesso a esta área." : "Your account is active, but this area is not open to it yet."}
                    {auth.login ? <> <span className="font-mono text-foreground">{auth.login}</span></> : null}
                  </p>
                  <Button asChild variant="outline" className="w-full sm:w-auto">
                    <Link to="/profile">{pt ? "Ver minha conta" : "View my account"}</Link>
                  </Button>
                  <p className="text-xs text-muted-foreground">
                    {pt
                      ? "A liberação é feita na mão, um login por vez. Mande o seu para quem administra."
                      : "Access is granted by hand, one login at a time. Send yours to whoever administers it."}
                  </p>
                </>
              )}
            </CardContent>
          </Card>
        )}
      </main>
      <Footer />
    </div>
  );
}
