import { Link } from "react-router-dom";
import { Lock, Github, Loader2, Sparkles, FileText, Mail, Crosshair, ArrowRight, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { useLanguage } from "@/contexts/LanguageContext";
import { useAuth } from "@/contexts/AuthContext";
import { useSidebar } from "@/contexts/SidebarContext";
import { cn } from "@/lib/utils";

type Feature = "threat-brief" | "advisory-feed" | "exposure-watchlist" | "knowledge" | "hunting";

const COPY: Record<Feature, { pt: [string, string]; en: [string, string] }> = {
  "threat-brief": {
    pt: ["Threat Feed Generator", "Cole o link de um relatório ou notícia e receba uma análise organizada."],
    en: ["Threat Feed Generator", "Paste a link to a report or news post and get an organized analysis."],
  },
  "advisory-feed": {
    pt: ["Coletor de Intel", "Um resumo diário dos avisos de segurança que importam."],
    en: ["Intel Collector", "A daily rundown of the security alerts that matter."],
  },
  "exposure-watchlist": {
    pt: ["Attack Surface Monitor", "Monitore ativos externos e acompanhe drift na superficie exposta."],
    en: ["Attack Surface Monitor", "Monitor external assets and track exposed-surface drift."],
  },
  knowledge: {
    pt: ["Knowledge", "Guarde as fontes que importam e transforme cada uma em relatório."],
    en: ["Knowledge", "Keep the sources that matter and turn each one into a report."],
  },
  hunting: {
    pt: ["Hunting", "Explore hipóteses, mantenha consultas KQL e acompanhe sua cobertura ATT&CK."],
    en: ["Hunting", "Explore hypotheses, keep KQL queries, and track your ATT&CK coverage."],
  },
};

// Gate de recurso premium = login aberto + allow-list premium separada.
// Renderiza os filhos só quando a sessão existe e o usuário tem premium.
export function PremiumRoute({ children, feature }: { children: React.ReactNode; feature: Feature }) {
  const { auth, loading } = useAuth();
  const { language } = useLanguage();
  const { isCollapsed } = useSidebar();
  const pt = language === "pt";

  if (!loading && auth.authenticated && auth.isPremium) return <>{children}</>;

  const [title, blurb] = COPY[feature][pt ? "pt" : "en"];
  const anonymous = !loading && !auth.authenticated;

  return (
    <div
      className={cn(
        "soc-shell relative min-h-screen bg-background flex flex-col transition-[padding] duration-200",
        isCollapsed ? "lg:pl-[72px]" : "lg:pl-64"
      )}
    >
      <div className="soc-grid pointer-events-none absolute inset-0 z-0" />
      <Header />
      <main className="relative z-10 flex-1 container mx-auto px-4 py-12 max-w-lg w-full flex flex-col justify-center">
        {loading ? (
          <Card><CardContent className="p-6 flex items-center gap-2 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> {pt ? "Verificando sessão…" : "Checking session…"}
          </CardContent></Card>
        ) : (
          <Card className="border-border/50  shadow-primary/5 overflow-hidden">
            <div className="bg-gradient-to-br from-primary/10 to-transparent p-6 text-center">
              <div className="mx-auto mb-3 h-14 w-14 rounded-xl bg-primary/15 ring-1 ring-inset ring-primary/25 flex items-center justify-center">
                <Lock className="h-6 w-6 text-primary" />
              </div>
              <Badge className="mb-2 gap-1"><Sparkles className="h-3 w-3" /> {pt ? "Recurso premium" : "Premium feature"}</Badge>
              <h1 className="text-2xl font-bold">{title}</h1>
              <p className="text-muted-foreground mt-1.5 text-sm">
                {anonymous
                  ? blurb
                  : (pt
                    ? "Sua conta já acessa as ferramentas gratuitas. Este recurso precisa de liberação premium."
                    : "Your account can already use the free tools. This feature needs premium access.")}
              </p>
            </div>
            <CardContent className="p-6 pt-5 flex flex-col gap-4">
              <ul className="space-y-2 text-sm text-muted-foreground">
                {[
                  { icon: FileText, t: pt ? "Um resumo a partir de qualquer link" : "A summary from any link" },
                  { icon: Mail, t: pt ? "Um feed dos avisos que importam" : "A feed of the alerts that matter" },
                  { icon: Crosshair, t: pt ? "Ajuda pra investigar ameaças" : "Help digging into threats" },
                ].map((r) => (
                  <li key={r.t} className="flex items-center gap-2.5">
                    <r.icon className="h-4 w-4 text-primary shrink-0" /> {r.t}
                  </li>
                ))}
              </ul>
              {anonymous ? (
                <div className="grid gap-2 sm:grid-cols-2">
                  <Button asChild size="lg" className="w-full">
                    <Link to="/login"><Github className="h-4 w-4 mr-2" /> {pt ? "Entrar" : "Sign in"}</Link>
                  </Button>
                  <Button asChild size="lg" variant="outline" className="w-full">
                    <Link to="/cadastro">{pt ? "Cadastrar" : "Sign up"} <ArrowRight className="h-4 w-4 ml-1.5" /></Link>
                  </Button>
                </div>
              ) : (
                <Button asChild size="lg" variant="outline" className="w-full">
                  <Link to="/profile"><Github className="h-4 w-4 mr-2" /> {pt ? "Ver minha conta" : "View my account"}</Link>
                </Button>
              )}
              <p className="text-xs text-center text-muted-foreground inline-flex items-center justify-center gap-1">
                <ShieldCheck className="h-3 w-3" />
                {anonymous
                  ? (pt ? "Conta free liberada. Premium depende da allow-list." : "Free account allowed. Premium depends on the allow-list.")
                  : (pt ? "Peça para um admin adicionar seu GitHub na lista premium." : "Ask an admin to add your GitHub login to the premium list.")}
              </p>
            </CardContent>
          </Card>
        )}
      </main>
      <Footer />
    </div>
  );
}
