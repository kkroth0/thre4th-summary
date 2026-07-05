import { Link } from "react-router-dom";
import { Lock, Github, Loader2, Sparkles, FileText, Mail, Crosshair, ArrowRight, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";
import { useAuth } from "@/contexts/AuthContext";

type Feature = "threat-brief" | "advisory-feed" | "threat-hunting";

const COPY: Record<Feature, { pt: [string, string]; en: [string, string] }> = {
  "threat-brief": {
    pt: ["Threat Brief", "Cole o link de um relatório ou notícia e receba um resumo organizado."],
    en: ["Threat Brief", "Paste a link to a report or news post and get an organized summary."],
  },
  "advisory-feed": {
    pt: ["Coletor de Intel", "Um resumo diário dos avisos de segurança que importam."],
    en: ["Intel Collector", "A daily rundown of the security alerts that matter."],
  },
  "threat-hunting": {
    pt: ["Threat Hunting", "Ferramentas pra investigar e cruzar indicadores (IOCs)."],
    en: ["Threat Hunting", "Tools to dig into and cross-check indicators (IOCs)."],
  },
};

// Gate de recurso premium = precisa estar logado (a allow-list é o "premium").
// Renderiza os filhos só quando autenticado — assim a página nem chega a montar
// (nem buscar dados) enquanto travada.
export function PremiumRoute({ children, feature }: { children: React.ReactNode; feature: Feature }) {
  const { auth, loading } = useAuth();
  const { isCollapsed } = useSidebar();
  const { language } = useLanguage();
  const pt = language === "pt";

  if (auth.authenticated) return <>{children}</>;

  const [title, blurb] = COPY[feature][pt ? "pt" : "en"];

  return (
    <div className={`min-h-screen bg-background flex flex-col transition-all duration-300 ${isCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
      <Header showBackButton />
      <main className="flex-1 container mx-auto px-4 py-12 max-w-lg w-full flex flex-col justify-center">
        {loading ? (
          <Card><CardContent className="p-6 flex items-center gap-2 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> {pt ? "Verificando sessão…" : "Checking session…"}
          </CardContent></Card>
        ) : (
          <Card className="border-primary/10  shadow-primary/5 overflow-hidden">
            <div className="bg-gradient-to-br from-primary/10 to-transparent p-6 text-center">
              <div className="mx-auto mb-3 h-14 w-14 rounded-xl bg-primary/15 ring-1 ring-inset ring-primary/25 flex items-center justify-center">
                <Lock className="h-6 w-6 text-primary" />
              </div>
              <Badge className="mb-2 gap-1"><Sparkles className="h-3 w-3" /> {pt ? "Recurso premium" : "Premium feature"}</Badge>
              <h1 className="text-2xl font-bold">{title}</h1>
              <p className="text-muted-foreground mt-1.5 text-sm">{blurb}</p>
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
              <Button asChild size="lg" className="w-full">
                <Link to="/login"><Github className="h-4 w-4 mr-2" /> {pt ? "Entrar com GitHub" : "Sign in with GitHub"} <ArrowRight className="h-4 w-4 ml-1.5" /></Link>
              </Button>
              <p className="text-xs text-center text-muted-foreground inline-flex items-center justify-center gap-1">
                <ShieldCheck className="h-3 w-3" /> {pt ? "Só quem está na lista entra." : "Only people on the list can sign in."}
              </p>
            </CardContent>
          </Card>
        )}
      </main>
      <Footer />
    </div>
  );
}
