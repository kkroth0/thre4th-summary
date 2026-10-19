import { Link } from "react-router-dom";
import { ArrowRight, Bookmark, FileText, Search, Rss } from "lucide-react";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { Button } from "@/components/ui/button";
import { useLanguage } from "@/contexts/LanguageContext";
import { LandingPipeline } from "@/components/LandingPipeline";

export default function Home() {
  const { language } = useLanguage();
  const pt = language === "pt";
  const workflow = [
    { icon: Rss, number: "01", title: pt ? "Acompanhe o que importa" : "Follow what matters", text: pt ? "Filtre notícias e avisos de segurança por tema, severidade e contexto da sua organização." : "Filter security news and advisories by topic, severity and organizational context.", path: "/newsletter" },
    { icon: Bookmark, number: "02", title: pt ? "Guarde o que importa" : "Save what matters", text: pt ? "Salve publicações relevantes para consultar depois e continuar a investigação." : "Save relevant publications to revisit later and continue your investigation.", path: "/knowledge" },
    { icon: FileText, number: "03", title: pt ? "Entregue análises com contexto" : "Deliver analysis with context", text: pt ? "Transforme notícias, indicadores e vulnerabilidades em boletins e relatórios para sua equipe." : "Turn news, indicators and vulnerabilities into briefings and reports for your team.", path: "/relatorios" },
  ];

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <Header />
      <main className="mx-auto w-full max-w-7xl px-5 md:px-8">
        <section className="max-w-4xl py-12 lg:py-16">
          <div>
            <p className="mb-6 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-primary">
              <span className="h-2 w-2 rounded-full bg-primary" />
              {pt ? "CTI para sua rotina de análise" : "CTI for your analysis workflow"}
            </p>
            <h1 className="max-w-2xl text-4xl font-semibold leading-[1.1] tracking-tight sm:text-5xl lg:text-6xl">
              {pt ? "Inteligência de ameaças feita para o analista." : "Threat intelligence built for the analyst."}
            </h1>
            <p className="mt-6 max-w-xl text-lg leading-relaxed text-muted-foreground">
              {pt ? "Reúna notícias, IOCs, CVEs, atores e malware em uma investigação conectada. Priorize ameaças, acompanhe evidências e transforme suas análises em relatórios." : "Bring news, IOCs, CVEs, actors and malware into one connected investigation. Prioritize threats, follow the evidence and turn your analysis into reports."}
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Button asChild size="lg"><Link to="/newsletter"><Rss className="mr-2 h-4 w-4" />{pt ? "Começar investigação" : "Start investigating"}<ArrowRight className="ml-2 h-4 w-4" /></Link></Button>
              <Button asChild size="lg" variant="outline"><Link to="/analyzer"><Search className="mr-2 h-4 w-4" />{pt ? "Consultar um IOC" : "Look up an IOC"}</Link></Button>
            </div>
            <p className="mt-4 max-w-xl text-xs leading-relaxed text-muted-foreground">
              {pt ? "Notícias, publicações salvas e relatórios disponíveis para contas autorizadas." : "News, saved publications and reports are available to authorized accounts."}
            </p>
          </div>

        </section>

        <LandingPipeline pt={pt} />

        <section aria-labelledby="workflow-title" className="border-t border-border py-12 md:py-16">
          <div className="mb-8 flex flex-wrap items-end justify-between gap-3">
            <div><p className="mb-2 text-xs font-semibold uppercase tracking-widest text-primary">{pt ? "Disponível hoje" : "Available today"}</p><h2 id="workflow-title" className="text-2xl font-semibold tracking-tight sm:text-3xl">{pt ? "Da triagem ao relatório, um fluxo para o analista." : "An analyst workflow, from triage to reporting."}</h2></div>
            <Link to="/vendors" className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-primary">{pt ? "Conheça as fontes de dados" : "Explore data sources"}<ArrowRight className="h-4 w-4" /></Link>
          </div>
          <div className="grid gap-4 md:grid-cols-3">
            {workflow.map(({ icon: Icon, number, title, text, path }) => (
              <Link key={path} to={path} className="group rounded-xl border border-border bg-card p-6 transition-colors hover:border-primary/50">
                <div className="mb-8 flex items-center justify-between"><Icon className="h-6 w-6 text-primary" /><span className="font-mono text-xs text-muted-foreground">{number}</span></div>
                <h3 className="text-lg font-semibold">{title}</h3><p className="mt-3 text-sm leading-relaxed text-muted-foreground">{text}</p><ArrowRight className="mt-6 h-4 w-4 text-muted-foreground group-hover:text-primary" />
              </Link>
            ))}
          </div>
        </section>

        <section className="mb-14 grid gap-8 rounded-2xl border border-border bg-secondary/30 p-6 md:grid-cols-2 md:p-10">
          <div><h2 className="text-2xl font-semibold">{pt ? "Sua análise começa com contexto." : "Your analysis starts with context."}</h2><p className="mt-4 text-sm leading-relaxed text-muted-foreground">{pt ? "Explore as conexões entre notícias, indicadores, vulnerabilidades e atores de ameaça. Encontre as fontes que sustentam cada relação e aprofunde a investigação com as evidências à mão." : "Explore connections between news, indicators, vulnerabilities and threat actors. Find the sources behind each relationship and investigate further with the evidence at hand."}</p><Link to="/dashboard" className="mt-5 inline-flex items-center gap-2 text-sm font-semibold text-primary">{pt ? "Abrir visão de inteligência" : "Open intelligence overview"}<ArrowRight className="h-4 w-4" /></Link></div>
          <div><h3 className="text-sm font-semibold">{pt ? "Contexto para aprofundar a investigação" : "Context for deeper investigation"}</h3><div className="mt-4 grid gap-2">{[["/atores", pt ? "Atores e aliases" : "Actors and aliases"], ["/cves", pt ? "Vulnerabilidades e exploração" : "Vulnerabilities and exploitation"], ["/threat-map", pt ? "Vítimas de ransomware" : "Ransomware victims"], ["/analyzer", pt ? "Consulta de indicadores" : "Indicator lookup"]].map(([path, label]) => <Link key={path} to={path} className="flex items-center justify-between rounded-lg border border-border bg-background px-4 py-3 text-sm hover:border-primary/50">{label}<ArrowRight className="h-4 w-4 text-muted-foreground" /></Link>)}</div></div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
