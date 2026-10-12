import { Link } from "react-router-dom";
import { ArrowRight, Bookmark, FileText, Github, Rss } from "lucide-react";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { Button } from "@/components/ui/button";
import { useLanguage } from "@/contexts/LanguageContext";
import { LandingPipeline } from "@/components/LandingPipeline";

const repository = "https://github.com/kkroth0/thre4th-summary";

export default function Home() {
  const { language } = useLanguage();
  const pt = language === "pt";
  const workflow = [
    { icon: Rss, number: "01", title: pt ? "Reúna as fontes" : "Bring sources together", text: pt ? "Notícias, advisories e pesquisas de segurança em um feed com links para as publicações originais." : "Security news, advisories and research in a feed linked to the original publications.", path: "/newsletter" },
    { icon: Bookmark, number: "02", title: pt ? "Guarde o que importa" : "Save what matters", text: pt ? "Salve publicações relevantes para consultar depois e continuar a investigação." : "Save relevant publications to revisit later and continue your investigation.", path: "/knowledge" },
    { icon: FileText, number: "03", title: pt ? "Produza inteligência" : "Produce intelligence", text: pt ? "Use relatórios e resumos para transformar a leitura em material para sua equipe." : "Use reports and summaries to turn your reading into material for your team.", path: "/relatorios" },
  ];

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <Header />
      <main className="mx-auto w-full max-w-7xl px-5 md:px-8">
        <section className="max-w-4xl py-12 lg:py-16">
          <div>
            <p className="mb-6 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-primary">
              <span className="h-2 w-2 rounded-full bg-primary" />
              Open source threat intelligence
            </p>
            <h1 className="max-w-2xl text-4xl font-semibold leading-[1.1] tracking-tight sm:text-5xl lg:text-6xl">
              {pt ? "Das fontes à inteligência de ameaças." : "From sources to threat intelligence."}
            </h1>
            <p className="mt-6 max-w-xl text-lg leading-relaxed text-muted-foreground">
              {pt ? "Colete publicações de segurança, correlacione eventos e investigue CVEs, indicadores, atores e malware com referências às fontes originais. Uma plataforma CTI open source." : "Collect security publications, correlate events and investigate CVEs, indicators, actors and malware with references to original sources. An open source CTI platform."}
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Button asChild size="lg"><Link to="/newsletter"><Rss className="mr-2 h-4 w-4" />{pt ? "Abrir feed de inteligência" : "Open intelligence feed"}<ArrowRight className="ml-2 h-4 w-4" /></Link></Button>
              <Button asChild size="lg" variant="outline"><a href={repository} target="_blank" rel="noopener noreferrer"><Github className="mr-2 h-4 w-4" />{pt ? "Explorar o código" : "Explore the code"}</a></Button>
            </div>
            <p className="mt-4 max-w-xl text-xs leading-relaxed text-muted-foreground">
              {pt ? "Código sob AGPL-3.0. A instância hospedada exige uma conta autorizada para notícias, publicações salvas e relatórios." : "Code licensed under AGPL-3.0. The hosted instance requires an authorized account for news, saved publications and reports."}
            </p>
          </div>

        </section>

        <LandingPipeline pt={pt} />

        <section aria-labelledby="workflow-title" className="border-t border-border py-12 md:py-16">
          <div className="mb-8 flex flex-wrap items-end justify-between gap-3">
            <div><p className="mb-2 text-xs font-semibold uppercase tracking-widest text-primary">{pt ? "Disponível hoje" : "Available today"}</p><h2 id="workflow-title" className="text-2xl font-semibold tracking-tight sm:text-3xl">{pt ? "Um fluxo para sua pesquisa CTI." : "A workflow for your CTI research."}</h2></div>
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
          <div><h2 className="text-2xl font-semibold">{pt ? "Aberta para construir junto." : "Open to build together."}</h2><p className="mt-4 text-sm leading-relaxed text-muted-foreground">{pt ? "Execute sua própria instância, inspecione como os feeds são processados e contribua com fontes, correlação e avaliação. A especialização começa por uma inteligência rastreável até a origem." : "Run your own instance, inspect how feeds are processed and contribute sources, correlation and evaluation. Specialization starts with intelligence traceable to its sources."}</p><a href={`${repository}/blob/main/README.md`} target="_blank" rel="noopener noreferrer" className="mt-5 inline-flex items-center gap-2 text-sm font-semibold text-primary">{pt ? "Documentação e instalação" : "Documentation and setup"}<ArrowRight className="h-4 w-4" /></a></div>
          <div><h3 className="text-sm font-semibold">{pt ? "Contexto para aprofundar a investigação" : "Context for deeper investigation"}</h3><div className="mt-4 grid gap-2">{[["/atores", pt ? "Atores e aliases" : "Actors and aliases"], ["/cves", pt ? "Vulnerabilidades e exploração" : "Vulnerabilities and exploitation"], ["/threat-map", pt ? "Vítimas de ransomware" : "Ransomware victims"], ["/analyzer", pt ? "Consulta de indicadores" : "Indicator lookup"]].map(([path, label]) => <Link key={path} to={path} className="flex items-center justify-between rounded-lg border border-border bg-background px-4 py-3 text-sm hover:border-primary/50">{label}<ArrowRight className="h-4 w-4 text-muted-foreground" /></Link>)}</div></div>
        </section>
      </main>
      <Footer />
    </div>
  );
}
