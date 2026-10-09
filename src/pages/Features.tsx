import { Link } from "react-router-dom";
import {
  ArrowRight, FileText, Rss, ShieldCheck, Search, Eye, ListChecks,
  Shield, Zap, Building, Cpu, UserCheck,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageLayout } from "@/components/PageLayout";
import { useLanguage } from "@/contexts/LanguageContext";

const content = {
  en: {
    whyTitle: "Why",
    whyTitleHighlight: "ThreatSumm4ry",
    whyPara1: "ThreatSumm4ry is a unified threat-intelligence platform — Brazilian-Portuguese first — that turns raw security data into clear, actionable intelligence: from a single advisory URL into a structured report, to a curated daily feed of what matters.",
    whyPara2: "Instead of juggling fragile scripts and siloed vendor APIs, you generate ready-to-share reports, triage a relevance-scored advisory feed, and verify indicators — all in one place, with the analysis anchored to the source, never invented.",

    // 4 cards
    foundationTitle: "Automated CTI reports",
    foundationDesc: "Paste any advisory, report or news URL and get a structured report — executive summary, affected products, CVE/CVSS/KEV, IOCs and MITRE ATT&CK — ready to render as the official deck.",
    plugTitle: "Curated advisory feed",
    plugDesc: "A daily feed aggregated from PSIRT, vendor and research sources, scored by CTI relevance and correlated with CISA KEV and FIRST EPSS.",
    silosTitle: "CVE & patch intelligence",
    silosDesc: "Track CVEs, Patch Tuesday and actively-exploited vulnerabilities, enriched with NVD severity, CWE and real exploitation status.",
    changeTitle: "Indicator verification",
    changeDesc: "Check IPs, domains and hashes against a weighted consensus of reputation sources, with passive DNS and registrar data.",

    // Key features
    keyFeaturesTitle: "Key",
    keyFeaturesHighlight: "features",
    keyFeaturesSub: "Built for performance, modularity and fidelity. Every fact (IOC, CVE, KEV, TTP) is deterministic or validated against an authority — the LLM only writes the prose.",

    leftFeatureTitle: "Interactive graph exploration",
    leftFeatureSub: "An intuitive, interactive node graph to map, explore and expand threat indicators and their network relationships.",

    rightFeatureTitle: "From raw data to actionable intel",

    subFeat1Title: "Report generator",
    subFeat1Desc: "Turn any URL into a ready-to-share report and a JSON for the official deck, with deterministic IOC and CVE extraction — nothing invented.",
    subFeat2Title: "Relevance scoring",
    subFeat2Desc: "Each advisory is scored by CTI signals — exploitation, malware, scope, sector and region — then re-ranked with CISA KEV and FIRST EPSS.",
    subFeat3Title: "MITRE ATT&CK & IOC enrichment",
    subFeat3Desc: "Full-article analysis maps techniques and sweeps indicators deterministically (defanged and validated before you ever block them).",
    subFeat4Title: "Weekly digest builder",
    subFeat4Desc: "Select advisories straight from the feed and compile a shareable weekly threat digest in one click.",
    subFeat5Title: "Exportable reports",
    subFeat5Desc: "Export reports, IOC sets (CSV) and digests as professional JSON or PDF, ready for tickets and stakeholders.",

    // Who is it for
    whoTitle: "Who is it",
    whoTitleHighlight: "for",
    whoSub: "ThreatSumm4ry is built for teams and analysts who need to turn the firehose of advisories into decisions.",

    who1Title: "Cybersecurity & threat analysts",
    who1Desc: "Investigate alerts, triage advisories by real relevance, and produce reports leadership can read.",
    who2Title: "OSINT researchers",
    who2Desc: "Gather passive open-source intelligence and build correlation maps of suspicious infrastructure.",
    who3Title: "Incident responders",
    who3Desc: "Trace indicators, pull validated IOC sets, and act on actively-exploited vulnerabilities first.",
    who4Title: "Corporate security teams",
    who4Desc: "Monitor perimeter reputation and evaluate partner and vendor security risk.",
    who5Title: "SOC engineers",
    who5Desc: "Automate enrichment and generate JSON/PDF reports to attach to security incident tickets.",
    who6Title: "CTI & boletim writers",
    who6Desc: "Compile a daily/weekly threat digest from a curated feed without copy-pasting from ten tabs.",

    ctaTitle: "Ready to start?",
    ctaSub: "Generate a report from a single URL, or open the curated advisory feed and see what matters today.",
    ctaSearch: "ThreatSumm4ry Search",
    ctaBrief: "Report Generation",
    ctaFeed: "Intel Collector",
    ctaCves: "CVE Dashboard",
  },
  pt: {
    whyTitle: "Por que o",
    whyTitleHighlight: "ThreatSumm4ry",
    whyPara1: "O ThreatSumm4ry é uma plataforma unificada de inteligência contra ameaças — pensada em português do Brasil — que transforma dados brutos de segurança em inteligência clara e acionável: de uma única URL de advisory para um relatório estruturado, até um feed diário curado do que realmente importa.",
    whyPara2: "Em vez de lidar com scripts frágeis e APIs isoladas, você gera relatórios prontos para compartilhar, prioriza um feed de advisories pontuado por relevância e valida indicadores — tudo em um só lugar, com a análise ancorada na fonte e nada inventado.",

    // 4 cards
    foundationTitle: "Relatórios de ameaça automáticos",
    foundationDesc: "Cole qualquer advisory, relatório ou notícia e receba uma análise estruturada — resumo executivo, produtos afetados, CVE/CVSS/KEV, IOCs e MITRE ATT&CK — pronta para virar o slide oficial.",
    plugTitle: "Feed de advisories curado",
    plugDesc: "Um feed diário agregado de fontes PSIRT, fabricantes e pesquisa, pontuado por relevância CTI e correlacionado com CISA KEV e FIRST EPSS.",
    silosTitle: "Inteligência de CVE e patches",
    silosDesc: "Acompanhe CVEs, Patch Tuesday e vulnerabilidades ativamente exploradas, enriquecidas com severidade NVD, CWE e status real de exploração.",
    changeTitle: "Verificação de indicadores",
    changeDesc: "Verifique IPs, domínios e hashes contra um consenso ponderado de fontes de reputação, com DNS passivo e dados de registro.",

    // Key features
    keyFeaturesTitle: "Principais",
    keyFeaturesHighlight: "recursos",
    keyFeaturesSub: "Feito para performance, modularidade e fidelidade. Todo fato (IOC, CVE, KEV, TTP) é determinístico ou validado contra uma autoridade — o LLM só escreve a prosa.",

    leftFeatureTitle: "Exploração de grafo interativa",
    leftFeatureSub: "Interface visual interativa baseada em nós para mapear, explorar e expandir conexões entre indicadores de ameaça.",

    rightFeatureTitle: "Do dado bruto à inteligência acionável",

    subFeat1Title: "Geração de Relatórios",
    subFeat1Desc: "Transforme qualquer URL em um relatório pronto para compartilhar e um JSON para o slide oficial, com extração determinística de IOC e CVE — nada inventado.",
    subFeat2Title: "Pontuação por relevância",
    subFeat2Desc: "Cada advisory é pontuado por sinais de CTI — exploração, malware, alcance, setor e região — e re-ranqueado com CISA KEV e FIRST EPSS.",
    subFeat3Title: "Enriquecimento MITRE ATT&CK e IOC",
    subFeat3Desc: "A análise do artigo completo mapeia técnicas e varre indicadores de forma determinística (defanged e validados antes de você bloquear).",
    subFeat4Title: "Construtor de digest semanal",
    subFeat4Desc: "Selecione advisories direto do feed e compile um boletim semanal compartilhável em um clique.",
    subFeat5Title: "Relatórios exportáveis",
    subFeat5Desc: "Exporte relatórios, conjuntos de IOC (CSV) e digests em JSON ou PDF profissional, prontos para chamados e gestão.",

    // Who is it for
    whoTitle: "Para quem é o",
    whoTitleHighlight: "projeto",
    whoSub: "O ThreatSumm4ry foi feito para equipes e analistas que precisam transformar a enxurrada de advisories em decisões.",

    who1Title: "Analistas de segurança e ameaças",
    who1Desc: "Investigue alertas, priorize advisories por relevância real e produza relatórios que a liderança lê.",
    who2Title: "Pesquisadores de OSINT",
    who2Desc: "Colete inteligência passiva de fontes abertas e construa mapas de correlação de infraestrutura suspeita.",
    who3Title: "Resposta a incidentes",
    who3Desc: "Rastreie indicadores, extraia conjuntos de IOC validados e ataque primeiro o que está sendo explorado.",
    who4Title: "Segurança corporativa",
    who4Desc: "Monitore a reputação do perímetro e avalie o risco digital de parceiros e fornecedores.",
    who5Title: "Engenheiros de SOC",
    who5Desc: "Automatize o enriquecimento e gere relatórios JSON/PDF para anexar a chamados de incidente.",
    who6Title: "Quem escreve CTI e relatórios",
    who6Desc: "Compile um digest diário/semanal a partir de um feed curado, sem copiar e colar de dez abas.",

    ctaTitle: "Pronto para começar?",
    ctaSub: "Gere um relatório a partir de uma única URL, ou abra o feed de advisories curado e veja o que importa hoje.",
    ctaSearch: "Busca ThreatSumm4ry",
    ctaBrief: "Geração de Relatórios",
    ctaFeed: "Coletor de Intel",
    ctaCves: "Painel de CVEs",
  },
};

const CARD = "soc-panel rounded-lg p-5 transition-all hover:border-foreground/25 hover:shadow-sm";
const CHIP = "flex h-10 w-10 shrink-0 items-center justify-center rounded-md border border-primary/25 bg-primary/10 text-primary";

export default function Features() {
  const { language } = useLanguage();
  const t = content[language as "en" | "pt"] || content.en;

  const cards = [
    { icon: FileText, title: t.foundationTitle, desc: t.foundationDesc },
    { icon: Rss, title: t.plugTitle, desc: t.plugDesc },
    { icon: ShieldCheck, title: t.silosTitle, desc: t.silosDesc },
    { icon: Search, title: t.changeTitle, desc: t.changeDesc },
  ];
  const subFeats = [
    { title: t.subFeat1Title, desc: t.subFeat1Desc },
    { title: t.subFeat2Title, desc: t.subFeat2Desc },
    { title: t.subFeat3Title, desc: t.subFeat3Desc },
    { title: t.subFeat4Title, desc: t.subFeat4Desc },
    { title: t.subFeat5Title, desc: t.subFeat5Desc },
  ];
  const roles = [
    { icon: Shield, title: t.who1Title, desc: t.who1Desc },
    { icon: Search, title: t.who2Title, desc: t.who2Desc },
    { icon: Zap, title: t.who3Title, desc: t.who3Desc },
    { icon: Building, title: t.who4Title, desc: t.who4Desc },
    { icon: Cpu, title: t.who5Title, desc: t.who5Desc },
    { icon: UserCheck, title: t.who6Title, desc: t.who6Desc },
  ];
  const metrics = [
    ["21", language === "pt" ? "fontes" : "sources"],
    ["5", "exports"],
    ["SOC", "workflow"],
  ];

  return (
    <PageLayout width="max-w-7xl" showBackButton={false}>

      <style>{`
        @keyframes flow-dash { to { stroke-dashoffset: -20; } }
        .flow-line { animation: flow-dash 1.5s linear infinite; }
      `}</style>

      <div className="space-y-16 md:space-y-20">

        <section className="border-b border-border pb-12">
          <div className="flex flex-col gap-8 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-3xl">
              <span className="inline-flex items-center rounded-full border border-primary/25 bg-primary/10 px-3 py-1 text-[11px] font-black uppercase tracking-wide text-primary">
                {language === "pt" ? "Mapa de features" : "Feature map"}
              </span>
              <h1 className="mt-5 text-4xl font-black tracking-tight text-foreground md:text-6xl">
                {t.whyTitle} <span className="text-primary">{t.whyTitleHighlight}</span>
              </h1>
              <p className="mt-5 max-w-2xl text-base font-semibold leading-8 text-muted-foreground">
                {t.whyPara1}
              </p>
              <div className="mt-6 flex flex-wrap gap-3">
                <Button asChild className="h-10 font-bold">
                  <Link to="/analyzer">
                    {t.ctaSearch}
                    <ArrowRight className="h-4 w-4" />
                  </Link>
                </Button>
                <Button variant="outline" asChild className="h-10 font-bold">
                  <Link to="/relatorios">{t.ctaBrief}</Link>
                </Button>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-2 lg:w-80">
              {metrics.map(([value, label]) => (
                <div key={label} className="soc-panel rounded-lg p-4 text-center">
                  <div className="font-mono text-xl font-black text-foreground">{value}</div>
                  <div className="mt-1 text-[10px] font-bold uppercase tracking-wide text-muted-foreground">{label}</div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Section 1: Why */}
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-16 items-start">
          <div className="lg:col-span-5 space-y-6">
            <h2 className="text-3xl font-black tracking-tight leading-tight md:text-4xl">
              {t.whyTitle} <span className="text-primary">{t.whyTitleHighlight}</span>?
            </h2>
            <div className="space-y-4 text-sm font-medium leading-7 text-muted-foreground md:text-base">
              <p>{t.whyPara2}</p>
            </div>
          </div>

          <div className="lg:col-span-7 grid grid-cols-1 sm:grid-cols-2 gap-4">
            {cards.map(({ icon: Icon, title, desc }) => (
              <div key={title} className={`${CARD} space-y-4`}>
                <div className={CHIP}><Icon className="h-4.5 w-4.5" /></div>
                <h3 className="text-sm font-black tracking-tight text-foreground">{title}</h3>
                <p className="text-xs font-medium leading-6 text-muted-foreground">{desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Section 2: Key features */}
        <section className="space-y-12">
          <div className="text-center space-y-3 max-w-2xl mx-auto">
            <h2 className="text-3xl font-black tracking-tight md:text-4xl">
              {t.keyFeaturesTitle} <span className="text-primary">{t.keyFeaturesHighlight}</span>
            </h2>
            <p className="text-xs font-medium leading-6 text-muted-foreground md:text-sm">{t.keyFeaturesSub}</p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-center">
            {/* Left: graph mockup */}
            <div className="lg:col-span-7 space-y-4">
              <div className="flex items-center gap-2 mb-1">
                <Eye className="h-4.5 w-4.5 text-primary" />
                <h3 className="text-sm font-black tracking-tight text-foreground">{t.leftFeatureTitle}</h3>
              </div>
              <p className="text-xs font-medium leading-6 text-muted-foreground max-w-xl">{t.leftFeatureSub}</p>

              <div className="soc-panel relative flex h-[340px] min-h-[300px] items-center justify-center overflow-hidden rounded-lg bg-zinc-950 p-4">
                <div className="absolute top-3 left-4 right-4 flex items-center justify-between border-b border-white/10 pb-2 text-[9px] text-zinc-500 font-mono">
                  <div className="flex items-center gap-1.5">
                    <span className="h-1.5 w-1.5 rounded-full bg-primary" />
                    <span>CTI_GRAPH_EXPLORER</span>
                  </div>
                  <span>14.103.115.208 // Target_Scan</span>
                </div>

                <svg viewBox="0 0 420 220" className="w-full h-full pt-6 select-none">
                  <line x1="210" y1="110" x2="110" y2="50" stroke="#f43f5e" strokeWidth="1.2" strokeDasharray="4,4" className="flow-line" />
                  <line x1="210" y1="110" x2="310" y2="50" stroke="#ef4444" strokeWidth="1.2" strokeDasharray="4,4" className="flow-line" />
                  <line x1="210" y1="110" x2="110" y2="170" stroke="#10b981" strokeWidth="1.2" strokeDasharray="4,4" className="flow-line" />
                  <line x1="210" y1="110" x2="310" y2="170" stroke="#eab308" strokeWidth="1.2" strokeDasharray="4,4" className="flow-line" />
                  <line x1="110" y1="50" x2="60" y2="50" stroke="#f43f5e" strokeWidth="1" strokeDasharray="2,2" />
                  <line x1="310" y1="50" x2="360" y2="50" stroke="#ef4444" strokeWidth="1" strokeDasharray="2,2" />
                  <g transform="translate(210, 110)">
                    <circle r="28" fill="#0f0f11" stroke="#f43f5e" strokeWidth="2.5" className="animate-pulse" />
                    <text y="3" textAnchor="middle" fill="#ffffff" className="text-[7.5px] font-mono font-bold tracking-tight">14.103.115.208</text>
                  </g>
                  <g transform="translate(110, 50)"><circle r="18" fill="#121214" stroke="#f43f5e" strokeWidth="1.5" /><text y="2.5" textAnchor="middle" fill="#ef4444" className="text-[6.5px] font-bold">VirusTotal</text></g>
                  <g transform="translate(310, 50)"><circle r="18" fill="#121214" stroke="#ef4444" strokeWidth="1.5" /><text y="2.5" textAnchor="middle" fill="#ef4444" className="text-[6.5px] font-bold">AbuseIPDB</text></g>
                  <g transform="translate(110, 170)"><circle r="18" fill="#121214" stroke="#10b981" strokeWidth="1.5" /><text y="2.5" textAnchor="middle" fill="#10b981" className="text-[6.5px] font-bold">GeoIP</text></g>
                  <g transform="translate(310, 170)"><circle r="18" fill="#121214" stroke="#eab308" strokeWidth="1.5" /><text y="2.5" textAnchor="middle" fill="#eab308" className="text-[6.5px] font-bold">Shodan</text></g>
                </svg>
              </div>
            </div>

            {/* Right: feature list */}
            <div className="lg:col-span-5 space-y-6">
              <div className="flex items-center gap-2 mb-1">
                <ListChecks className="h-4.5 w-4.5 text-primary" />
                <h3 className="text-sm font-black tracking-tight text-foreground">{t.rightFeatureTitle}</h3>
              </div>
              <div className="space-y-3">
                {subFeats.map(({ title, desc }) => (
                  <div key={title} className="soc-panel rounded-lg p-4">
                    <h4 className="text-xs font-black tracking-tight text-foreground">{title}</h4>
                    <p className="mt-1.5 text-[11px] font-medium leading-5 text-muted-foreground">{desc}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* Section 3: Who is it for */}
        <section className="space-y-12">
          <div className="text-center space-y-3 max-w-2xl mx-auto">
            <h2 className="text-3xl font-black tracking-tight md:text-4xl">
              {t.whoTitle} <span className="text-primary">{t.whoTitleHighlight}</span>?
            </h2>
            <p className="text-xs font-medium leading-6 text-muted-foreground md:text-sm">{t.whoSub}</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {roles.map(({ icon: Icon, title, desc }) => (
              <div key={title} className={`${CARD} flex gap-4`}>
                <div className={CHIP}><Icon className="h-4.5 w-4.5" /></div>
                <div className="space-y-1">
                  <h3 className="text-xs font-black tracking-tight text-foreground">{title}</h3>
                  <p className="text-[11px] font-medium leading-5 text-muted-foreground">{desc}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* CTA */}
        <section className="soc-panel rounded-lg p-8 text-center">
          <h2 className="text-xl font-black tracking-tight text-foreground md:text-2xl">{t.ctaTitle}</h2>
          <p className="mx-auto mt-2 max-w-md text-xs font-medium leading-6 text-muted-foreground">{t.ctaSub}</p>
          <div className="mt-6 flex flex-wrap justify-center gap-3">
            <Link to="/analyzer"><Button className="h-9 rounded-md font-bold text-xs">{t.ctaSearch}</Button></Link>
            <Link to="/relatorios"><Button variant="outline" className="h-9 rounded-md font-bold text-xs">{t.ctaBrief}</Button></Link>
            <Link to="/newsletter"><Button variant="outline" className="h-9 rounded-md font-semibold text-xs">{t.ctaFeed}</Button></Link>
            <Link to="/cves"><Button variant="outline" className="h-9 rounded-md font-semibold text-xs">{t.ctaCves}</Button></Link>
          </div>
        </section>

      </div>
    </PageLayout>
  );
}
