import { Link } from "react-router-dom";
import {
  FileText, Rss, ShieldCheck, Search, Eye, ListChecks,
  Shield, Zap, Building, Cpu, UserCheck,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Footer } from "@/components/Footer";
import { Header } from "@/components/Header";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";

const content = {
  en: {
    whyTitle: "Why",
    whyTitleHighlight: "ThreatSumm4ry",
    whyPara1: "ThreatSumm4ry is a unified threat-intelligence platform — Brazilian-Portuguese first — that turns raw security data into clear, actionable intelligence: from a single advisory URL into a structured brief, to a curated daily feed of what matters.",
    whyPara2: "Instead of juggling fragile scripts and siloed vendor APIs, you generate ready-to-share briefs, triage a relevance-scored advisory feed, and verify indicators — all in one place, with the analysis anchored to the source, never invented.",

    // 4 cards
    foundationTitle: "Automated threat briefs",
    foundationDesc: "Paste any advisory, report or news URL and get a structured brief — executive summary, affected products, CVE/CVSS/KEV, IOCs and MITRE ATT&CK — ready to render as the official deck.",
    plugTitle: "Curated advisory feed",
    plugDesc: "A daily feed aggregated from PSIRT, vendor and research sources, scored by CTI relevance and correlated with CISA KEV and FIRST EPSS.",
    silosTitle: "CVE & patch intelligence",
    silosDesc: "Track CVEs, Patch Tuesday and actively-exploited vulnerabilities, enriched with NVD severity, CWE and real exploitation status.",
    changeTitle: "Indicator verification",
    changeDesc: "Check IPs, domains and hashes against a weighted consensus of reputation sources, with passive DNS, DNSBL history and registrar data.",

    // Key features
    keyFeaturesTitle: "Key",
    keyFeaturesHighlight: "features",
    keyFeaturesSub: "Built for performance, modularity and fidelity. Every fact (IOC, CVE, KEV, TTP) is deterministic or validated against an authority — the LLM only writes the prose.",

    leftFeatureTitle: "Interactive graph exploration",
    leftFeatureSub: "An intuitive, interactive node graph to map, explore and expand threat indicators and their network relationships.",

    rightFeatureTitle: "From raw data to actionable intel",

    subFeat1Title: "Threat Brief generator",
    subFeat1Desc: "Turn any URL into a ready-to-share brief and a JSON for the official deck, with deterministic IOC and CVE extraction — nothing invented.",
    subFeat2Title: "Relevance scoring",
    subFeat2Desc: "Each advisory is scored by CTI signals — exploitation, malware, scope, sector and region — then re-ranked with CISA KEV and FIRST EPSS.",
    subFeat3Title: "MITRE ATT&CK & IOC enrichment",
    subFeat3Desc: "Full-article analysis maps techniques and sweeps indicators deterministically (defanged and validated before you ever block them).",
    subFeat4Title: "Weekly digest builder",
    subFeat4Desc: "Select advisories straight from the feed and compile a shareable weekly threat digest in one click.",
    subFeat5Title: "Exportable reports",
    subFeat5Desc: "Export briefs, IOC sets (CSV) and digests as professional JSON or PDF, ready for tickets and stakeholders.",

    // Who is it for
    whoTitle: "Who is it",
    whoTitleHighlight: "for",
    whoSub: "ThreatSumm4ry is built for teams and analysts who need to turn the firehose of advisories into decisions.",

    who1Title: "Cybersecurity & threat analysts",
    who1Desc: "Investigate alerts, triage advisories by real relevance, and produce briefs leadership can read.",
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
    ctaSub: "Generate a brief from a single URL, or open the curated advisory feed and see what matters today.",
    ctaBrief: "Threat Brief",
    ctaFeed: "Intel Collector",
    ctaCves: "CVE Dashboard",
    ctaHunt: "Threat Hunting",
  },
  pt: {
    whyTitle: "Por que o",
    whyTitleHighlight: "ThreatSumm4ry",
    whyPara1: "O ThreatSumm4ry é uma plataforma unificada de inteligência contra ameaças — pensada em português do Brasil — que transforma dados brutos de segurança em inteligência clara e acionável: de uma única URL de advisory para um boletim estruturado, até um feed diário curado do que realmente importa.",
    whyPara2: "Em vez de lidar com scripts frágeis e APIs isoladas, você gera boletins prontos para compartilhar, prioriza um feed de advisories pontuado por relevância e valida indicadores — tudo em um só lugar, com a análise ancorada na fonte e nada inventado.",

    // 4 cards
    foundationTitle: "Boletins de ameaça automáticos",
    foundationDesc: "Cole qualquer advisory, relatório ou notícia e receba um boletim estruturado — resumo executivo, produtos afetados, CVE/CVSS/KEV, IOCs e MITRE ATT&CK — pronto para virar o slide oficial.",
    plugTitle: "Feed de advisories curado",
    plugDesc: "Um feed diário agregado de fontes PSIRT, fabricantes e pesquisa, pontuado por relevância CTI e correlacionado com CISA KEV e FIRST EPSS.",
    silosTitle: "Inteligência de CVE e patches",
    silosDesc: "Acompanhe CVEs, Patch Tuesday e vulnerabilidades ativamente exploradas, enriquecidas com severidade NVD, CWE e status real de exploração.",
    changeTitle: "Verificação de indicadores",
    changeDesc: "Verifique IPs, domínios e hashes contra um consenso ponderado de fontes de reputação, com DNS passivo, histórico DNSBL e dados de registro.",

    // Key features
    keyFeaturesTitle: "Principais",
    keyFeaturesHighlight: "recursos",
    keyFeaturesSub: "Feito para performance, modularidade e fidelidade. Todo fato (IOC, CVE, KEV, TTP) é determinístico ou validado contra uma autoridade — o LLM só escreve a prosa.",

    leftFeatureTitle: "Exploração de grafo interativa",
    leftFeatureSub: "Interface visual interativa baseada em nós para mapear, explorar e expandir conexões entre indicadores de ameaça.",

    rightFeatureTitle: "Do dado bruto à inteligência acionável",

    subFeat1Title: "Gerador de Threat Brief",
    subFeat1Desc: "Transforme qualquer URL em um boletim pronto para compartilhar e um JSON para o slide oficial, com extração determinística de IOC e CVE — nada inventado.",
    subFeat2Title: "Pontuação por relevância",
    subFeat2Desc: "Cada advisory é pontuado por sinais de CTI — exploração, malware, alcance, setor e região — e re-ranqueado com CISA KEV e FIRST EPSS.",
    subFeat3Title: "Enriquecimento MITRE ATT&CK e IOC",
    subFeat3Desc: "A análise do artigo completo mapeia técnicas e varre indicadores de forma determinística (defanged e validados antes de você bloquear).",
    subFeat4Title: "Construtor de digest semanal",
    subFeat4Desc: "Selecione advisories direto do feed e compile um boletim semanal compartilhável em um clique.",
    subFeat5Title: "Relatórios exportáveis",
    subFeat5Desc: "Exporte boletins, conjuntos de IOC (CSV) e digests em JSON ou PDF profissional, prontos para chamados e gestão.",

    // Who is it for
    whoTitle: "Para quem é o",
    whoTitleHighlight: "projeto",
    whoSub: "O ThreatSumm4ry foi feito para equipes e analistas que precisam transformar a enxurrada de advisories em decisões.",

    who1Title: "Analistas de segurança e ameaças",
    who1Desc: "Investigue alertas, priorize advisories por relevância real e produza boletins que a liderança lê.",
    who2Title: "Pesquisadores de OSINT",
    who2Desc: "Colete inteligência passiva de fontes abertas e construa mapas de correlação de infraestrutura suspeita.",
    who3Title: "Resposta a incidentes",
    who3Desc: "Rastreie indicadores, extraia conjuntos de IOC validados e ataque primeiro o que está sendo explorado.",
    who4Title: "Segurança corporativa",
    who4Desc: "Monitore a reputação do perímetro e avalie o risco digital de parceiros e fornecedores.",
    who5Title: "Engenheiros de SOC",
    who5Desc: "Automatize o enriquecimento e gere relatórios JSON/PDF para anexar a chamados de incidente.",
    who6Title: "Quem escreve CTI e boletins",
    who6Desc: "Compile um digest diário/semanal a partir de um feed curado, sem copiar e colar de dez abas.",

    ctaTitle: "Pronto para começar?",
    ctaSub: "Gere um boletim a partir de uma única URL, ou abra o feed de advisories curado e veja o que importa hoje.",
    ctaBrief: "Threat Brief",
    ctaFeed: "Coletor de Intel",
    ctaCves: "Painel de CVEs",
    ctaHunt: "Threat Hunting",
  },
};

const CARD = "bg-card hover:bg-muted/40 border rounded-lg p-5 transition-colors";
const CHIP = "h-9 w-9 rounded-md bg-primary/10 text-primary flex items-center justify-center shrink-0";

export default function Features() {
  const { isCollapsed } = useSidebar();
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

  return (
    <div className={`min-h-screen bg-background text-foreground flex flex-col transition-all duration-300 ${isCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
      <Header />

      <style>{`
        @keyframes flow-dash { to { stroke-dashoffset: -20; } }
        .flow-line { animation: flow-dash 1.5s linear infinite; }
      `}</style>

      <div className="flex-1 max-w-7xl mx-auto px-4 md:px-8 py-12 md:py-20 space-y-24 md:space-y-32 w-full">

        {/* Section 1: Why */}
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-16 items-start">
          <div className="lg:col-span-5 space-y-6">
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight leading-tight">
              {t.whyTitle} <span className="text-primary">{t.whyTitleHighlight}</span>?
            </h2>
            <div className="space-y-4 text-sm md:text-base text-muted-foreground leading-relaxed">
              <p>{t.whyPara1}</p>
              <p>{t.whyPara2}</p>
            </div>
          </div>

          <div className="lg:col-span-7 grid grid-cols-1 sm:grid-cols-2 gap-4">
            {cards.map(({ icon: Icon, title, desc }) => (
              <div key={title} className={`${CARD} space-y-3`}>
                <div className={CHIP}><Icon className="h-4.5 w-4.5" /></div>
                <h3 className="text-sm font-bold tracking-wide">{title}</h3>
                <p className="text-xs text-muted-foreground leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Section 2: Key features */}
        <section className="space-y-12">
          <div className="text-center space-y-3 max-w-2xl mx-auto">
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight">
              {t.keyFeaturesTitle} <span className="text-primary">{t.keyFeaturesHighlight}</span>
            </h2>
            <p className="text-xs md:text-sm text-muted-foreground leading-relaxed">{t.keyFeaturesSub}</p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-center">
            {/* Left: graph mockup */}
            <div className="lg:col-span-7 space-y-4">
              <div className="flex items-center gap-2 mb-1">
                <Eye className="h-4.5 w-4.5 text-primary" />
                <h3 className="text-sm font-bold tracking-wide">{t.leftFeatureTitle}</h3>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed max-w-xl">{t.leftFeatureSub}</p>

              <div className="border rounded-lg p-4 relative overflow-hidden min-h-[300px] h-[340px] flex items-center justify-center bg-zinc-950">
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
                <h3 className="text-sm font-bold tracking-wide">{t.rightFeatureTitle}</h3>
              </div>
              <div className="space-y-4">
                {subFeats.map(({ title, desc }) => (
                  <div key={title} className="space-y-1">
                    <h4 className="text-xs font-bold tracking-wide">{title}</h4>
                    <p className="text-[11px] text-muted-foreground leading-normal">{desc}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* Section 3: Who is it for */}
        <section className="space-y-12">
          <div className="text-center space-y-3 max-w-2xl mx-auto">
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight">
              {t.whoTitle} <span className="text-primary">{t.whoTitleHighlight}</span>?
            </h2>
            <p className="text-xs md:text-sm text-muted-foreground leading-relaxed">{t.whoSub}</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {roles.map(({ icon: Icon, title, desc }) => (
              <div key={title} className={`${CARD} flex gap-4`}>
                <div className={CHIP}><Icon className="h-4.5 w-4.5" /></div>
                <div className="space-y-1">
                  <h3 className="text-xs font-bold tracking-wide">{title}</h3>
                  <p className="text-[11px] text-muted-foreground leading-relaxed">{desc}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* CTA */}
        <section className="text-center space-y-6 pt-6 border-t">
          <h2 className="text-xl md:text-2xl font-bold tracking-tight">{t.ctaTitle}</h2>
          <p className="text-xs text-muted-foreground max-w-md mx-auto">{t.ctaSub}</p>
          <div className="flex flex-wrap justify-center gap-3">
            <Link to="/threat-brief"><Button className="h-9 rounded-md font-semibold text-xs">{t.ctaBrief}</Button></Link>
            <Link to="/newsletter"><Button variant="outline" className="h-9 rounded-md font-semibold text-xs">{t.ctaFeed}</Button></Link>
            <Link to="/cves"><Button variant="outline" className="h-9 rounded-md font-semibold text-xs">{t.ctaCves}</Button></Link>
            <Link to="/threat-hunting"><Button variant="outline" className="h-9 rounded-md font-semibold text-xs">{t.ctaHunt}</Button></Link>
          </div>
        </section>

      </div>
      <Footer />
    </div>
  );
}
