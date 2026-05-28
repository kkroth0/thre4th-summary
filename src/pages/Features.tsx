import { useState } from "react";
import { Link } from "react-router-dom";
import { 
  Activity, BookOpen, ShieldAlert, Globe, MailWarning, Mail, Shield, 
  Terminal, ArrowRight, CheckCircle2, ChevronDown, Sparkles, AlertTriangle, Cpu, Network
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Footer } from "@/components/Footer";
import { Header } from "@/components/Header";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";

type Category = "all" | "intel" | "network" | "content";

export default function Features() {
  const { isCollapsed } = useSidebar();
  const { language } = useLanguage();
  const [activeCategory, setActiveCategory] = useState<Category>("all");

  const categories = [
    { id: "all", label: language === "pt" ? "Todos" : "All" },
    { id: "intel", label: language === "pt" ? "Inteligência de Ameaças" : "Threat Intel" },
    { id: "network", label: language === "pt" ? "Infraestrutura & DNS" : "Network & DNS" },
    { id: "content", label: language === "pt" ? "Conteúdo & Vulnerabilidades" : "Content & Vulns" },
  ];

  const features = [
    {
      id: "cti",
      category: "intel",
      icon: Activity,
      title: language === "pt" ? "Motor de Reputação CTI" : "CTI Reputation Engine",
      description: language === "pt" 
        ? "Consolida relatórios de reputação, contagem de abusos e vereditos de segurança em mais de 21 provedores de CTI."
        : "Consolidate reputation reports, abuse scores, and security verdicts across 21+ global threat intelligence databases.",
      helpText: language === "pt"
        ? "Reduz o tempo de triagem de incidentes ao agrupar múltiplos bancos de dados em uma única consulta."
        : "Saves critical analyst triage time by grouping multiple threat feeds into a single, unified search.",
      path: "/",
      cta: language === "pt" ? "Analisar Indicadores" : "Analyze Indicators",
    },
    {
      id: "dns-flow",
      category: "network",
      icon: Globe,
      title: language === "pt" ? "Gráfico de Fluxo DNS & WHOIS" : "DNS & WHOIS Flow Graph",
      description: language === "pt" 
        ? "Mapeia visualmente registros de DNS e históricos de WHOIS com suporte a detecção de subdomínios via DNSDumpster."
        : "Graphically map DNS records and WHOIS history with passive subdomain discovery powered by DNSDumpster.",
      helpText: language === "pt"
        ? "Revela infraestruturas ocultas, servidores de e-mail (MX) e IPs vinculados a campanhas suspeitas."
        : "Uncovers shadow IT resources, active mail servers, and IPs linked to malicious campaigns.",
      path: "/dns-visualizer",
      cta: language === "pt" ? "Visualizar DNS" : "Visualize DNS",
    },
    {
      id: "phishing",
      category: "content",
      icon: MailWarning,
      title: language === "pt" ? "Analisador de Phishing" : "Phishing Analyzer",
      description: language === "pt" 
        ? "Examina e-mails, domínios suspeitos e registros SPF/DKIM em busca de assinaturas de engenharia social."
        : "Scan emails, suspicious domains, and SPF/DKIM verification records to flag social engineering signatures.",
      helpText: language === "pt"
        ? "Evita cliques em links falsos detalhando a idade do domínio e o histórico de abuso."
        : "Prevents credential harvesting by showing domain creation timestamps and reputation scores.",
      path: "/phishing-analyzer",
      cta: language === "pt" ? "Analisar E-mails" : "Analyze Phishing",
    },
    {
      id: "dnsbl",
      category: "network",
      icon: ShieldAlert,
      title: language === "pt" ? "Verificador de Blocklists (DNSBL)" : "DNSBL Blacklist Checker",
      description: language === "pt" 
        ? "Valida IPs e servidores de e-mail contra redes globais de spam e listas de bloqueio reputacionais."
        : "Validate IPs and mail servers against global spam blacklist networks and reputation databases.",
      helpText: language === "pt"
        ? "Mantém a confiabilidade do seu domínio e alerta sobre servidores locais potencialmente infectados."
        : "Helps preserve sender domain authority and alerts you if local assets are blacklisted.",
      path: "/dnsbl",
      cta: language === "pt" ? "Checar Blocklists" : "Check Blocklists",
    },
    {
      id: "newsletter",
      category: "content",
      icon: Mail,
      title: language === "pt" ? "Feed de Advisories CTI" : "CTI Advisory Stream",
      description: language === "pt" 
        ? "Fluxo contínuo de atualizações sobre campanhas ativas, vulnerabilidades críticas e boletins de segurança."
        : "Continuous stream of security alerts, zero-day threat profiles, and practical campaign mitigation guidelines.",
      helpText: language === "pt"
        ? "Fornece inteligência acionável e indicadores de comprometimento (IOCs) para o seu time de defesa."
        : "Provides actionable intelligence and IOCs to help proactive defense teams update boundary controls.",
      path: "/newsletter",
      cta: language === "pt" ? "Ver Advisories" : "View Advisories",
    },
    {
      id: "cves",
      category: "content",
      icon: Shield,
      title: language === "pt" ? "Painel de Vulnerabilidades CVE" : "CVE Dashboard",
      description: language === "pt" 
        ? "Painel de busca e filtragem conectado ao banco nacional de vulnerabilidades (NVD) para controle de exploits."
        : "Search, filter, and track public security defects cataloged by the National Vulnerability Database (NVD).",
      helpText: language === "pt"
        ? "Facilita a priorização de correções com base na gravidade do vetor CVSS e referências externas."
        : "Simplifies patch management schedules by filtering vulnerabilities by CVSS score metrics.",
      path: "/cves",
      cta: language === "pt" ? "Pesquisar CVEs" : "Search CVEs",
    },
    {
      id: "vendors",
      category: "intel",
      icon: BookOpen,
      title: language === "pt" ? "Catálogo de Conectores API" : "API Connectors Ecosystem",
      description: language === "pt" 
        ? "Veja todos os parceiros de inteligência, suas especialidades e o status atual de comunicação da chave de API."
        : "Browse active integration status, vendor capabilities, and credentials configured across the platform.",
      helpText: language === "pt"
        ? "Centraliza a transparência sobre quais feeds reputacionais alimentam as respostas do ThreatSumm4ry."
        : "Ensures configuration transparency over the intelligence partners powering your queries.",
      path: "/vendors",
      cta: language === "pt" ? "Ver Integrações" : "View Connectors",
    },
  ];

  const filteredFeatures = activeCategory === "all" 
    ? features 
    : features.filter(f => f.category === activeCategory);

  const stats = [
    { value: "21+", label: language === "pt" ? "Integrações CTI" : "CTI Connectors" },
    { value: "100%", label: language === "pt" ? "Varreduras Passivas" : "Passive Scanning" },
    { value: "< 2s", label: language === "pt" ? "Tempo de Resposta" : "Query Latency" },
    { value: "PDF", label: language === "pt" ? "Relatórios Exportáveis" : "Exportable Reports" },
  ];

  return (
    <div className={`min-h-screen bg-background flex flex-col transition-all duration-300 ${isCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
      <Header />

      <div className="flex-1 space-y-12 pb-16">
        {/* Hero Section */}
        <section className="relative overflow-hidden pt-12 md:pt-16 pb-8 border-b border-border/20 bg-[radial-gradient(circle_at_center,rgba(var(--primary-rgb),0.03),transparent_65%)]">
          <div className="max-w-4xl mx-auto text-center px-4 space-y-6">
            <Badge variant="outline" className="px-3 py-1 rounded-full border-primary/20 bg-primary/5 text-primary text-xs gap-1.5 animate-pulse">
              <Sparkles className="h-3 w-3" />
              {language === "pt" ? "NOVO: Integração DNSDumpster Ativa" : "NEW: DNSDumpster Integration Active"}
            </Badge>
            <h1 className="text-4xl md:text-5xl font-extrabold tracking-tight bg-gradient-to-r from-foreground via-foreground/90 to-foreground/60 bg-clip-text text-transparent">
              {language === "pt" ? "Inteligência contra Ameaças Simplificada" : "Cyber Threat Intelligence, Simplified"}
            </h1>
            <p className="text-base text-muted-foreground/80 max-w-2xl mx-auto leading-relaxed">
              {language === "pt"
                ? "O ThreatSumm4ry reúne um ecossistema completo de ferramentas passivas para ajudar analistas de segurança, threat hunters e administradores a correlacionar ameaças em tempo recorde."
                : "ThreatSumm4ry gathers a comprehensive ecosystem of passive analytical tools to help security analysts, threat hunters, and system administrators correlate infrastructure indicators in real-time."}
            </p>
          </div>

          {/* Stats Bar */}
          <div className="max-w-5xl mx-auto px-4 mt-12 grid grid-cols-2 md:grid-cols-4 gap-4">
            {stats.map((s, idx) => (
              <div key={idx} className="bg-card/30 backdrop-blur-sm border border-border/25 rounded-2xl p-4 text-center space-y-1 shadow-inner shadow-primary/2">
                <div className="text-2xl md:text-3xl font-black text-primary tracking-tight">{s.value}</div>
                <div className="text-[10px] uppercase font-bold tracking-widest text-muted-foreground/60">{s.label}</div>
              </div>
            ))}
          </div>
        </section>

        {/* Feature Filters */}
        <section className="max-w-6xl mx-auto px-4 space-y-8">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4 border-b border-border/30 pb-4">
            <div className="space-y-1">
              <h2 className="text-xl font-bold tracking-tight text-foreground">
                {language === "pt" ? "Nossas Ferramentas Analíticas" : "Analytical Module Directory"}
              </h2>
              <p className="text-xs text-muted-foreground">
                {language === "pt" ? "Filtre módulos por categoria de uso." : "Filter capability modules by category."}
              </p>
            </div>
            <div className="flex flex-wrap gap-1 bg-muted/30 p-1 border border-border/30 rounded-xl">
              {categories.map((c) => (
                <button
                  key={c.id}
                  onClick={() => setActiveCategory(c.id as Category)}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${
                    activeCategory === c.id 
                      ? "bg-primary text-primary-foreground shadow"
                      : "text-muted-foreground hover:text-foreground hover:bg-muted/40"
                  }`}
                >
                  {c.label}
                </button>
              ))}
            </div>
          </div>

          {/* Feature Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredFeatures.map((f) => {
              const IconComponent = f.icon;
              return (
                <Card key={f.id} className="relative group overflow-hidden border-border/30 bg-card/20 backdrop-blur-sm hover:border-primary/40 hover:shadow-lg hover:shadow-primary/5 transition-all duration-300 hover:-translate-y-1 flex flex-col justify-between">
                  <div className="absolute top-0 right-0 h-16 w-16 bg-gradient-to-br from-primary/5 to-transparent rounded-bl-full pointer-events-none group-hover:from-primary/10 transition-all" />
                  <CardHeader className="space-y-3">
                    <div className="h-10 w-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary group-hover:bg-primary/20 group-hover:scale-105 transition-all">
                      <IconComponent className="h-5 w-5" />
                    </div>
                    <CardTitle className="text-base font-bold tracking-tight text-foreground">{f.title}</CardTitle>
                    <CardDescription className="text-xs text-muted-foreground/75 leading-relaxed">{f.description}</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4 pt-0">
                    <div className="bg-muted/15 border border-border/20 rounded-lg p-2.5 text-[11px] text-muted-foreground/80 leading-normal flex items-start gap-2">
                      <Cpu className="h-3.5 w-3.5 text-primary shrink-0 mt-0.5" />
                      <div>
                        <strong className="font-semibold text-foreground">{language === "pt" ? "Como ajuda: " : "Benefit: "}</strong>
                        {f.helpText}
                      </div>
                    </div>
                    <Link to={f.path} className="block">
                      <Button className="w-full h-9 rounded-xl font-bold text-xs gap-1.5">
                        {f.cta}
                        <ArrowRight className="h-3 w-3 group-hover:translate-x-0.5 transition-transform" />
                      </Button>
                    </Link>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </section>

        {/* Platform FAQs */}
        <section className="max-w-3xl mx-auto px-4 space-y-6 pt-4">
          <div className="text-center space-y-2">
            <h2 className="text-2xl font-bold tracking-tight text-foreground">
              {language === "pt" ? "Dúvidas Frequentes" : "Frequently Asked Questions"}
            </h2>
            <p className="text-xs text-muted-foreground">
              {language === "pt" ? "Saiba mais sobre a privacidade das consultas e o ecossistema." : "Understand our lookup policies, query privacy, and integration architecture."}
            </p>
          </div>

          <Accordion type="single" collapsible className="w-full border border-border/30 rounded-2xl bg-card/15 p-4 space-y-2">
            <AccordionItem value="q1" className="border-b border-border/20 last:border-0 pb-1">
              <AccordionTrigger className="text-sm font-semibold hover:no-underline hover:text-primary transition-colors text-foreground">
                {language === "pt" ? "Como funciona o motor de busca unificado?" : "How does the consolidated search work?"}
              </AccordionTrigger>
              <AccordionContent className="text-xs text-muted-foreground/80 leading-relaxed pt-1.5 pb-3">
                {language === "pt"
                  ? "Nosso backend proxy conecta-se de forma paralela via chaves de API a diversos parceiros reputacionais (VirusTotal, AbuseIPDB, Shodan, etc.). Retornamos as respostas em tempo real, organizando logs, pontuações de perigo e mapeando IPs ativos."
                  : "Our backend API query proxy routes target addresses parallelly to configured endpoints (VirusTotal, AbuseIPDB, Shodan). Results are structured on-the-fly, producing threat levels, logs, and connection charts."}
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="q2" className="border-b border-border/20 last:border-0 pb-1">
              <AccordionTrigger className="text-sm font-semibold hover:no-underline hover:text-primary transition-colors text-foreground">
                {language === "pt" ? "As pesquisas são passivas e seguras?" : "Are intelligence searches completely passive?"}
              </AccordionTrigger>
              <AccordionContent className="text-xs text-muted-foreground/80 leading-relaxed pt-1.5 pb-3">
                {language === "pt"
                  ? "Sim. Toda requisição é realizada em nosso backend ou por APIs reputacionais públicas. Em nenhum momento seu endereço de IP local ou rede interna entra em contato com o domínio, IP ou hash suspeito pesquisado."
                  : "Yes. All lookups are executed purely on the server side or through passive APIs. Your personal IP address is never exposed to the infrastructure or target domains under investigation."}
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="q3" className="last:border-0">
              <AccordionTrigger className="text-sm font-semibold hover:no-underline hover:text-primary transition-colors text-foreground">
                {language === "pt" ? "Posso exportar os relatórios?" : "Can reports be exported?"}
              </AccordionTrigger>
              <AccordionContent className="text-xs text-muted-foreground/80 leading-relaxed pt-1.5 pb-2">
                {language === "pt"
                  ? "Sim. O painel de buscas principal (CTI Search) possui um botão dedicado para exportar o relatório de inteligência compilado em formato PDF profissional, ideal para envio para times de segurança ou anexar a tickets de incidentes."
                  : "Yes. The main CTI search interface provides a print action that renders all threat intelligence verdicts, charts, and details into an audit-ready, professional PDF report."}
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </section>
      </div>

      <Footer />
    </div>
  );
}
