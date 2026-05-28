import { useState } from "react";
import { Link } from "react-router-dom";
import { 
  Layers, Cable, Network, RefreshCw, Eye, Settings, Shield, Search, 
  Zap, Building, Cpu, UserCheck, ArrowRight, ArrowLeft
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
    whyPara1: "Threat intelligence feeds evolve, appear, and disappear. What never changes is the need to verify, correlate, and analyze indicators clearly. ThreatSumm4ry provides a unified, passive OSINT platform that stays stable while tools change.",
    whyPara2: "Instead of juggling fragile scripts and siloed vendor APIs, centralize your analysis in one place. Add a new API key? Swap a provider? Your investigative workflow stays intact, and your team's insights remain continuous.",
    
    // 4 cards
    foundationTitle: "Consolidated consensus",
    foundationDesc: "Query 21+ threat intelligence databases in parallel to compile an unbiased, high-fidelity security verdict.",
    plugTitle: "Plug-and-play APIs",
    plugDesc: "Seamlessly integrate your paid and free API subscriptions. No custom scripts, no friction.",
    silosTitle: "Break data silos",
    silosDesc: "Correlate hostnames, open ports, passive DNS, and BGP prefixes in a single unified workspace.",
    changeTitle: "Built for speed",
    changeDesc: "Scan indicators, query historical DNSBL databases, and get comprehensive results in under two seconds.",

    // Key features
    keyFeaturesTitle: "Key",
    keyFeaturesHighlight: "features",
    keyFeaturesSub: "Built with performance, modularity, and passive security in mind. ThreatSumm4ry provides everything you need for CTI and OSINT analysis.",
    
    leftFeatureTitle: "Interactive graph exploration",
    leftFeatureSub: "An intuitive, interactive node graph UI to map, explore, and expand threat indicators and their network relationships.",
    
    subFeat1Title: "Dynamic parser",
    subFeat1Desc: "Input IPs, domains, or file hashes. The search bar automatically detects target format and queries relevant sources.",
    subFeat2Title: "Passive DNS footprint",
    subFeat2Desc: "Discover subdomains and passive DNS mappings through integrated CTI pools like DNSDumpster.",
    subFeat3Title: "Weighted scoring engine",
    subFeat3Desc: "Aggressively weigh primary security engines alongside a general consensus to compute an accurate risk rating.",
    subFeat4Title: "Mitigation playbooks",
    subFeat4Desc: "Receive instant mitigation guidance, CISA KEV schedules, and registrar data for active threat vectors.",
    subFeat5Title: "Exportable reports",
    subFeat5Desc: "Compile detailed vendor analysis, charts, and DNSBL logs into professional, shareable PDF or JSON reports.",

    // Who is it for
    whoTitle: "Who is it",
    whoTitleHighlight: "for",
    whoSub: "ThreatSumm4ry is built for teams and analysts who need to verify indicators and assess digital risk.",
    
    who1Title: "Cybersecurity & threat analysts",
    who1Desc: "Investigate security alerts, analyze target reputations, and triage infrastructure indicators.",
    who2Title: "OSINT researchers",
    who2Desc: "Gather passive open-source intelligence and build correlation maps of suspicious infrastructure.",
    who3Title: "Incident responders",
    who3Desc: "Trace network indicators, evaluate spam blacklists, and block active malicious entities.",
    who4Title: "Corporate security teams",
    who4Desc: "Monitor organizational perimeter reputation and evaluate partner vendor security risk.",
    who5Title: "SOC engineers",
    who5Desc: "Automate consensus verifications and generate PDF reports for security incident tickets.",
    who6Title: "Anyone verifying threat indicators",
    who6Desc: "Ensure safe navigation, verify suspicious emails, and examine server health securely."
  },
  pt: {
    whyTitle: "Por que o",
    whyTitleHighlight: "ThreatSumm4ry",
    whyPara1: "Provedores de inteligência contra ameaças evoluem, aparecem e somem. O que nunca muda é a necessidade de verificar, correlacionar e analisar indicadores com clareza. O ThreatSumm4ry fornece uma base consolidada e estável enquanto as ferramentas mudam.",
    whyPara2: "Em vez de lidar com scripts frágeis e APIs de fabricantes isolados, centralize suas análises em um só lugar. Adicionar uma nova chave de API? Trocar de provedor? Seu fluxo de investigação permanece intacto e seus insights contínuos.",
    
    // 4 cards
    foundationTitle: "Consenso consolidado",
    foundationDesc: "Consulte mais de 21 bases de inteligência contra ameaças em paralelo para obter um veredito unificado e imparcial.",
    plugTitle: "APIs plug-and-play",
    plugDesc: "Integre facilmente suas assinaturas de API pagas e gratuitas. Sem scripts customizados, sem atrito.",
    silosTitle: "Quebre silos de dados",
    silosDesc: "Correlacione nomes de host, portas abertas, DNS passivo e prefixos BGP em uma única área de trabalho.",
    changeTitle: "Feito para velocidade",
    changeDesc: "Escanear indicadores, consultar bancos de dados históricos de DNSBL e obter resultados completos em menos de dois segundos.",

    // Key features
    keyFeaturesTitle: "Principais",
    keyFeaturesHighlight: "recursos",
    keyFeaturesSub: "Desenvolvido com foco em performance, modularidade e segurança passiva. O ThreatSumm4ry fornece tudo o que você precisa para análise de CTI e OSINT.",
    
    leftFeatureTitle: "Exploração de grafo interativa",
    leftFeatureSub: "Interface visual interativa baseada em nós para mapear, explorar e expandir conexões entre indicadores de ameaça.",
    
    subFeat1Title: "Parser dinâmico",
    subFeat1Desc: "Insira IPs, domínios ou hashes de arquivos. A busca identifica o formato do alvo e seleciona os provedores adequados.",
    subFeat2Title: "Mapeamento de DNS passivo",
    subFeat2Desc: "Descubra subdomínios e mapeamentos históricos de DNS por meio de integrações ativas como DNSDumpster.",
    subFeat3Title: "Motor de pontuação ponderado",
    subFeat3Desc: "Pondere o peso de motores primários com o consenso geral para calcular um percentual de risco preciso.",
    subFeat4Title: "Diretrizes de mitigação",
    subFeat4Desc: "Obtenha playbooks imediatos de remediação, status CISA KEV e dados de registro para vulnerabilidades ativas.",
    subFeat5Title: "Relatórios exportáveis",
    subFeat5Desc: "Compile análises detalhadas de fornecedores, gráficos e logs DNSBL em relatórios profissionais em PDF ou JSON.",

    // Who is it for
    whoTitle: "Para quem é o",
    whoTitleHighlight: "projeto",
    whoSub: "O ThreatSumm4ry foi desenvolvido para equipes e analistas que precisam validar indicadores e avaliar riscos digitais.",
    
    who1Title: "Analistas de segurança e ameaças",
    who1Desc: "Investigue alertas de segurança, analise reputação de alvos e realize a triagem de indicadores de infraestrutura.",
    who2Title: "Pesquisadores de OSINT",
    who2Desc: "Colete inteligência passiva de fontes abertas e construa mapas de correlação de infraestrutura suspeita.",
    who3Title: "Equipes de resposta a incidentes",
    who3Desc: "Rastreie indicadores de rede, verifique blocklists de spam e bloqueie entidades maliciosas ativas.",
    who4Title: "Segurança corporativa",
    who4Desc: "Monitore a reputação do perímetro organizacional e avalie o risco digital de parceiros comerciais.",
    who5Title: "Engenheiros de SOC",
    who5Desc: "Automatize a verificação de consenso e gere relatórios PDF detalhados para anexar a chamados de incidentes.",
    who6Title: "Qualquer pessoa validando ameaças",
    who6Desc: "Navegue com segurança, valide e-mails suspeitos e examine o estado de saúde de servidores de forma segura."
  }
};

export default function Features() {
  const { isCollapsed } = useSidebar();
  const { language } = useLanguage();
  const t = content[language as "en" | "pt"] || content.en;

  return (
    <div className={`min-h-screen bg-background text-slate-200 flex flex-col transition-all duration-300 ${isCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
      <Header />

      <style>{`
        @keyframes flow-dash {
          to {
            stroke-dashoffset: -20;
          }
        }
        .flow-line {
          animation: flow-dash 1.5s linear infinite;
        }
      `}</style>

      <div className="flex-1 max-w-7xl mx-auto px-4 md:px-8 py-12 md:py-20 space-y-24 md:space-y-36">
        
        {/* Section 1: Why ThreatSumm4ry */}
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-16 items-start">
          <div className="lg:col-span-5 space-y-6">
            <h2 className="text-3xl md:text-4.5xl font-bold tracking-tight text-white leading-tight">
              {t.whyTitle} <span className="text-blue-500">{t.whyTitleHighlight}</span>?
            </h2>
            <div className="space-y-4 text-sm md:text-base text-zinc-400 leading-relaxed font-sans">
              <p>{t.whyPara1}</p>
              <p>{t.whyPara2}</p>
            </div>
          </div>

          <div className="lg:col-span-7 grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Foundation Card */}
            <div className="bg-white/[0.01] hover:bg-white/[0.02] border border-white/[0.04] rounded-2xl p-5 transition-all duration-200 space-y-3">
              <div className="h-9 w-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-500 shrink-0">
                <Layers className="h-4.5 w-4.5" />
              </div>
              <h3 className="text-sm font-bold text-white tracking-wide">{t.foundationTitle}</h3>
              <p className="text-[11px] text-zinc-400 leading-relaxed font-sans">{t.foundationDesc}</p>
            </div>

            {/* Plug Card */}
            <div className="bg-white/[0.01] hover:bg-white/[0.02] border border-white/[0.04] rounded-2xl p-5 transition-all duration-200 space-y-3">
              <div className="h-9 w-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-500 shrink-0">
                <Cable className="h-4.5 w-4.5" />
              </div>
              <h3 className="text-sm font-bold text-white tracking-wide">{t.plugTitle}</h3>
              <p className="text-[11px] text-zinc-400 leading-relaxed font-sans">{t.plugDesc}</p>
            </div>

            {/* Silos Card */}
            <div className="bg-white/[0.01] hover:bg-white/[0.02] border border-white/[0.04] rounded-2xl p-5 transition-all duration-200 space-y-3">
              <div className="h-9 w-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-500 shrink-0">
                <Network className="h-4.5 w-4.5" />
              </div>
              <h3 className="text-sm font-bold text-white tracking-wide">{t.silosTitle}</h3>
              <p className="text-[11px] text-zinc-400 leading-relaxed font-sans">{t.silosDesc}</p>
            </div>

            {/* Speed Card */}
            <div className="bg-white/[0.01] hover:bg-white/[0.02] border border-white/[0.04] rounded-2xl p-5 transition-all duration-200 space-y-3">
              <div className="h-9 w-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-500 shrink-0">
                <RefreshCw className="h-4.5 w-4.5" />
              </div>
              <h3 className="text-sm font-bold text-white tracking-wide">{t.changeTitle}</h3>
              <p className="text-[11px] text-zinc-400 leading-relaxed font-sans">{t.changeDesc}</p>
            </div>
          </div>
        </section>

        {/* Section 2: Key Features */}
        <section className="space-y-12">
          <div className="text-center space-y-3 max-w-2xl mx-auto">
            <h2 className="text-3xl md:text-4.5xl font-bold tracking-tight text-white">
              {t.keyFeaturesTitle} <span className="text-blue-500">{t.keyFeaturesHighlight}</span>
            </h2>
            <p className="text-xs md:text-sm text-zinc-400 leading-relaxed font-sans">
              {t.keyFeaturesSub}
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-center">
            
            {/* Left: Interactive graph exploration mockup */}
            <div className="lg:col-span-7 space-y-4">
              <div className="flex items-center gap-2 mb-1">
                <Eye className="h-4.5 w-4.5 text-blue-500" />
                <h3 className="text-sm font-bold text-white tracking-wide">{t.leftFeatureTitle}</h3>
              </div>
              <p className="text-[11px] text-zinc-400 leading-relaxed font-sans max-w-xl">
                {t.leftFeatureSub}
              </p>

              {/* Glowing SVG Graph UI Mockup */}
              <div className="border border-white/[0.04] bg-[#0f0f11]/80 rounded-2xl p-4.5 relative overflow-hidden shadow-2xl min-h-[300px] h-[340px] flex items-center justify-center">
                {/* Mock header */}
                <div className="absolute top-3 left-4 right-4 flex items-center justify-between border-b border-white/[0.04] pb-2 text-[9px] text-zinc-500 font-mono">
                  <div className="flex items-center gap-1.5">
                    <span className="h-1.5 w-1.5 rounded-full bg-blue-500" />
                    <span>CTI_GRAPH_EXPLORER</span>
                  </div>
                  <span>14.103.115.208 // Target_Scan</span>
                </div>

                <svg viewBox="0 0 420 220" className="w-full h-full pt-6 select-none">
                  {/* Glowing Lines with flowing animations */}
                  <line x1="210" y1="110" x2="110" y2="50" stroke="#f43f5e" strokeWidth="1.2" strokeDasharray="4,4" className="flow-line" />
                  <line x1="210" y1="110" x2="310" y2="50" stroke="#ef4444" strokeWidth="1.2" strokeDasharray="4,4" className="flow-line" />
                  <line x1="210" y1="110" x2="110" y2="170" stroke="#10b981" strokeWidth="1.2" strokeDasharray="4,4" className="flow-line" />
                  <line x1="210" y1="110" x2="310" y2="170" stroke="#eab308" strokeWidth="1.2" strokeDasharray="4,4" className="flow-line" />
                  
                  {/* Connecting indicator targets */}
                  <line x1="110" y1="50" x2="60" y2="50" stroke="#f43f5e" strokeWidth="1" strokeDasharray="2,2" />
                  <line x1="310" y1="50" x2="360" y2="50" stroke="#ef4444" strokeWidth="1" strokeDasharray="2,2" />
                  
                  {/* Central Node (Target IP) */}
                  <g transform="translate(210, 110)">
                    <circle r="28" fill="#0f0f11" stroke="#f43f5e" strokeWidth="2.5" className="animate-pulse" />
                    <text y="3" textAnchor="middle" fill="#ffffff" className="text-[7.5px] font-mono font-bold tracking-tight">14.103.115.208</text>
                  </g>
                  
                  {/* Branch Node 1: VirusTotal */}
                  <g transform="translate(110, 50)">
                    <circle r="18" fill="#121214" stroke="#f43f5e" strokeWidth="1.5" />
                    <text y="2.5" textAnchor="middle" fill="#ef4444" className="text-[6.5px] font-bold">VirusTotal</text>
                  </g>

                  {/* Branch Node 2: AbuseIPDB */}
                  <g transform="translate(310, 50)">
                    <circle r="18" fill="#121214" stroke="#ef4444" strokeWidth="1.5" />
                    <text y="2.5" textAnchor="middle" fill="#ef4444" className="text-[6.5px] font-bold">AbuseIPDB</text>
                  </g>

                  {/* Branch Node 3: GeoIP */}
                  <g transform="translate(110, 170)">
                    <circle r="18" fill="#121214" stroke="#10b981" strokeWidth="1.5" />
                    <text y="2.5" textAnchor="middle" fill="#10b981" className="text-[6.5px] font-bold">GeoIP</text>
                  </g>

                  {/* Branch Node 4: Shodan */}
                  <g transform="translate(310, 170)">
                    <circle r="18" fill="#121214" stroke="#eab308" strokeWidth="1.5" />
                    <text y="2.5" textAnchor="middle" fill="#eab308" className="text-[6.5px] font-bold">Shodan</text>
                  </g>
                </svg>
              </div>
            </div>

            {/* Right: Flexible entity modeling list */}
            <div className="lg:col-span-5 space-y-6">
              <div className="flex items-center gap-2 mb-1">
                <Settings className="h-4.5 w-4.5 text-blue-500" />
                <h3 className="text-sm font-bold text-white tracking-wide">{t.rightFeatureTitle}</h3>
              </div>
              
              <div className="space-y-4">
                {/* Feat 1 */}
                <div className="space-y-1">
                  <h4 className="text-xs font-bold text-white tracking-wide">{t.subFeat1Title}</h4>
                  <p className="text-[10px] text-zinc-400 leading-normal font-sans">{t.subFeat1Desc}</p>
                </div>
                {/* Feat 2 */}
                <div className="space-y-1">
                  <h4 className="text-xs font-bold text-white tracking-wide">{t.subFeat2Title}</h4>
                  <p className="text-[10px] text-zinc-400 leading-normal font-sans">{t.subFeat2Desc}</p>
                </div>
                {/* Feat 3 */}
                <div className="space-y-1">
                  <h4 className="text-xs font-bold text-white tracking-wide">{t.subFeat3Title}</h4>
                  <p className="text-[10px] text-zinc-400 leading-normal font-sans">{t.subFeat3Desc}</p>
                </div>
                {/* Feat 4 */}
                <div className="space-y-1">
                  <h4 className="text-xs font-bold text-white tracking-wide">{t.subFeat4Title}</h4>
                  <p className="text-[10px] text-zinc-400 leading-normal font-sans">{t.subFeat4Desc}</p>
                </div>
                {/* Feat 5 */}
                <div className="space-y-1">
                  <h4 className="text-xs font-bold text-white tracking-wide">{t.subFeat5Title}</h4>
                  <p className="text-[10px] text-zinc-400 leading-normal font-sans">{t.subFeat5Desc}</p>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Section 3: Who is it for? */}
        <section className="space-y-12">
          <div className="text-center space-y-3 max-w-2xl mx-auto">
            <h2 className="text-3xl md:text-4.5xl font-bold tracking-tight text-white">
              {t.whoTitle} <span className="text-blue-500">{t.whoTitleHighlight}</span>?
            </h2>
            <p className="text-xs md:text-sm text-zinc-400 leading-relaxed font-sans">
              {t.whoSub}
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            
            {/* Role 1: Threat Analysts */}
            <div className="bg-white/[0.01] hover:bg-white/[0.02] border border-white/[0.04] rounded-2xl p-5 transition-all duration-200 flex gap-4">
              <div className="h-9 w-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-500 shrink-0">
                <Shield className="h-4.5 w-4.5" />
              </div>
              <div className="space-y-1">
                <h3 className="text-xs font-bold text-white tracking-wide">{t.who1Title}</h3>
                <p className="text-[10.5px] text-zinc-400 leading-relaxed font-sans">{t.who1Desc}</p>
              </div>
            </div>

            {/* Role 2: OSINT Researchers */}
            <div className="bg-white/[0.01] hover:bg-white/[0.02] border border-white/[0.04] rounded-2xl p-5 transition-all duration-200 flex gap-4">
              <div className="h-9 w-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-500 shrink-0">
                <Search className="h-4.5 w-4.5" />
              </div>
              <div className="space-y-1">
                <h3 className="text-xs font-bold text-white tracking-wide">{t.who2Title}</h3>
                <p className="text-[10.5px] text-zinc-400 leading-relaxed font-sans">{t.who2Desc}</p>
              </div>
            </div>

            {/* Role 3: Incident Responders */}
            <div className="bg-white/[0.01] hover:bg-white/[0.02] border border-white/[0.04] rounded-2xl p-5 transition-all duration-200 flex gap-4">
              <div className="h-9 w-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-500 shrink-0">
                <Zap className="h-4.5 w-4.5" />
              </div>
              <div className="space-y-1">
                <h3 className="text-xs font-bold text-white tracking-wide">{t.who3Title}</h3>
                <p className="text-[10.5px] text-zinc-400 leading-relaxed font-sans">{t.who3Desc}</p>
              </div>
            </div>

            {/* Role 4: Corporate security teams */}
            <div className="bg-white/[0.01] hover:bg-white/[0.02] border border-white/[0.04] rounded-2xl p-5 transition-all duration-200 flex gap-4">
              <div className="h-9 w-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-500 shrink-0">
                <Building className="h-4.5 w-4.5" />
              </div>
              <div className="space-y-1">
                <h3 className="text-xs font-bold text-white tracking-wide">{t.who4Title}</h3>
                <p className="text-[10.5px] text-zinc-400 leading-relaxed font-sans">{t.who4Desc}</p>
              </div>
            </div>

            {/* Role 5: SOC Engineers */}
            <div className="bg-white/[0.01] hover:bg-white/[0.02] border border-white/[0.04] rounded-2xl p-5 transition-all duration-200 flex gap-4">
              <div className="h-9 w-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-500 shrink-0">
                <Cpu className="h-4.5 w-4.5" />
              </div>
              <div className="space-y-1">
                <h3 className="text-xs font-bold text-white tracking-wide">{t.who5Title}</h3>
                <p className="text-[10.5px] text-zinc-400 leading-relaxed font-sans">{t.who5Desc}</p>
              </div>
            </div>

            {/* Role 6: Anyone mapping relationships */}
            <div className="bg-white/[0.01] hover:bg-white/[0.02] border border-white/[0.04] rounded-2xl p-5 transition-all duration-200 flex gap-4">
              <div className="h-9 w-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-500 shrink-0">
                <UserCheck className="h-4.5 w-4.5" />
              </div>
              <div className="space-y-1">
                <h3 className="text-xs font-bold text-white tracking-wide">{t.who6Title}</h3>
                <p className="text-[10.5px] text-zinc-400 leading-relaxed font-sans">{t.who6Desc}</p>
              </div>
            </div>

          </div>
        </section>

        {/* Quick Access Calls-to-Action */}
        <section className="text-center space-y-6 pt-6 border-t border-white/[0.04]">
          <h2 className="text-xl md:text-2xl font-bold tracking-tight text-white">
            {language === "pt" ? "Pronto para começar a investigar?" : "Ready to start investigating?"}
          </h2>
          <p className="text-xs text-zinc-400 max-w-md mx-auto font-sans">
            {language === "pt" 
              ? "Acesse nossas ferramentas analíticas e comece a correlacionar indicadores de ameaça." 
              : "Launch our passive analytical tools and start correlating threat indicators immediately."}
          </p>
          <div className="flex flex-wrap justify-center gap-3">
            <Link to="/">
              <Button className="h-9.5 rounded-xl font-bold text-xs bg-blue-500 hover:bg-blue-600 text-white shadow-md shadow-blue-500/15">
                {language === "pt" ? "Análise CTI" : "CTI Main Console"}
              </Button>
            </Link>
            <Link to="/dnsbl">
              <Button variant="outline" className="h-9.5 rounded-xl font-bold text-xs border-white/10 hover:bg-white/5 text-slate-300">
                {language === "pt" ? "Verificador DNSBL" : "DNSBL Checker"}
              </Button>
            </Link>
            <Link to="/dns-visualizer">
              <Button variant="outline" className="h-9.5 rounded-xl font-bold text-xs border-white/10 hover:bg-white/5 text-slate-300">
                {language === "pt" ? "Visualizador DNS" : "DNS Visualizer"}
              </Button>
            </Link>
            <Link to="/phishing-analyzer">
              <Button variant="outline" className="h-9.5 rounded-xl font-bold text-xs border-white/10 hover:bg-white/5 text-slate-300">
                {language === "pt" ? "Analisador de Phishing" : "Phishing Analyzer"}
              </Button>
            </Link>
          </div>
        </section>

      </div>
      <Footer />
    </div>
  );
}
