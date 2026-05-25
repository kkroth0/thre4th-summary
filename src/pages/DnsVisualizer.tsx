import { useState, useMemo, useEffect } from "react";
import { 
  Globe, Search, RotateCw, Database, Mail, FileText, Link2, 
  Shield, Info, ExternalLink, Copy, Server, AlertTriangle, AlertCircle, Check
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { fetchDnsLookup, fetchWHOISData, DnsLookupResult } from "@/services/threatApi";
import { useToast } from "@/hooks/use-toast";
import { Footer } from "@/components/Footer";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";
import { Header } from "@/components/Header";

interface GraphNode {
  id: string;
  label: string;
  type: 'domain' | 'A' | 'AAAA' | 'MX' | 'TXT' | 'NS' | 'CNAME';
  value: string;
  x: number;
  y: number;
}

interface GraphLink {
  source: string;
  target: string;
  type: string;
}

const PRESETS = ["google.com", "cloudflare.com", "github.com", "abuseipdb.com"];

const DnsVisualizer = () => {
  const { isCollapsed } = useSidebar();
  const [query, setQuery] = useState("");
  const [dnsData, setDnsData] = useState<DnsLookupResult | null>(null);
  const [whoisData, setWhoisData] = useState<any>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [activeNode, setActiveNode] = useState<GraphNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null);

  const { toast } = useToast();
  const { t, language } = useLanguage();

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!query) {
      toast({
        title: t('error'),
        description: language === "pt" ? "Por favor, digite um domínio válido" : "Please enter a valid domain",
        variant: "destructive",
      });
      return;
    }

    // Domain validation
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    if (!domainRegex.test(query.trim())) {
      toast({
        title: t('invalidInput'),
        description: language === "pt" ? "Formato de domínio inválido" : "Invalid domain format",
        variant: "destructive",
      });
      return;
    }

    setIsScanning(true);
    setDnsData(null);
    setWhoisData(null);
    setActiveNode(null);

    try {
      const [dnsResult, whoisResult] = await Promise.all([
        fetchDnsLookup(query.trim()),
        fetchWHOISData(query.trim()).catch(() => null) // fail WHOIS silently if API key is not configured or errors out
      ]);

      setDnsData(dnsResult);
      if (whoisResult && whoisResult.WhoisRecord) {
        setWhoisData(whoisResult.WhoisRecord);
      }
      
      toast({
        title: language === "pt" ? "Varredura Concluída" : "Scan Completed",
        description: language === "pt" ? `Registros DNS para ${query.trim()} carregados.` : `DNS records for ${query.trim()} loaded.`,
      });
    } catch (err: any) {
      console.error(err);
      toast({
        title: t('error'),
        description: err.message || (language === "pt" ? "Erro ao buscar registros DNS" : "Failed to fetch DNS records"),
        variant: "destructive",
      });
    } finally {
      setIsScanning(false);
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: language === "pt" ? "Copiado!" : "Copied!",
      description: `${label} ${language === "pt" ? "copiado para a área de transferência" : "copied to clipboard"}.`,
    });
  };

  const handlePivotSearch = (ip: string) => {
    localStorage.setItem("pivotSearchQuery", ip);
    toast({
      title: language === "pt" ? "Redirecionando..." : "Redirecting...",
      description: language === "pt" ? `Pesquisando ${ip} no painel principal...` : `Searching ${ip} on main dashboard...`,
    });
    window.location.href = "/";
  };

  // Construct Graph Nodes and Links
  const graph = useMemo(() => {
    if (!dnsData) return { nodes: [], links: [] };

    const nodes: GraphNode[] = [];
    const links: GraphLink[] = [];
    const cx = 300;
    const cy = 300;

    // 1. Center Domain Node
    nodes.push({
      id: "center",
      label: dnsData.domain,
      type: "domain",
      value: dnsData.domain,
      x: cx,
      y: cy
    });

    const records = dnsData.records;
    const recordTypes = Object.keys(records) as (keyof typeof records)[];

    // Filter categories that have actual records
    const activeCategories = recordTypes.filter(type => records[type] && records[type].length > 0);
    const K = activeCategories.length;
    const radius = 175;

    activeCategories.forEach((type, catIdx) => {
      const items = records[type];
      const M = items.length;

      // Calculate base angle for this category sector
      const baseAngle = (2 * Math.PI * catIdx) / K;
      // Spread nodes within their sector
      const angularSpread = 0.45; // Spread width in radians

      items.forEach((val, itemIdx) => {
        const nodeId = `${type}-${val}`;
        
        // Calculate specific angle for this node in the sector
        const angle = M === 1 
          ? baseAngle 
          : baseAngle + (itemIdx - (M - 1) / 2) * (angularSpread / (M - 1));

        const x = cx + radius * Math.cos(angle);
        const y = cy + radius * Math.sin(angle);

        nodes.push({
          id: nodeId,
          label: val,
          type: type as any,
          value: val,
          x,
          y
        });

        links.push({
          source: "center",
          target: nodeId,
          type: type
        });
      });
    });

    return { nodes, links };
  }, [dnsData]);

  // Set default active node once graph is resolved
  useEffect(() => {
    if (graph.nodes.length > 0) {
      setActiveNode(graph.nodes[0]);
    }
  }, [graph]);

  const getNodeColor = (type: string, isHovered = false, isActive = false) => {
    let base = "text-muted-foreground";
    switch (type) {
      case "domain": base = "text-primary fill-primary/10"; break;
      case "A": base = "text-red-500 fill-red-500/10"; break;
      case "AAAA": base = "text-orange-500 fill-orange-500/10"; break;
      case "MX": base = "text-blue-500 fill-blue-500/10"; break;
      case "NS": base = "text-purple-500 fill-purple-500/10"; break;
      case "TXT": base = "text-emerald-500 fill-emerald-500/10"; break;
      case "CNAME": base = "text-cyan-500 fill-cyan-500/10"; break;
    }
    return base;
  };

  const getStrokeColor = (type: string) => {
    switch (type) {
      case "domain": return "stroke-primary";
      case "A": return "stroke-red-500";
      case "AAAA": return "stroke-orange-500";
      case "MX": return "stroke-blue-500";
      case "NS": return "stroke-purple-500";
      case "TXT": return "stroke-emerald-500";
      case "CNAME": return "stroke-cyan-500";
      default: return "stroke-muted-foreground";
    }
  };

  const getNodeIcon = (type: string) => {
    switch (type) {
      case "domain": return <Globe className="h-5 w-5" />;
      case "A": return <Shield className="h-5 w-5" />;
      case "AAAA": return <Server className="h-5 w-5" />;
      case "MX": return <Mail className="h-5 w-5" />;
      case "NS": return <Database className="h-5 w-5" />;
      case "TXT": return <FileText className="h-5 w-5" />;
      case "CNAME": return <Link2 className="h-5 w-5" />;
      default: return <Info className="h-5 w-5" />;
    }
  };

  const displayNode = hoveredNode || activeNode;

  return (
    <div className={`min-h-screen bg-background flex flex-col transition-all duration-300 ${isCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
      <Header showBackButton />

      <div className={`flex-1 p-4 md:p-8 flex flex-col ${!dnsData ? "justify-center min-h-[75vh]" : ""} transition-all duration-500`}>
        <div className={`w-full transition-all duration-500 ${!dnsData ? "max-w-3xl mx-auto space-y-6 py-6" : "max-w-7xl mx-auto space-y-8"}`}>
          
          {/* Page Title */}
          <div className={`${!dnsData ? "text-center space-y-4 mb-2 animate-fade-in" : "flex flex-col md:flex-row md:items-center justify-between gap-4 border-b pb-4 animate-fade-in"}`}>
            <div className={`${!dnsData ? "space-y-3" : ""}`}>
              <h2 className={`font-bold tracking-tight text-foreground transition-all duration-500 ${!dnsData ? "text-3xl sm:text-4xl bg-gradient-to-r from-primary via-primary/80 to-primary/60 bg-clip-text text-transparent" : "text-2xl"}`}>
                {language === "pt" ? "Visualizador de DNS & WHOIS" : "DNS & WHOIS Graph Visualizer"}
              </h2>
              <p className={`text-sm text-muted-foreground mt-1 transition-all duration-500 ${!dnsData ? "max-w-2xl mx-auto" : "max-w-none"}`}>
                {language === "pt" 
                  ? "Explore graficamente conexões de DNS e dados de registro WHOIS para identificar relacionamentos de infraestrutura de ameaças"
                  : "Graphically map DNS records and WHOIS registration history to analyze infrastructure relationships and threat clusters"}
              </p>
            </div>
          </div>

          {/* Search Form */}
          <div className={`transition-all duration-500 w-full ${!dnsData ? "max-w-3xl mx-auto" : "max-w-none"}`}>
            <Card className="border-primary/10 bg-card/25 backdrop-blur-xl shadow-xl rounded-3xl p-1">
              <CardContent className="pt-6 space-y-4">
                <form onSubmit={handleSearch} className="flex flex-col sm:flex-row gap-3">
                  <div className="relative flex-1">
                    <Globe className="absolute left-4 top-3.5 h-5 w-5 text-muted-foreground/75" />
                    <Input
                      placeholder={language === "pt" ? "Digite um domínio (Ex: google.com)" : "Enter a domain (e.g. google.com)"}
                      value={query}
                      onChange={(e) => setQuery(e.target.value)}
                      className="flex-1 text-sm h-12 pl-11 bg-background/40 focus-visible:ring-primary/30 border-primary/20 rounded-2xl placeholder:text-muted-foreground/50 text-foreground font-medium"
                    />
                  </div>
                  <Button 
                    type="submit" 
                    disabled={isScanning} 
                    size="lg" 
                    className="h-12 px-8 font-semibold rounded-2xl bg-primary hover:bg-primary/95 text-primary-foreground flex items-center gap-2 shrink-0 transition-all shadow-md hover:shadow-lg"
                  >
                    {isScanning ? <RotateCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                    <span>{isScanning ? (language === "pt" ? "Escaneando..." : "Scanning...") : (language === "pt" ? "Escanear" : "Scan")}</span>
                  </Button>
                </form>

                {/* Suggestions */}
                <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground/80 justify-center sm:justify-start pt-2 border-t border-border/10">
                  <span className="font-semibold">{language === 'pt' ? "Sugestões:" : "Suggestions:"}</span>
                  <div className="flex flex-wrap gap-2">
                    {PRESETS.map(domain => (
                      <button
                        key={domain}
                        type="button"
                        onClick={() => setQuery(domain)}
                        className="px-2.5 py-1 rounded bg-muted/60 hover:bg-primary/15 hover:text-primary transition-all border border-primary/5 hover:border-primary/20 font-mono shadow-sm"
                      >
                        {domain}
                      </button>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Loader */}
          {isScanning && !dnsData && (
            <div className="flex flex-col items-center justify-center py-20 animate-fade-in">
              <div className="relative flex items-center justify-center h-16 w-16 mb-4">
                <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary"></div>
                <Globe className="absolute h-5 w-5 text-primary animate-pulse" />
              </div>
              <p className="text-sm font-semibold text-muted-foreground animate-pulse">
                {language === "pt" ? "Resolvendo registros DNS e WHOIS..." : "Resolving DNS records and WHOIS history..."}
              </p>
            </div>
          )}

          {/* Main Visualizer Area */}
          {dnsData && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 animate-fade-in">
              
              {/* Left Side: SVG Network Graph */}
              <Card className="lg:col-span-7 border-primary/10 bg-card/45 backdrop-blur-md shadow-sm overflow-hidden flex flex-col min-h-[550px]">
                <CardHeader className="pb-2 border-b border-border/40">
                  <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                    <Globe className="h-4 w-4 text-primary" />
                    {language === "pt" ? "Visualização de Relacionamentos" : "Infrastructure Relationship Graph"}
                  </CardTitle>
                </CardHeader>
                <CardContent className="flex-1 flex items-center justify-center p-4 min-h-[480px] relative select-none">
                  
                  {/* SVG Canvas */}
                  <svg className="w-full h-full max-w-[600px] max-h-[600px]" viewBox="0 0 600 600">
                    <defs>
                      <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                        <feGaussianBlur stdDeviation="6" result="blur" />
                        <feComposite in="SourceGraphic" in2="blur" operator="over" />
                      </filter>
                      <filter id="glow-active" x="-20%" y="-20%" width="140%" height="140%">
                        <feGaussianBlur stdDeviation="10" result="blur" />
                        <feComposite in="SourceGraphic" in2="blur" operator="over" />
                      </filter>
                    </defs>

                    {/* Links / Connecting Lines */}
                    {graph.links.map((link, idx) => {
                      const sourceNode = graph.nodes.find(n => n.id === link.source);
                      const targetNode = graph.nodes.find(n => n.id === link.target);
                      if (!sourceNode || !targetNode) return null;

                      const isLinkActive = displayNode && (displayNode.id === targetNode.id || displayNode.id === "center");
                      const isHovered = hoveredNode && (hoveredNode.id === targetNode.id || hoveredNode.id === "center");

                      return (
                        <line
                          key={idx}
                          x1={sourceNode.x}
                          y1={sourceNode.y}
                          x2={targetNode.x}
                          y2={targetNode.y}
                          className={`stroke-[1.5] transition-all duration-300 ${
                            isLinkActive 
                              ? `${getStrokeColor(link.type)} stroke-[2.5] opacity-80 filter drop-shadow-[0_0_4px_rgba(139,92,246,0.3)]` 
                              : "stroke-border/40 opacity-40"
                          }`}
                        />
                      );
                    })}

                    {/* Nodes / Circles */}
                    {graph.nodes.map((node) => {
                      const isActive = activeNode?.id === node.id;
                      const isHovered = hoveredNode?.id === node.id;
                      const isCenter = node.type === "domain";
                      const size = isCenter ? 26 : 14;

                      return (
                        <g 
                          key={node.id}
                          transform={`translate(${node.x}, ${node.y})`}
                          onClick={() => setActiveNode(node)}
                          onMouseEnter={() => setHoveredNode(node)}
                          onMouseLeave={() => setHoveredNode(null)}
                          className="cursor-pointer group"
                        >
                          {/* Inner glowing pulse for active/hovered state */}
                          {(isHovered || isActive) && (
                            <circle
                              r={size + 8}
                              className={`animate-ping opacity-15 fill-current ${getNodeColor(node.type)}`}
                              style={{ animationDuration: '3s' }}
                            />
                          )}

                          {/* Main Circle background */}
                          <circle
                            r={size}
                            className={`stroke-2 transition-all duration-300 fill-card ${getNodeColor(node.type)} ${
                              isActive || isHovered 
                                ? `${getStrokeColor(node.type)} stroke-3 scale-105 filter drop-shadow-[0_0_8px_rgba(139,92,246,0.2)]` 
                                : "stroke-border/70 hover:stroke-foreground/60"
                            }`}
                          />

                          {/* Mini Icon indicator in center */}
                          <g transform={`translate(-8, -8)`} className={`pointer-events-none scale-[0.8] ${getNodeColor(node.type)}`}>
                            {getNodeIcon(node.type)}
                          </g>

                          {/* Label (Only shown for center node by default or on hover) */}
                          {(isCenter || isHovered || isActive) && (
                            <g transform={`translate(0, ${size + 14})`}>
                              {/* Label Backdrop bubble */}
                              <rect
                                x={-Math.min(100, node.label.length * 3.5 + 8)}
                                y={-9}
                                width={Math.min(200, node.label.length * 7 + 16)}
                                height={16}
                                rx={8}
                                className="fill-popover/90 stroke-border/40 stroke-[0.5] backdrop-blur-md"
                              />
                              {/* Text */}
                              <text
                                textAnchor="middle"
                                className="text-[10px] font-bold font-mono fill-popover-foreground pointer-events-none"
                                y={2}
                              >
                                {node.label.length > 25 ? `${node.label.substring(0, 22)}...` : node.label}
                              </text>
                            </g>
                          )}
                        </g>
                      );
                    })}
                  </svg>

                  {/* Legend Overlay bottom left */}
                  <div className="absolute bottom-4 left-4 bg-background/85 backdrop-blur-md p-3.5 border rounded-2xl space-y-1.5 text-[10px] font-semibold text-muted-foreground/80 max-w-[200px] shadow-sm">
                    <div className="font-bold text-foreground text-[11px] mb-1 uppercase tracking-wider">Legend</div>
                    <div className="flex items-center gap-2"><div className="h-3 w-3 rounded-full bg-primary/10 border border-primary" />Domain</div>
                    <div className="flex items-center gap-2"><div className="h-3 w-3 rounded-full bg-red-500/10 border border-red-500" />A (IPv4)</div>
                    <div className="flex items-center gap-2"><div className="h-3 w-3 rounded-full bg-orange-500/10 border border-orange-500" />AAAA (IPv6)</div>
                    <div className="flex items-center gap-2"><div className="h-3 w-3 rounded-full bg-blue-500/10 border border-blue-500" />MX (Mail)</div>
                    <div className="flex items-center gap-2"><div className="h-3 w-3 rounded-full bg-purple-500/10 border border-purple-500" />NS (Nameserver)</div>
                    <div className="flex items-center gap-2"><div className="h-3 w-3 rounded-full bg-emerald-500/10 border border-emerald-500" />TXT (Text)</div>
                    <div className="flex items-center gap-2"><div className="h-3 w-3 rounded-full bg-cyan-500/10 border border-cyan-500" />CNAME (Alias)</div>
                  </div>
                </CardContent>
              </Card>

              {/* Right Side: Details Inspector Panel */}
              <div className="lg:col-span-5 space-y-6 flex flex-col">
                
                {/* Node Detail Card */}
                {displayNode && (
                  <Card className="border-primary/10 bg-card/45 backdrop-blur-md shadow-sm relative overflow-hidden flex flex-col">
                    <div className={`absolute top-0 left-0 right-0 h-1 ${
                      displayNode.type === "domain" ? "bg-primary" :
                      displayNode.type === "A" ? "bg-red-500" :
                      displayNode.type === "AAAA" ? "bg-orange-500" :
                      displayNode.type === "MX" ? "bg-blue-500" :
                      displayNode.type === "NS" ? "bg-purple-500" :
                      displayNode.type === "TXT" ? "bg-emerald-500" : "bg-cyan-500"
                    }`} />
                    <CardHeader className="pb-3">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={`text-[10px] font-bold uppercase ${
                          displayNode.type === "domain" ? "border-primary text-primary" :
                          displayNode.type === "A" ? "border-red-500 text-red-500" :
                          displayNode.type === "AAAA" ? "border-orange-500 text-orange-500" :
                          displayNode.type === "MX" ? "border-blue-500 text-blue-500" :
                          displayNode.type === "NS" ? "border-purple-500 text-purple-500" :
                          displayNode.type === "TXT" ? "border-emerald-500 text-emerald-500" : "border-cyan-500 text-cyan-500"
                        }`}>
                          {displayNode.type} RECORD
                        </Badge>
                      </div>
                      <CardTitle className="text-lg font-bold font-mono break-all leading-tight mt-1 flex items-center justify-between gap-4">
                        <span>{displayNode.value}</span>
                        <Button 
                          variant="ghost" 
                          size="icon" 
                          className="h-8 w-8 rounded-full hover:bg-muted/80 shrink-0"
                          onClick={() => copyToClipboard(displayNode.value, displayNode.type.toUpperCase() + " value")}
                          title={language === "pt" ? "Copiar valor" : "Copy value"}
                        >
                          <Copy className="h-3.5 w-3.5" />
                        </Button>
                      </CardTitle>
                    </CardHeader>
                    
                    <CardContent className="space-y-4 py-3 flex-1">
                      {/* Pivot options for IPs (A/AAAA records) */}
                      {(displayNode.type === "A" || displayNode.type === "AAAA") && (
                        <div className="bg-primary/5 border border-primary/10 rounded-2xl p-3.5 space-y-3">
                          <div className="text-xs font-bold text-foreground/90 flex items-center gap-1.5">
                            <Activity className="h-4 w-4 text-primary" />
                            {language === "pt" ? "Pivot de Inteligência contra Ameaças" : "Threat Intel Pivot"}
                          </div>
                          <p className="text-[11px] text-muted-foreground leading-normal">
                            {language === "pt"
                              ? "Faça uma varredura cruzada deste IP nos bancos de dados integrados (VirusTotal, AbuseIPDB, Shodan) para verificar reputação e incidentes."
                              : "Cross-query this IP address through integrated databases (VirusTotal, AbuseIPDB, Shodan) to check for historical reports and threat activity."}
                          </p>
                          <Button 
                            className="w-full h-9 rounded-xl text-xs font-semibold gap-1.5"
                            onClick={() => handlePivotSearch(displayNode.value)}
                          >
                            <ExternalLink className="h-3.5 w-3.5" />
                            {language === "pt" ? "Escanear IP de Ameaças" : "Analyze IP Reputation"}
                          </Button>
                        </div>
                      )}

                      {/* Domain details */}
                      {displayNode.type === "domain" && (
                        <div className="space-y-2 text-xs">
                          <div className="flex justify-between border-b pb-1.5">
                            <span className="text-muted-foreground font-semibold">Domain Name:</span>
                            <span className="font-bold text-foreground">{displayNode.value}</span>
                          </div>
                          {whoisData && (
                            <>
                              <div className="flex justify-between border-b pb-1.5">
                                <span className="text-muted-foreground font-semibold">Registrar:</span>
                                <span className="font-medium text-foreground">{whoisData.registrarName || "N/A"}</span>
                              </div>
                              <div className="flex justify-between border-b pb-1.5">
                                <span className="text-muted-foreground font-semibold">Registration Date:</span>
                                <span className="font-mono text-foreground">{whoisData.createdDate ? new Date(whoisData.createdDate).toLocaleDateString() : "N/A"}</span>
                              </div>
                              <div className="flex justify-between border-b pb-1.5">
                                <span className="text-muted-foreground font-semibold">Expiration Date:</span>
                                <span className="font-mono text-foreground">{whoisData.expiresDate ? new Date(whoisData.expiresDate).toLocaleDateString() : "N/A"}</span>
                              </div>
                              {whoisData.registrant && whoisData.registrant.country && (
                                <div className="flex justify-between border-b pb-1.5">
                                  <span className="text-muted-foreground font-semibold">Registrant Country:</span>
                                  <span className="font-medium text-foreground">{whoisData.registrant.country}</span>
                                </div>
                              )}
                            </>
                          )}
                        </div>
                      )}

                      {/* General Records (MX, NS, TXT) information */}
                      {["MX", "NS", "TXT", "CNAME"].includes(displayNode.type) && (
                        <div className="space-y-2 text-xs">
                          <div className="bg-muted/30 border p-3 rounded-2xl text-[11px] leading-relaxed text-muted-foreground break-words font-mono">
                            {displayNode.value}
                          </div>
                          <p className="text-[10px] text-muted-foreground/80 mt-2">
                            {displayNode.type === "MX" && (language === "pt" ? "O registro MX (Mail Exchange) especifica o servidor de e-mail responsável por aceitar mensagens de e-mail em nome do domínio." : "The MX (Mail Exchange) record specifies the mail server responsible for accepting email messages on behalf of the domain.")}
                            {displayNode.type === "NS" && (language === "pt" ? "O registro NS (Name Server) delega uma zona DNS para usar os servidores de nomes autoritativos listados." : "The NS (Name Server) record delegates a DNS zone to use the listed authoritative name servers.")}
                            {displayNode.type === "TXT" && (language === "pt" ? "Os registros TXT contêm informações textuais (geralmente SPF, DKIM, DMARC) usadas para validar a autenticidade do remetente." : "TXT records contain textual information (commonly SPF, DKIM, DMARC) used to validate domain ownership and sender authenticity.")}
                            {displayNode.type === "CNAME" && (language === "pt" ? "O registro CNAME (Canonical Name) mapeia um apelido ou nome alternativo para o nome de domínio canônico e verdadeiro." : "The CNAME (Canonical Name) record maps an alias or alternative name to the true canonical domain name.")}
                          </p>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                )}

                {/* List View Tabs Card */}
                <Card className="border-primary/10 bg-card/45 backdrop-blur-md shadow-sm flex-1 flex flex-col min-h-[300px]">
                  <Tabs defaultValue="all" className="w-full flex-1 flex flex-col">
                    <CardHeader className="pb-0 border-b border-border/40">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-2">
                        <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground">
                          {language === "pt" ? "Tabela de Registros DNS" : "DNS Records Table"}
                        </CardTitle>
                        <TabsList className="h-8 bg-muted/50 p-0.5 rounded-lg border border-border/40 self-start sm:self-auto">
                          <TabsTrigger value="all" className="text-xs h-7 rounded-md">All</TabsTrigger>
                          <TabsTrigger value="ips" className="text-xs h-7 rounded-md">IPs</TabsTrigger>
                          <TabsTrigger value="whois" className="text-xs h-7 rounded-md">WHOIS</TabsTrigger>
                        </TabsList>
                      </div>
                    </CardHeader>

                    <CardContent className="p-4 flex-1 overflow-y-auto max-h-[320px]">
                      
                      {/* View 1: All Records list */}
                      <TabsContent value="all" className="space-y-4 mt-0">
                        {dnsData && (
                          <div className="space-y-3">
                            {Object.entries(dnsData.records).map(([type, list]) => {
                              if (!list || list.length === 0) return null;
                              return (
                                <div key={type} className="space-y-1">
                                  <div className="text-[11px] font-bold text-muted-foreground uppercase tracking-widest flex items-center gap-1.5">
                                    <span className={`h-1.5 w-1.5 rounded-full ${
                                      type === "A" ? "bg-red-500" :
                                      type === "AAAA" ? "bg-orange-500" :
                                      type === "MX" ? "bg-blue-500" :
                                      type === "NS" ? "bg-purple-500" :
                                      type === "TXT" ? "bg-emerald-500" : "bg-cyan-500"
                                    }`} />
                                    {type} Records ({list.length})
                                  </div>
                                  <div className="border border-border/40 rounded-2xl divide-y overflow-hidden bg-background/20">
                                    {list.map((val, idx) => (
                                      <div key={idx} className="flex items-center justify-between p-2.5 px-3.5 hover:bg-muted/10 transition-colors">
                                        <span className="text-xs font-mono break-all text-foreground/80 leading-normal pr-4">{val}</span>
                                        <div className="flex gap-1 shrink-0">
                                          {(type === "A" || type === "AAAA") && (
                                            <Button 
                                              variant="ghost" 
                                              size="icon" 
                                              className="h-7 w-7 rounded-md hover:bg-muted/80"
                                              onClick={() => handlePivotSearch(val)}
                                              title={language === "pt" ? "Escanear ameaças" : "Scan threats"}
                                            >
                                              <Activity className="h-3 w-3 text-primary" />
                                            </Button>
                                          )}
                                          <Button 
                                            variant="ghost" 
                                            size="icon" 
                                            className="h-7 w-7 rounded-md hover:bg-muted/80"
                                            onClick={() => copyToClipboard(val, type + " value")}
                                            title="Copy"
                                          >
                                            <Copy className="h-3 w-3" />
                                          </Button>
                                        </div>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </TabsContent>

                      {/* View 2: Host IPs Only */}
                      <TabsContent value="ips" className="space-y-4 mt-0">
                        {dnsData && (
                          <div className="space-y-4">
                            {/* A Records */}
                            {dnsData.records.A.length > 0 && (
                              <div className="space-y-1.5">
                                <div className="text-[11px] font-bold text-red-500 uppercase tracking-widest flex items-center gap-1.5">
                                  <Server className="h-3.5 w-3.5" />
                                  IPv4 addresses (A records)
                                </div>
                                <div className="border border-border/40 rounded-2xl divide-y bg-background/20">
                                  {dnsData.records.A.map((ip, idx) => (
                                    <div key={idx} className="flex items-center justify-between p-2.5 px-3.5">
                                      <span className="text-xs font-mono text-foreground/80">{ip}</span>
                                      <Button 
                                        variant="outline" 
                                        size="sm" 
                                        className="h-7 text-[10px] font-bold rounded-lg border-primary/20 hover:bg-primary/10 gap-1"
                                        onClick={() => handlePivotSearch(ip)}
                                      >
                                        <ExternalLink className="h-3 w-3" /> Pivot Check
                                      </Button>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}

                            {/* AAAA Records */}
                            {dnsData.records.AAAA.length > 0 && (
                              <div className="space-y-1.5">
                                <div className="text-[11px] font-bold text-orange-500 uppercase tracking-widest flex items-center gap-1.5">
                                  <Server className="h-3.5 w-3.5" />
                                  IPv6 addresses (AAAA records)
                                </div>
                                <div className="border border-border/40 rounded-2xl divide-y bg-background/20">
                                  {dnsData.records.AAAA.map((ip, idx) => (
                                    <div key={idx} className="flex items-center justify-between p-2.5 px-3.5">
                                      <span className="text-xs font-mono text-foreground/80 break-all pr-4">{ip}</span>
                                      <Button 
                                        variant="outline" 
                                        size="sm" 
                                        className="h-7 text-[10px] font-bold rounded-lg border-primary/20 hover:bg-primary/10 gap-1 shrink-0"
                                        onClick={() => handlePivotSearch(ip)}
                                      >
                                        <ExternalLink className="h-3 w-3" /> Pivot Check
                                      </Button>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}

                            {dnsData.records.A.length === 0 && dnsData.records.AAAA.length === 0 && (
                              <div className="p-6 text-center text-xs text-muted-foreground flex flex-col items-center gap-1">
                                <AlertTriangle className="h-5 w-5 text-muted-foreground/60" />
                                <span>No IP records found for this domain</span>
                              </div>
                            )}
                          </div>
                        )}
                      </TabsContent>

                      {/* View 3: WHOIS history data */}
                      <TabsContent value="whois" className="space-y-4 mt-0">
                        {whoisData ? (
                          <div className="space-y-3 text-xs leading-normal">
                            <div className="bg-muted/10 border p-4 rounded-2xl space-y-2 border-border/30">
                              <div className="flex justify-between border-b pb-1.5">
                                <span className="text-muted-foreground font-semibold">Registrar:</span>
                                <span className="font-bold text-foreground">{whoisData.registrarName || "Unknown"}</span>
                              </div>
                              <div className="flex justify-between border-b pb-1.5">
                                <span className="text-muted-foreground font-semibold">Created Date:</span>
                                <span className="font-mono text-foreground">{whoisData.createdDate ? new Date(whoisData.createdDate).toLocaleString() : "Unknown"}</span>
                              </div>
                              <div className="flex justify-between border-b pb-1.5">
                                <span className="text-muted-foreground font-semibold">Updated Date:</span>
                                <span className="font-mono text-foreground">{whoisData.updatedDate ? new Date(whoisData.updatedDate).toLocaleString() : "Unknown"}</span>
                              </div>
                              <div className="flex justify-between border-b pb-1.5">
                                <span className="text-muted-foreground font-semibold">Expiry Date:</span>
                                <span className="font-mono text-foreground">{whoisData.expiresDate ? new Date(whoisData.expiresDate).toLocaleString() : "Unknown"}</span>
                              </div>
                              <div className="flex justify-between border-b pb-1.5">
                                <span className="text-muted-foreground font-semibold">Whois Server:</span>
                                <span className="font-mono text-foreground">{whoisData.whoisServer || "Unknown"}</span>
                              </div>
                              {whoisData.registrant && (
                                <div className="space-y-1 pt-2">
                                  <div className="font-bold text-[10px] uppercase tracking-wider text-primary">Registrant Information</div>
                                  <div className="grid grid-cols-2 gap-2 text-[11px] bg-background/30 p-2.5 rounded-xl border border-border/10">
                                    <div><span className="text-muted-foreground">Org:</span> <span className="font-semibold text-foreground/90">{whoisData.registrant.organization || "N/A"}</span></div>
                                    <div><span className="text-muted-foreground">Country:</span> <span className="font-semibold text-foreground/90">{whoisData.registrant.country || "N/A"}</span></div>
                                    <div><span className="text-muted-foreground">State:</span> <span className="font-semibold text-foreground/90">{whoisData.registrant.state || "N/A"}</span></div>
                                    <div><span className="text-muted-foreground">City:</span> <span className="font-semibold text-foreground/90">{whoisData.registrant.city || "N/A"}</span></div>
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        ) : (
                          <div className="p-8 text-center text-xs text-muted-foreground flex flex-col items-center gap-1.5">
                            <AlertCircle className="h-6 w-6 text-muted-foreground/50" />
                            <div>
                              <p className="font-semibold">No WHOIS data loaded</p>
                              <p className="text-[10px] text-muted-foreground/75 mt-0.5">
                                {language === "pt"
                                  ? "Certifique-se de configurar WHOIS_API_KEY no arquivo .env"
                                  : "Ensure WHOIS_API_KEY is configured in your .env file"}
                              </p>
                            </div>
                          </div>
                        )}
                      </TabsContent>
                    </CardContent>
                  </Tabs>
                </Card>
              </div>

            </div>
          )}

        </div>
      </div>
      <Footer />
    </div>
  );
};

export default DnsVisualizer;
