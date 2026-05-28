import { useState, useCallback } from "react";
import {
  Globe, Search, RotateCw, AlertTriangle, Copy, ExternalLink,
  Server, Activity, AlertCircle,
} from "lucide-react";
import { ReactFlowProvider } from "@xyflow/react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { fetchDnsLookup, fetchWHOISData, DnsLookupResult } from "@/services/threatApi";
import { useToast } from "@/hooks/use-toast";
import { Footer } from "@/components/Footer";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";
import { Header } from "@/components/Header";
import { DnsFlowGraph } from "@/components/dns-flow/DnsFlowGraph";
import { NodeInspector } from "@/components/dns-flow/NodeInspector";
import { TYPE_COLORS } from "@/components/dns-flow/DnsNodes";

const PRESETS = ["google.com", "cloudflare.com", "github.com", "abuseipdb.com"];

type SelectedNode = { id: string; type: string; value: string; label: string; meta?: any } | null;

const DnsVisualizer = () => {
  const { isCollapsed } = useSidebar();
  const [query, setQuery] = useState("");
  const [dnsData, setDnsData] = useState<DnsLookupResult | null>(null);
  const [whoisData, setWhoisData] = useState<any>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [selectedNode, setSelectedNode] = useState<SelectedNode>(null);
  const [subdomainSearch, setSubdomainSearch] = useState("");

  const { toast } = useToast();
  const { t, language } = useLanguage();

  const fetchDnsAndWhois = async (targetDomain: string) => {
    const trimmed = targetDomain.trim();
    if (!trimmed) {
      toast({ title: t("error"), description: language === "pt" ? "Por favor, digite um domínio válido" : "Please enter a valid domain", variant: "destructive" });
      return;
    }
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    if (!domainRegex.test(trimmed)) {
      toast({ title: t("invalidInput"), description: language === "pt" ? "Formato de domínio inválido" : "Invalid domain format", variant: "destructive" });
      return;
    }

    setIsScanning(true);
    setDnsData(null);
    setWhoisData(null);
    setSelectedNode(null);

    try {
      const [dnsResult, whoisResult] = await Promise.all([
        fetchDnsLookup(trimmed),
        fetchWHOISData(trimmed).catch(() => null),
      ]);
      setDnsData(dnsResult);
      if (whoisResult?.WhoisRecord) setWhoisData(whoisResult.WhoisRecord);
      setSelectedNode({ id: "domain-center", type: "domain", value: dnsResult.domain, label: dnsResult.domain });
      toast({
        title: language === "pt" ? "Varredura Concluída" : "Scan Completed",
        description: language === "pt" ? `Registros DNS para ${trimmed} carregados.` : `DNS records for ${trimmed} loaded.`,
      });
    } catch (err: any) {
      toast({ title: t("error"), description: err.message || "Failed to fetch DNS records", variant: "destructive" });
    } finally {
      setIsScanning(false);
    }
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchDnsAndWhois(query);
  };

  const handlePivotSearch = (ip: string) => {
    localStorage.setItem("pivotSearchQuery", ip);
    toast({
      title: language === "pt" ? "Redirecionando..." : "Redirecting...",
      description: language === "pt" ? `Pesquisando ${ip} no painel principal...` : `Searching ${ip} on main dashboard...`,
    });
    window.location.href = "/";
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: language === "pt" ? "Copiado!" : "Copied!", description: `${label} copied.` });
  };

  const onNodeSelect = useCallback((node: SelectedNode) => setSelectedNode(node), []);

  const renderSearchForm = (isCompact: boolean) => {
    return (
      <div className={`w-full transition-all duration-700 ${isCompact ? "max-w-7xl mx-auto flex flex-col sm:flex-row items-stretch sm:items-center gap-3" : "max-w-xl mx-auto space-y-4"}`}>
        <form onSubmit={handleSearch} className="flex flex-1 items-center gap-2 min-w-0">
          <div className="relative flex-1 min-w-0">
            <Globe className={`absolute text-muted-foreground/60 transition-all duration-500 ${isCompact ? "left-3 top-2.5 h-4 w-4" : "left-4 top-3.5 h-5 w-5"}`} />
            <Input
              placeholder={language === "pt" ? "Domínio (Ex: google.com)" : "Domain (e.g. google.com)"}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className={`w-full bg-background/50 border-border/40 font-medium placeholder:text-muted-foreground/40 transition-all duration-500 ${
                isCompact ? "h-9 pl-9 text-xs rounded-xl" : "h-12 pl-11 text-sm rounded-2xl shadow-lg focus:shadow-xl focus:border-primary/40"
              }`}
            />
          </div>
          <Button
            type="submit"
            disabled={isScanning}
            className={`font-semibold gap-1.5 shrink-0 transition-all duration-500 ${
              isCompact ? "h-9 px-4 rounded-xl text-xs" : "h-12 px-6 rounded-2xl text-sm"
            }`}
          >
            {isScanning ? <RotateCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
            <span>{isScanning ? (language === "pt" ? "Escaneando..." : "Scanning...") : (language === "pt" ? "Escanear" : "Scan")}</span>
          </Button>
        </form>

        <div className={`flex items-center gap-1.5 shrink-0 transition-all duration-500 ${isCompact ? "text-[11px] text-muted-foreground/60" : "justify-center pt-2 text-xs"}`}>
          {!isCompact && <span className="text-[10px] uppercase font-bold tracking-widest text-muted-foreground/40 mr-1.5">Presets:</span>}
          {PRESETS.map((d) => (
            <button
              key={d}
              onClick={() => {
                setQuery(d);
                if (!isCompact) {
                  setTimeout(() => {
                    fetchDnsAndWhois(d);
                  }, 50);
                }
              }}
              className={`font-mono transition-all border border-transparent hover:border-primary/20 ${
                isCompact
                  ? "px-2 py-1 rounded-md bg-muted/40 hover:bg-primary/10 hover:text-primary text-[10px]"
                  : "px-3 py-1.5 rounded-xl bg-card/45 hover:bg-primary/10 hover:text-primary text-xs"
              }`}
            >
              {d}
            </button>
          ))}
        </div>
      </div>
    );
  };

  return (
    <div className={`min-h-screen bg-background flex flex-col transition-all duration-300 ${isCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
      <Header showBackButton />

      <div className="flex-1 flex flex-col min-h-0 relative">

        {/* ── Compact Search Bar (at top, active during/after scan) ────────────────── */}
        <div className={`border-b border-border/30 bg-card/30 backdrop-blur-md px-4 md:px-6 py-3 transition-all duration-500 ease-in-out overflow-hidden ${
          (dnsData || isScanning) ? "opacity-100 max-h-20" : "opacity-0 max-h-0 pointer-events-none border-b-0 py-0"
        }`}>
          {renderSearchForm(true)}
        </div>

        {/* ── Centered Initial Search State ──────────────────────────── */}
        {!dnsData && !isScanning && (
          <div className="flex-1 flex flex-col items-center justify-center p-6 md:p-12 animate-fade-in">
            <div className="max-w-2xl w-full text-center space-y-8">
              <div className="space-y-4">
                <div className="mx-auto w-16 h-16 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center shadow-inner shadow-primary/5">
                  <Globe className="h-8 w-8 text-primary animate-pulse" />
                </div>
                <h2 className="text-3xl font-extrabold tracking-tight bg-gradient-to-r from-foreground via-foreground/90 to-foreground/50 bg-clip-text text-transparent">
                  {language === "pt" ? "Visualizador de DNS & WHOIS" : "DNS & WHOIS Graph Visualizer"}
                </h2>
                <p className="text-sm text-muted-foreground/75 max-w-lg mx-auto leading-relaxed">
                  {language === "pt"
                    ? "Explore graficamente conexões de DNS, dados WHOIS e registros DNSDumpster para mapear relacionamentos de infraestrutura."
                    : "Graphically map DNS records, WHOIS registration history, and DNSDumpster datasets to analyze infrastructure relationships."}
                </p>
              </div>

              {renderSearchForm(false)}
            </div>
          </div>
        )}

        {/* ── Scanning Status ──────────────────────────── */}
        {isScanning && !dnsData && (
          <div className="flex-1 flex items-center justify-center">
            <div className="flex flex-col items-center gap-4">
              <div className="relative h-14 w-14">
                <div className="animate-spin rounded-full h-14 w-14 border-t-2 border-b-2 border-primary" />
                <Globe className="absolute inset-0 m-auto h-5 w-5 text-primary animate-pulse" />
              </div>
              <p className="text-sm font-semibold text-muted-foreground animate-pulse">
                {language === "pt" ? "Resolvendo registros DNS..." : "Resolving DNS records..."}
              </p>
            </div>
          </div>
        )}

        {/* ── Main Content: Graph + Inspector ────────────────── */}
        {dnsData && (
          <div className="flex-1 flex min-h-0 animate-in fade-in duration-500">

            {/* React Flow Graph */}
            <div className="flex-1 min-w-0 relative">
              <ReactFlowProvider>
                <DnsFlowGraph
                  dnsData={dnsData}
                  onNodeSelect={onNodeSelect}
                  selectedNodeId={selectedNode?.id}
                />
              </ReactFlowProvider>
            </div>

            {/* Inspector Side Panel */}
            <div className={`border-l border-border/30 bg-card/40 backdrop-blur-md transition-all duration-300 flex flex-col overflow-hidden ${selectedNode ? "w-[320px] lg:w-[360px]" : "w-0"}`}>
              {selectedNode && (
                <Tabs defaultValue="inspector" className="flex-1 flex flex-col">
                  <div className="border-b border-border/30 px-3 pt-1">
                    <TabsList className="h-8 bg-transparent p-0 gap-1">
                      <TabsTrigger value="inspector" className="text-[11px] h-7 rounded-md px-2.5 data-[state=active]:bg-muted/50">Inspector</TabsTrigger>
                      <TabsTrigger value="records" className="text-[11px] h-7 rounded-md px-2.5 data-[state=active]:bg-muted/50">Records</TabsTrigger>
                      {dnsData.dnsDumpster && (
                        <TabsTrigger value="dumpster" className="text-[11px] h-7 rounded-md px-2.5 data-[state=active]:bg-muted/50">DNSDumpster</TabsTrigger>
                      )}
                      <TabsTrigger value="whois" className="text-[11px] h-7 rounded-md px-2.5 data-[state=active]:bg-muted/50">WHOIS</TabsTrigger>
                    </TabsList>
                  </div>

                  {/* Tab: Inspector */}
                  <TabsContent value="inspector" className="flex-1 mt-0 overflow-hidden">
                    <NodeInspector
                      node={selectedNode}
                      whoisData={whoisData}
                      onPivotSearch={handlePivotSearch}
                      onClose={() => setSelectedNode(null)}
                    />
                  </TabsContent>

                  {/* Tab: All Records */}
                  <TabsContent value="records" className="flex-1 mt-0 overflow-y-auto px-3 py-3 space-y-3">
                    {dnsData && Object.entries(dnsData.records).map(([type, list]) => {
                      if (!list || list.length === 0) return null;
                      const colors = TYPE_COLORS[type] || TYPE_COLORS["domain"];
                      return (
                        <div key={type} className="space-y-1">
                          <div className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground/60 flex items-center gap-1.5">
                            <span className={`h-1.5 w-1.5 rounded-full ${colors.dot}`} />
                            {type} Records ({list.length})
                          </div>
                          <div className="border border-border/30 rounded-xl divide-y divide-border/20 overflow-hidden bg-muted/5">
                            {list.map((val, idx) => (
                              <div key={idx} className="flex items-center justify-between p-2 px-3 hover:bg-muted/10 transition-colors">
                                <span className="text-[11px] font-mono break-all text-foreground/80 pr-2 leading-normal">{val}</span>
                                <div className="flex gap-0.5 shrink-0">
                                  <Button
                                    variant="ghost"
                                    size="icon"
                                    className="h-6 w-6 rounded-md text-muted-foreground hover:text-primary hover:bg-primary/10"
                                    onClick={() => setSelectedNode({ id: `${type}-${val.replace(/[^a-zA-Z0-9.-]/g, '_')}`, type, value: val, label: val })}
                                    title={language === "pt" ? "Localizar no gráfico" : "Locate in graph"}
                                  >
                                    <ExternalLink className="h-2.5 w-2.5" />
                                  </Button>
                                  {(type === "A" || type === "AAAA") && (
                                    <Button variant="ghost" size="icon" className="h-6 w-6 rounded-md" onClick={() => handlePivotSearch(val)} title="Pivot">
                                      <Activity className="h-2.5 w-2.5 text-primary" />
                                    </Button>
                                  )}
                                  <Button variant="ghost" size="icon" className="h-6 w-6 rounded-md" onClick={() => copyToClipboard(val, type)} title="Copy">
                                    <Copy className="h-2.5 w-2.5" />
                                  </Button>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </TabsContent>

                  {/* Tab: DNSDumpster */}
                  {dnsData.dnsDumpster && (
                    <TabsContent value="dumpster" className="flex-1 mt-0 overflow-y-auto px-3 py-3 space-y-4">
                      {/* Subdomain Filter Input */}
                      <div className="relative mb-2">
                        <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground/50" />
                        <Input
                          placeholder={language === "pt" ? "Filtrar subdomínios..." : "Filter subdomains..."}
                          value={subdomainSearch}
                          onChange={(e) => setSubdomainSearch(e.target.value)}
                          className="h-8 pl-8 text-xs bg-background/35 border-border/20 rounded-lg placeholder:text-muted-foreground/30 focus-visible:ring-1 focus-visible:ring-primary/30"
                        />
                      </div>

                      {(() => {
                        const subdomainsList = dnsData.dnsDumpster.a || [];
                        const filtered = subdomainsList.filter((hostItem: any) =>
                          hostItem.host.toLowerCase().includes(subdomainSearch.toLowerCase()) ||
                          hostItem.ips?.some((ipObj: any) =>
                            ipObj.ip.includes(subdomainSearch) ||
                            (ipObj.asn_name && ipObj.asn_name.toLowerCase().includes(subdomainSearch.toLowerCase())) ||
                            (ipObj.country && ipObj.country.toLowerCase().includes(subdomainSearch.toLowerCase()))
                          )
                        );

                        if (filtered.length === 0) {
                          return (
                            <div className="text-center py-6 text-xs text-muted-foreground/50">
                              {language === "pt" ? "Nenhum subdomínio correspondente" : "No matching subdomains"}
                            </div>
                          );
                        }

                        return (
                          <div className="space-y-1.5">
                            <div className="text-[10px] font-bold uppercase tracking-widest text-pink-400 flex items-center gap-1.5">
                              <span className="h-1.5 w-1.5 rounded-full bg-pink-400" />
                              Discovered Subdomains ({filtered.length})
                            </div>
                            <div className="space-y-2">
                              {filtered.map((hostItem: any, idx: number) => (
                                <div key={idx} className="border border-border/30 bg-muted/5 rounded-xl p-2.5 space-y-2 text-xs transition-all hover:bg-muted/10">
                                  <div className="flex justify-between items-center gap-2">
                                    <span className="font-semibold text-foreground break-all">{hostItem.host}</span>
                                    <div className="flex items-center gap-0.5 shrink-0">
                                      <Button
                                        variant="ghost"
                                        size="icon"
                                        className="h-5 w-5 rounded-md text-pink-400 hover:text-pink-300 hover:bg-pink-500/10"
                                        onClick={() => setSelectedNode({ id: `Subdomain-${hostItem.host}`, type: "Subdomain", value: hostItem.host, label: hostItem.host, meta: hostItem })}
                                        title={language === "pt" ? "Localizar no gráfico" : "Locate in graph"}
                                      >
                                        <ExternalLink className="h-2.5 w-2.5" />
                                      </Button>
                                      <Button variant="ghost" size="icon" className="h-5 w-5 rounded-md" onClick={() => copyToClipboard(hostItem.host, "Subdomain")}>
                                        <Copy className="h-2.5 w-2.5" />
                                      </Button>
                                    </div>
                                  </div>
                                  <div className="space-y-1.5 pl-1 border-l border-pink-500/10 ml-0.5">
                                    {hostItem.ips?.map((ipObj: any, ipIdx: number) => (
                                      <div key={ipIdx} className="pt-1 first:pt-0 space-y-0.5">
                                        <div className="flex justify-between items-center text-[11px] gap-2">
                                          <div className="flex items-center gap-1.5 min-w-0">
                                            <span className="font-mono text-primary/80 font-bold hover:underline cursor-pointer truncate" onClick={() => handlePivotSearch(ipObj.ip)}>{ipObj.ip}</span>
                                            <Button
                                              variant="ghost"
                                              size="icon"
                                              className="h-4 w-4 rounded-md text-muted-foreground/60 hover:text-primary hover:bg-primary/10 shrink-0"
                                              onClick={() => setSelectedNode({ id: `A-${ipObj.ip}`, type: "A", value: ipObj.ip, label: ipObj.ip, meta: { asn: ipObj.asn, asn_name: ipObj.asn_name, country: ipObj.country, banners: ipObj.banners, ptr: ipObj.ptr } })}
                                              title={language === "pt" ? "Localizar IP no gráfico" : "Locate IP in graph"}
                                            >
                                              <ExternalLink className="h-2 w-2" />
                                            </Button>
                                          </div>
                                          {ipObj.country && <Badge variant="outline" className="text-[8px] px-1 py-0 scale-90 border-muted-foreground/20 text-muted-foreground shrink-0">{ipObj.country}</Badge>}
                                        </div>
                                        {ipObj.asn_name && <p className="text-[9px] text-muted-foreground/50 truncate leading-normal">{ipObj.asn_name} (AS{ipObj.asn})</p>}
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        );
                      })()}

                      {dnsData.dnsDumpster.mx && dnsData.dnsDumpster.mx.length > 0 && (
                        <div className="space-y-1.5 pt-2">
                          <div className="text-[10px] font-bold uppercase tracking-widest text-blue-400 flex items-center gap-1.5">
                            <span className="h-1.5 w-1.5 rounded-full bg-blue-400" />
                            Mail Servers (MX) ({dnsData.dnsDumpster.mx.length})
                          </div>
                          <div className="border border-border/30 rounded-xl divide-y divide-border/20 overflow-hidden bg-muted/5">
                            {dnsData.dnsDumpster.mx.map((mxItem: any, idx: number) => (
                              <div key={idx} className="p-2 px-3 hover:bg-muted/10 transition-colors text-xs flex justify-between items-center">
                                <span className="font-mono text-foreground/80 break-all">{mxItem.host}</span>
                                <div className="flex gap-0.5 shrink-0">
                                  <Button
                                    variant="ghost"
                                    size="icon"
                                    className="h-5 w-5 rounded-md text-blue-400 hover:text-blue-300 hover:bg-blue-500/10"
                                    onClick={() => setSelectedNode({ id: `MX-${mxItem.host.replace(/[^a-zA-Z0-9.-]/g, '_')}`, type: "MX", value: mxItem.host, label: mxItem.host })}
                                    title={language === "pt" ? "Localizar no gráfico" : "Locate in graph"}
                                  >
                                    <ExternalLink className="h-2.5 w-2.5" />
                                  </Button>
                                  <Button variant="ghost" size="icon" className="h-5 w-5 rounded-md" onClick={() => copyToClipboard(mxItem.host, "MX host")}>
                                    <Copy className="h-2.5 w-2.5" />
                                  </Button>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </TabsContent>
                  )}

                  {/* Tab: WHOIS */}
                  <TabsContent value="whois" className="flex-1 mt-0 overflow-y-auto px-3 py-3">
                    {whoisData ? (
                      <div className="space-y-3 text-xs">
                        <div className="bg-muted/10 border border-border/30 rounded-xl p-3 space-y-1.5">
                          {[
                            ["Registrar", whoisData.registrarName],
                            ["Created", whoisData.createdDate ? new Date(whoisData.createdDate).toLocaleString() : null],
                            ["Updated", whoisData.updatedDate ? new Date(whoisData.updatedDate).toLocaleString() : null],
                            ["Expires", whoisData.expiresDate ? new Date(whoisData.expiresDate).toLocaleString() : null],
                            ["WHOIS Server", whoisData.whoisServer],
                          ].filter(([, v]) => v).map(([k, v]) => (
                            <div key={k as string} className="flex justify-between border-b border-border/10 pb-1">
                              <span className="text-muted-foreground font-semibold">{k}:</span>
                              <span className="font-mono text-foreground/80 text-right">{v}</span>
                            </div>
                          ))}
                        </div>
                        {whoisData.registrant && (
                          <div className="bg-muted/10 border border-border/30 rounded-xl p-3 space-y-1.5">
                            <div className="text-[9px] font-bold uppercase tracking-wider text-primary">Registrant</div>
                            <div className="grid grid-cols-2 gap-1.5 text-[11px]">
                              {[
                                ["Org", whoisData.registrant.organization],
                                ["Country", whoisData.registrant.country],
                                ["State", whoisData.registrant.state],
                                ["City", whoisData.registrant.city],
                              ].filter(([, v]) => v).map(([k, v]) => (
                                <div key={k as string}>
                                  <span className="text-muted-foreground/60">{k}: </span>
                                  <span className="font-semibold text-foreground/80">{v}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="flex flex-col items-center justify-center py-8 text-muted-foreground/50 gap-1.5">
                        <AlertCircle className="h-5 w-5" />
                        <p className="text-[11px] font-semibold">No WHOIS data available</p>
                      </div>
                    )}
                  </TabsContent>
                </Tabs>
              )}
            </div>
          </div>
        )}

      </div>
      <Footer />
    </div>
  );
};

export default DnsVisualizer;
