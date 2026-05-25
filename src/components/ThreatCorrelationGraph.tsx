import React, { useState, useMemo, useEffect } from "react";
import { 
  Globe, Shield, AlertTriangle, Database, Info, Copy, Server, Link2, ExternalLink
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useLanguage } from "@/contexts/LanguageContext";
import { toast } from "sonner";

interface VendorData {
  name: string;
  data: Record<string, any>;
  link?: string;
  error?: string;
}

interface ThreatCorrelationGraphProps {
  query: string;
  overallScore: number;
  threatLevel: string;
  totalVendors: number;
  detections: number;
  vendorData: VendorData[];
}

interface GraphNode {
  id: string;
  label: string;
  type: 'target' | 'vendor' | 'country' | 'isp' | 'asn' | 'port' | 'verdict' | 'misc';
  x: number;
  y: number;
  value: string;
  connectedVendors: string[];
}

interface GraphLink {
  source: string;
  target: string;
  type: string;
}

export const ThreatCorrelationGraph = ({
  query,
  overallScore,
  threatLevel,
  totalVendors,
  detections,
  vendorData
}: ThreatCorrelationGraphProps) => {
  const { language } = useLanguage();
  const [activeNode, setActiveNode] = useState<GraphNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null);

  // Helper to normalize values for correlation matching
  const normalizeIsp = (isp: string): string => {
    if (!isp) return "";
    return isp
      .toLowerCase()
      .replace(/[\s,\.\-]+/g, "")
      .replace(/(inc|corp|ltd|sas|co|gmbh|llc|limited|s\.a\.)/g, "")
      .trim();
  };

  const normalizeCountry = (country: string): string => {
    if (!country) return "";
    // If format is "France (FR)", extract "France"
    const match = country.match(/^([^\(]+)/);
    const name = match ? match[1].trim() : country.trim();
    // Use common 2-letter to full name mappings if needed, or simple lowercase comparison
    return name.toLowerCase();
  };

  const extractAsnNumber = (asn: any): string => {
    if (!asn) return "";
    const match = String(asn).match(/\d+/);
    return match ? match[0] : "";
  };

  // Compile the graph structure
  const graph = useMemo(() => {
    const nodes: GraphNode[] = [];
    const links: GraphLink[] = [];
    const cx = 300;
    const cy = 300;

    // 1. Center Target Node
    nodes.push({
      id: "target",
      label: query,
      type: "target",
      value: query,
      x: cx,
      y: cy,
      connectedVendors: vendorData.map(v => v.name)
    });

    // We will collect fact candidates and build relations to map duplicates
    const asnMap: Record<string, { rawLabel: string; vendors: string[] }> = {};
    const countryMap: Record<string, { rawLabel: string; vendors: string[] }> = {};
    const ispMap: Record<string, { rawLabel: string; vendors: string[] }> = {};
    const portMap: Record<string, { rawLabel: string; vendors: string[] }> = {};
    const verdictMap: Record<string, { rawLabel: string; vendors: string[] }> = {};

    // Filter out Geolocation vendor to keep core analysis engines in center ring (if we want, or keep all)
    const activeVendors = vendorData.filter(v => Object.keys(v.data).length > 0 || v.error);

    // 2. Position Vendor Nodes in a circle
    const numVendors = activeVendors.length;
    const r1 = 120; // Inner circle radius

    activeVendors.forEach((vendor, idx) => {
      const angle = (2 * Math.PI * idx) / numVendors;
      const vx = cx + r1 * Math.cos(angle);
      const vy = cy + r1 * Math.sin(angle);
      const vendorNodeId = `vendor-${vendor.name}`;

      nodes.push({
        id: vendorNodeId,
        label: vendor.name,
        type: "vendor",
        value: vendor.name,
        x: vx,
        y: vy,
        connectedVendors: [vendor.name]
      });

      links.push({
        source: "target",
        target: vendorNodeId,
        type: "vendor-link"
      });

      // Scan vendor fields for facts to correlate
      if (vendor.error) {
        verdictMap["error"] = verdictMap["error"] || { rawLabel: "Error", vendors: [] };
        verdictMap["error"].vendors.push(vendor.name);
        return;
      }

      const data = vendor.data;

      // Extract Status / Verdict
      const status = data["Status"] || data["Verdict"] || data["Risk"];
      if (status) {
        const lowerStatus = String(status).toLowerCase();
        let key = "clean";
        let label = "Clean / Safe";
        if (lowerStatus.includes("malicious") || lowerStatus.includes("unsafe") || lowerStatus.includes("phishing") || lowerStatus.includes("high") || lowerStatus.includes("malware") || lowerStatus.includes("sample")) {
          key = "malicious";
          label = "Malicious / Danger";
        } else if (lowerStatus.includes("suspicious") || lowerStatus.includes("risk") || lowerStatus.includes("medium")) {
          key = "suspicious";
          label = "Suspicious / Warning";
        }
        
        verdictMap[key] = verdictMap[key] || { rawLabel: label, vendors: [] };
        if (!verdictMap[key].vendors.includes(vendor.name)) {
          verdictMap[key].vendors.push(vendor.name);
        }
      }

      // Extract ASN
      const asnVal = data["ASN"] || data["AS"] || data["AS Owner"];
      const asnNum = extractAsnNumber(asnVal);
      if (asnNum) {
        asnMap[asnNum] = asnMap[asnNum] || { rawLabel: `ASN ${asnNum}`, vendors: [] };
        if (!asnMap[asnNum].vendors.includes(vendor.name)) {
          asnMap[asnNum].vendors.push(vendor.name);
        }
      }

      // Extract Country
      const countryVal = data["Country"] || data["Country Code"] || data["Location"] || data["Geo Location"];
      if (countryVal && countryVal !== "Unknown" && countryVal !== "N/A") {
        const normCountry = normalizeCountry(String(countryVal));
        if (normCountry) {
          countryMap[normCountry] = countryMap[normCountry] || { rawLabel: String(countryVal), vendors: [] };
          if (!countryMap[normCountry].vendors.includes(vendor.name)) {
            countryMap[normCountry].vendors.push(vendor.name);
          }
        }
      }

      // Extract ISP / Org
      const ispVal = data["ISP"] || data["Organization"] || data["AS Owner"] || data["Org"];
      if (ispVal && ispVal !== "Unknown" && ispVal !== "N/A") {
        const normIsp = normalizeIsp(String(ispVal));
        if (normIsp && normIsp.length > 2) {
          // Simple duplicate check (if one contains another, merge them)
          let matchKey = normIsp;
          const existingKey = Object.keys(ispMap).find(k => k.includes(normIsp) || normIsp.includes(k));
          if (existingKey) {
            matchKey = existingKey;
          }

          ispMap[matchKey] = ispMap[matchKey] || { rawLabel: String(ispVal), vendors: [] };
          if (!ispMap[matchKey].vendors.includes(vendor.name)) {
            ispMap[matchKey].vendors.push(vendor.name);
          }
        }
      }

      // Extract Ports
      const portsVal = data["Open Ports"] || data["Ports"];
      if (portsVal) {
        const ports = String(portsVal).split(/[\s,]+/);
        ports.forEach(p => {
          const cleanPort = p.trim().replace(/\/\w+$/, ""); // remove tcp/udp suffix
          if (cleanPort && /^\d+$/.test(cleanPort)) {
            portMap[cleanPort] = portMap[cleanPort] || { rawLabel: `Port ${cleanPort}`, vendors: [] };
            if (!portMap[cleanPort].vendors.includes(vendor.name)) {
              portMap[cleanPort].vendors.push(vendor.name);
            }
          }
        });
      }
    });

    // 3. Position Fact Nodes in their sectors (Outer circle radius R2 = 240)
    // We group sectors logically:
    // - Verdicts: top sector (around 1.5 * PI)
    // - Countries: right sector (around 0 * PI)
    // - ISPs & ASNs: left sector (around 1.0 * PI)
    // - Open Ports: bottom sector (around 0.5 * PI)

    // Position Verdict nodes
    const verdictKeys = Object.keys(verdictMap);
    verdictKeys.forEach((key, idx) => {
      const info = verdictMap[key];
      const sectorCenter = 1.5 * Math.PI; // Top
      const angle = sectorCenter + (idx - (verdictKeys.length - 1) / 2) * 0.15;
      const x = cx + 220 * Math.cos(angle);
      const y = cy + 220 * Math.sin(angle);
      const id = `verdict-${key}`;

      nodes.push({
        id,
        label: info.rawLabel,
        type: "verdict",
        value: info.rawLabel,
        x,
        y,
        connectedVendors: info.vendors
      });

      info.vendors.forEach(v => {
        links.push({
          source: `vendor-${v}`,
          target: id,
          type: "verdict-link"
        });
      });
    });

    // Position Country nodes
    const countryKeys = Object.keys(countryMap);
    countryKeys.forEach((key, idx) => {
      const info = countryMap[key];
      const sectorCenter = 0 * Math.PI; // Right
      const angle = sectorCenter + (idx - (countryKeys.length - 1) / 2) * 0.12;
      const x = cx + 240 * Math.cos(angle);
      const y = cy + 240 * Math.sin(angle);
      const id = `country-${key}`;

      nodes.push({
        id,
        label: info.rawLabel,
        type: "country",
        value: info.rawLabel,
        x,
        y,
        connectedVendors: info.vendors
      });

      info.vendors.forEach(v => {
        links.push({
          source: `vendor-${v}`,
          target: id,
          type: "country-link"
        });
      });
    });

    // Position ISP & ASN nodes
    const ispKeys = Object.keys(ispMap).slice(0, 5); // Cap to avoid clutter
    const asnKeys = Object.keys(asnMap).slice(0, 5);
    const leftKeys = [...ispKeys.map(k => ({ key: k, type: 'isp', info: ispMap[k] })), ...asnKeys.map(k => ({ key: k, type: 'asn', info: asnMap[k] }))];

    leftKeys.forEach((item, idx) => {
      const sectorCenter = 1.0 * Math.PI; // Left
      const angle = sectorCenter + (idx - (leftKeys.length - 1) / 2) * 0.10;
      const x = cx + 240 * Math.cos(angle);
      const y = cy + 240 * Math.sin(angle);
      const id = `${item.type}-${item.key}`;

      nodes.push({
        id,
        label: item.info.rawLabel,
        type: item.type as any,
        value: item.info.rawLabel,
        x,
        y,
        connectedVendors: item.info.vendors
      });

      item.info.vendors.forEach(v => {
        links.push({
          source: `vendor-${v}`,
          target: id,
          type: `${item.type}-link`
        });
      });
    });

    // Position Port nodes
    const portKeys = Object.keys(portMap).slice(0, 6);
    portKeys.forEach((key, idx) => {
      const info = portMap[key];
      const sectorCenter = 0.5 * Math.PI; // Bottom
      const angle = sectorCenter + (idx - (portKeys.length - 1) / 2) * 0.12;
      const x = cx + 240 * Math.cos(angle);
      const y = cy + 240 * Math.sin(angle);
      const id = `port-${key}`;

      nodes.push({
        id,
        label: info.rawLabel,
        type: "port",
        value: info.rawLabel,
        x,
        y,
        connectedVendors: info.vendors
      });

      info.vendors.forEach(v => {
        links.push({
          source: `vendor-${v}`,
          target: id,
          type: "port-link"
        });
      });
    });

    return { nodes, links };
  }, [query, vendorData]);

  // Set default active node
  useEffect(() => {
    if (graph.nodes.length > 0) {
      setActiveNode(graph.nodes[0]);
    }
  }, [graph]);

  const getNodeColor = (type: string) => {
    switch (type) {
      case "target": return "text-primary fill-primary/10 border-primary";
      case "vendor": return "text-muted-foreground fill-muted/10 border-muted-foreground";
      case "verdict": return "text-indigo-500 fill-indigo-500/10 border-indigo-500";
      case "country": return "text-rose-500 fill-rose-500/10 border-rose-500";
      case "isp": return "text-amber-500 fill-amber-500/10 border-amber-500";
      case "asn": return "text-purple-500 fill-purple-500/10 border-purple-500";
      case "port": return "text-emerald-500 fill-emerald-500/10 border-emerald-500";
      default: return "text-muted-foreground fill-muted/10 border-muted-foreground";
    }
  };

  const getStrokeColor = (type: string) => {
    switch (type) {
      case "target": return "stroke-primary";
      case "vendor": return "stroke-muted-foreground/60";
      case "verdict": return "stroke-indigo-500";
      case "country": return "stroke-rose-500";
      case "isp": return "stroke-amber-500";
      case "asn": return "stroke-purple-500";
      case "port": return "stroke-emerald-500";
      default: return "stroke-border/40";
    }
  };

  const getLinkColor = (link: GraphLink, activeNodeId?: string) => {
    if (!activeNodeId) return "stroke-border/20 opacity-30";
    
    // Highlight lines connected to active node
    const isConnected = link.source === activeNodeId || link.target === activeNodeId ||
      (activeNodeId === "target" && link.source === "target");

    if (isConnected) {
      if (link.type === "vendor-link") return "stroke-primary stroke-[2] opacity-80";
      if (link.type === "verdict-link") return "stroke-indigo-500 stroke-[2] opacity-80";
      if (link.type === "country-link") return "stroke-rose-500 stroke-[2] opacity-80";
      if (link.type === "isp-link") return "stroke-amber-500 stroke-[2] opacity-80";
      if (link.type === "asn-link") return "stroke-purple-500 stroke-[2] opacity-80";
      if (link.type === "port-link") return "stroke-emerald-500 stroke-[2] opacity-80";
    }
    return "stroke-border/10 opacity-15";
  };

  const getNodeIcon = (type: string, label: string) => {
    if (type === "verdict") {
      if (label.toLowerCase().includes("malicious") || label.toLowerCase().includes("danger")) {
        return <AlertTriangle className="h-5 w-5 text-red-500" />;
      }
      return <Shield className="h-5 w-5 text-green-500" />;
    }

    switch (type) {
      case "target": return <Globe className="h-5 w-5 text-primary" />;
      case "vendor": return <Database className="h-5 w-5 text-muted-foreground" />;
      case "country": return <Globe className="h-5 w-5 text-rose-500" />;
      case "isp": return <Server className="h-5 w-5 text-amber-500" />;
      case "asn": return <Link2 className="h-5 w-5 text-purple-500" />;
      case "port": return <Server className="h-5 w-5 text-emerald-500" />;
      default: return <Info className="h-5 w-5 text-muted-foreground" />;
    }
  };

  const displayNode = hoveredNode || activeNode;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success(language === "pt" ? "Copiado!" : "Copied!");
  };

  return (
    <Card className="border-primary/10 bg-card/45 backdrop-blur-xl shadow-lg rounded-3xl overflow-hidden animate-fade-in">
      <CardHeader className="pb-3 border-b border-border/40">
        <CardTitle className="text-lg font-bold flex items-center justify-between">
          <span>{language === "pt" ? "Grafo de Correlação de Ameaças" : "Threat Correlation Graph"}</span>
          <Badge variant={threatLevel === "malicious" ? "destructive" : "secondary"}>
            Score: {overallScore}/100 ({threatLevel.toUpperCase()})
          </Badge>
        </CardTitle>
        <CardDescription className="text-xs">
          {language === "pt"
            ? "Mapeamento interativo de bancos de dados de segurança. Linhas convergentes indicam correlação de dados entre diferentes fontes."
            : "Interactive mapping of security databases. Converging lines indicate data correlation across different vendors."}
        </CardDescription>
      </CardHeader>
      
      <CardContent className="p-0 grid grid-cols-1 lg:grid-cols-12 min-h-[500px]">
        {/* Left Grid: SVG Canvas Graph */}
        <div className="lg:col-span-8 flex items-center justify-center p-4 border-b lg:border-b-0 lg:border-r border-border/40 bg-muted/5 relative select-none">
          <svg className="w-full h-full max-w-[560px] max-h-[560px]" viewBox="0 0 600 600">
            {/* Links / Connecting Lines */}
            {graph.links.map((link, idx) => (
              <line
                key={idx}
                x1={graph.nodes.find(n => n.id === link.source)?.x}
                y1={graph.nodes.find(n => n.id === link.source)?.y}
                x2={graph.nodes.find(n => n.id === link.target)?.x}
                y2={graph.nodes.find(n => n.id === link.target)?.y}
                className={`stroke-[1.5] transition-all duration-300 ${getLinkColor(link, displayNode?.id)}`}
              />
            ))}

            {/* Nodes / Circles */}
            {graph.nodes.map((node) => {
              const isActive = activeNode?.id === node.id;
              const isHovered = hoveredNode?.id === node.id;
              const isTarget = node.type === "target";
              const size = isTarget ? 24 : 12;

              return (
                <g 
                  key={node.id}
                  transform={`translate(${node.x}, ${node.y})`}
                  onClick={() => setActiveNode(node)}
                  onMouseEnter={() => setHoveredNode(node)}
                  onMouseLeave={() => setHoveredNode(null)}
                  className="cursor-pointer"
                >
                  {/* Glowing Pulse */}
                  {(isHovered || isActive) && (
                    <circle
                      r={size + 6}
                      className={`animate-ping opacity-15 fill-current ${getNodeColor(node.type)}`}
                      style={{ animationDuration: '3.5s' }}
                    />
                  )}

                  {/* Main Node Circle */}
                  <circle
                    r={size}
                    className={`stroke-2 transition-all duration-300 fill-card ${getNodeColor(node.type)} ${
                      isActive || isHovered 
                        ? `${getStrokeColor(node.type)} stroke-3 scale-105 filter drop-shadow-[0_0_8px_rgba(139,92,246,0.3)]` 
                        : "stroke-border/70 hover:stroke-foreground/60"
                    }`}
                  />

                  {/* Inner Node Icon */}
                  <g transform="translate(-8, -8)" className="scale-[0.8] pointer-events-none">
                    {getNodeIcon(node.type, node.label)}
                  </g>

                  {/* Bubble labels on active/hover */}
                  {(isTarget || isHovered || isActive) && (
                    <g transform={`translate(0, ${size + 14})`}>
                      <rect
                        x={-Math.min(100, node.label.length * 3.5 + 8)}
                        y={-9}
                        width={Math.min(200, node.label.length * 7 + 16)}
                        height={16}
                        rx={8}
                        className="fill-popover/90 stroke-border/40 stroke-[0.5]"
                      />
                      <text
                        textAnchor="middle"
                        className="text-[9px] font-bold font-mono fill-popover-foreground pointer-events-none"
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

          {/* Simple Legend Overlay */}
          <div className="absolute bottom-4 left-4 bg-background/80 backdrop-blur-md p-3 border rounded-2xl space-y-1 text-[9px] font-semibold text-muted-foreground/80 max-w-[140px] shadow-sm">
            <div className="flex items-center gap-1.5"><div className="h-2 w-2 rounded-full bg-primary/10 border border-primary" />Target IoC</div>
            <div className="flex items-center gap-1.5"><div className="h-2 w-2 rounded-full bg-muted/10 border border-muted-foreground" />Security Vendor</div>
            <div className="flex items-center gap-1.5"><div className="h-2 w-2 rounded-full bg-indigo-500/10 border border-indigo-500" />Status Verdict</div>
            <div className="flex items-center gap-1.5"><div className="h-2 w-2 rounded-full bg-rose-500/10 border border-rose-500" />Country</div>
            <div className="flex items-center gap-1.5"><div className="h-2 w-2 rounded-full bg-amber-500/10 border border-amber-500" />ISP/Org</div>
            <div className="flex items-center gap-1.5"><div className="h-2 w-2 rounded-full bg-purple-500/10 border border-purple-500" />ASN</div>
            <div className="flex items-center gap-1.5"><div className="h-2 w-2 rounded-full bg-emerald-500/10 border border-emerald-500" />Open Port</div>
          </div>
        </div>

        {/* Right Grid: Inspector Sidebar */}
        <div className="lg:col-span-4 p-5 flex flex-col justify-between bg-muted/5 min-h-[300px]">
          {displayNode ? (
            <div className="space-y-5">
              <div className="space-y-1.5">
                <Badge variant="outline" className="text-[10px] font-bold uppercase tracking-wider">
                  {displayNode.type} Node Details
                </Badge>
                <h3 className="text-base font-bold font-mono break-all leading-tight text-foreground flex items-center justify-between gap-3">
                  <span>{displayNode.label}</span>
                  <Button 
                    variant="ghost" 
                    size="icon" 
                    className="h-8 w-8 rounded-full hover:bg-muted"
                    onClick={() => handleCopy(displayNode.value)}
                  >
                    <Copy className="h-3.5 w-3.5" />
                  </Button>
                </h3>
              </div>

              {/* Node Type Details */}
              {displayNode.type === "target" && (
                <div className="space-y-2 text-xs leading-relaxed text-muted-foreground">
                  <p>
                    {language === "pt"
                      ? `Este é o IoC alvo que você consultou (${query}). Ele está diretamente conectado a ${displayNode.connectedVendors.length} bancos de dados de segurança.`
                      : `This is the target IoC you scanned (${query}). It is directly linked to ${displayNode.connectedVendors.length} security databases.`}
                  </p>
                </div>
              )}

              {displayNode.type === "vendor" && (
                <div className="space-y-3 text-xs leading-relaxed">
                  <p className="text-muted-foreground">
                    {language === "pt"
                      ? `Banco de dados consultado para verificar a reputação do alvo. Clique em "Visualizar no Fabricante" para obter mais detalhes.`
                      : `Queried database source validating target reputation. Click "Visit Vendor Database" to see full reports.`}
                  </p>
                  {(() => {
                    const vendor = vendorData.find(v => v.name === displayNode.value);
                    if (!vendor) return null;
                    return (
                      <div className="space-y-2 border-t pt-2.5">
                        {vendor.error ? (
                          <div className="text-destructive font-semibold flex items-center gap-1.5">
                            <AlertTriangle className="h-4 w-4" /> API Error: {vendor.error}
                          </div>
                        ) : (
                          Object.entries(vendor.data)
                            .filter(([k]) => !["All Vendors", "Hostnames", "Reports", "Services Detail"].includes(k))
                            .slice(0, 5)
                            .map(([k, val]) => (
                              <div key={k} className="flex justify-between border-b border-border/30 pb-1">
                                <span className="text-muted-foreground font-semibold">{k}:</span>
                                <span className="font-medium text-foreground">{String(val)}</span>
                              </div>
                            ))
                        )}
                        {vendor.link && (
                          <a 
                            href={vendor.link} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 text-[11px] font-bold text-primary hover:underline pt-1.5"
                          >
                            <ExternalLink className="h-3 w-3" /> Visit Vendor Database
                          </a>
                        )}
                      </div>
                    );
                  })()}
                </div>
              )}

              {/* Shared Fact Nodes (IP/Country/ISP/Port) */}
              {["country", "isp", "asn", "port", "verdict"].includes(displayNode.type) && (
                <div className="space-y-4 text-xs leading-relaxed">
                  <div className="bg-primary/5 border border-primary/10 rounded-2xl p-4 space-y-2">
                    <div className="text-[11px] font-bold text-foreground flex items-center gap-1.5">
                      <Shield className="h-4 w-4 text-primary" />
                      {language === "pt" ? "Correlação de Dados Confirmada" : "Data Correlation Confirmed"}
                    </div>
                    <p className="text-[11px] text-muted-foreground">
                      {language === "pt"
                        ? `Esta informação foi confirmada e correlacionada através de múltiplos bancos de dados independentes.`
                        : `This property is correlated and verified across multiple independent security databases.`}
                    </p>
                  </div>

                  <div className="space-y-2">
                    <div className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest">
                      {language === "pt" ? "Confirmado por:" : "Verified by:"}
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {displayNode.connectedVendors.map(vendorName => (
                        <Badge key={vendorName} variant="secondary" className="font-semibold text-[10px] py-0.5 px-2 bg-background border border-border/50">
                          {vendorName}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="h-full flex items-center justify-center p-6 text-center text-xs text-muted-foreground flex-col gap-1.5">
              <Info className="h-6 w-6 text-muted-foreground/60" />
              <span>Hover or click a node to inspect correlations</span>
            </div>
          )}

          <div className="text-[10px] text-muted-foreground/60 text-center border-t border-border/40 pt-4 mt-6">
            ThreatSumm4ry Correlation Graph Engine
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
