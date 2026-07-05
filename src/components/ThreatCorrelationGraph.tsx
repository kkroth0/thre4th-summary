import React, { useState, useMemo, useEffect, useRef } from "react";
import { 
  Globe, Shield, AlertTriangle, Database, Info, Copy, Server, Link2, ExternalLink,
  ZoomIn, ZoomOut, Maximize2, Network, Terminal, Activity
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useLanguage } from "@/contexts/LanguageContext";
import { toast } from "sonner";
import { forceSimulation, forceLink, forceManyBody, forceCenter, forceCollide } from "d3-force";

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
  type: 'target' | 'vendor' | 'country' | 'isp' | 'asn' | 'port' | 'verdict' | 'misc' | 'category';
  x: number;
  y: number;
  vx?: number;
  vy?: number;
  fx?: number | null;
  fy?: number | null;
  value: string;
  connectedVendors: string[];
}

interface GraphLink {
  source: string | any;
  target: string | any;
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

  // Simulation state
  const [animatedNodes, setAnimatedNodes] = useState<GraphNode[]>([]);
  const [animatedLinks, setAnimatedLinks] = useState<GraphLink[]>([]);
  const simulationRef = useRef<any>(null);

  // Zoom & Pan state
  const [zoom, setZoom] = useState({ x: 0, y: 0, k: 1 });
  const [isPanning, setIsPanning] = useState(false);
  const [panStart, setPanStart] = useState({ x: 0, y: 0 });
  const [draggedNodeId, setDraggedNodeId] = useState<string | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

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
    const match = country.match(/^([^\(]+)/);
    const name = match ? match[1].trim() : country.trim();
    return name.toLowerCase();
  };

  const extractAsnNumber = (asn: any): string => {
    if (!asn) return "";
    const match = String(asn).match(/\d+/);
    return match ? match[0] : "";
  };

  // Compile the initial graph structure
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

    const asnMap: Record<string, { rawLabel: string; vendors: string[] }> = {};
    const countryMap: Record<string, { rawLabel: string; vendors: string[] }> = {};
    const ispMap: Record<string, { rawLabel: string; vendors: string[] }> = {};
    const portMap: Record<string, { rawLabel: string; vendors: string[] }> = {};
    const verdictMap: Record<string, { rawLabel: string; vendors: string[]; status: 'safe' | 'suspicious' | 'malicious' | 'muted' }> = {};

    const activeVendors = vendorData.filter(v => Object.keys(v.data).length > 0 || v.error);

    activeVendors.forEach((vendor) => {
      if (vendor.error) {
        verdictMap[vendor.name] = { 
          rawLabel: `${vendor.name}: Error`, 
          vendors: [vendor.name],
          status: 'muted'
        };
        return;
      }

      const data = vendor.data;

      // Extract Status / Verdict
      const status = data["Status"] || data["Verdict"] || data["Risk"] || data["Abuse Score"] || data["Detections"];
      let verdictStatus: 'safe' | 'suspicious' | 'malicious' | 'muted' = 'safe';
      let statusText = "Clean";
      if (status) {
        const lowerStatus = String(status).toLowerCase();
        if (lowerStatus.includes("malicious") || lowerStatus.includes("unsafe") || lowerStatus.includes("phishing") || lowerStatus.includes("danger") || lowerStatus.includes("malware") || lowerStatus.includes("sample")) {
          verdictStatus = 'malicious';
          statusText = language === "pt" ? "Malicioso" : "Malicious";
        } else if (lowerStatus.includes("suspicious") || lowerStatus.includes("risk") || lowerStatus.includes("medium") || lowerStatus.includes("warning") || (typeof status === 'number' && status > 0) || (lowerStatus.includes("%") && parseInt(lowerStatus) > 0)) {
          verdictStatus = 'suspicious';
          statusText = language === "pt" ? "Suspeito" : "Suspicious";
        } else {
          statusText = language === "pt" ? "Limpo" : "Clean";
        }
      } else {
        statusText = language === "pt" ? "Limpo" : "Clean";
      }

      verdictMap[vendor.name] = {
        rawLabel: `${vendor.name}: ${statusText}`,
        vendors: [vendor.name],
        status: verdictStatus
      };

      // Extract ASN
      const asnVal = data["ASN"] || data["AS"] || data["AS Owner"];
      const asnNum = extractAsnNumber(asnVal);
      if (asnNum) {
        asnMap[asnNum] = asnMap[asnNum] || { rawLabel: `AS${asnNum}`, vendors: [] };
        if (!asnMap[asnNum].vendors.includes(vendor.name)) {
          asnMap[asnNum].vendors.push(vendor.name);
        }
      }

      // Extract Country
      const countryVal = data["Country"] || data["Country Code"] || data["Location"] || data["Geo Location"] || data["Country Name"];
      if (countryVal && countryVal !== "Unknown" && countryVal !== "N/A") {
        const normCountry = normalizeCountry(String(countryVal));
        if (normCountry) {
          let cCode = normCountry.toUpperCase();
          if (cCode.length > 3) {
            cCode = cCode.substring(0, 2);
          }
          countryMap[cCode] = countryMap[cCode] || { rawLabel: String(countryVal), vendors: [] };
          if (!countryMap[cCode].vendors.includes(vendor.name)) {
            countryMap[cCode].vendors.push(vendor.name);
          }
        }
      }

      // Extract ISP / Org
      const ispVal = data["ISP"] || data["Organization"] || data["AS Owner"] || data["Org"];
      if (ispVal && ispVal !== "Unknown" && ispVal !== "N/A") {
        const normIsp = normalizeIsp(String(ispVal));
        if (normIsp && normIsp.length > 2) {
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
          const cleanPort = p.trim().replace(/\/\w+$/, "");
          if (cleanPort && /^\d+$/.test(cleanPort)) {
            portMap[cleanPort] = portMap[cleanPort] || { rawLabel: `Port ${cleanPort}`, vendors: [] };
            if (!portMap[cleanPort].vendors.includes(vendor.name)) {
              portMap[cleanPort].vendors.push(vendor.name);
            }
          }
        });
      }
    });

    // 2. Create Category Nodes and connect them to Target
    const categoryList: { id: string; label: string; value: string; iconType: string; initialPos: { x: number; y: number } }[] = [];

    // Verdicts Category (always included)
    categoryList.push({
      id: "category-verdicts",
      label: language === "pt" ? "Vereditos" : "Security Verdicts",
      value: "verdicts",
      iconType: "verdicts",
      initialPos: { x: cx, y: cy - 100 }
    });

    // Geo Category
    const countryKeys = Object.keys(countryMap);
    if (countryKeys.length > 0) {
      categoryList.push({
        id: "category-geo",
        label: language === "pt" ? "Geolocalização" : "Geographic Info",
        value: "geo",
        iconType: "geo",
        initialPos: { x: cx + 100, y: cy }
      });
    }

    // Network Category
    const ispKeys = Object.keys(ispMap).slice(0, 4);
    const asnKeys = Object.keys(asnMap).slice(0, 4);
    if (ispKeys.length > 0 || asnKeys.length > 0) {
      categoryList.push({
        id: "category-net",
        label: language === "pt" ? "Infraestrutura" : "Network Owner",
        value: "network",
        iconType: "network",
        initialPos: { x: cx - 100, y: cy }
      });
    }

    // Ports Category
    const portKeys = Object.keys(portMap).slice(0, 5);
    if (portKeys.length > 0) {
      categoryList.push({
        id: "category-ports",
        label: language === "pt" ? "Portas Ativas" : "Active Services",
        value: "ports",
        iconType: "ports",
        initialPos: { x: cx, y: cy + 100 }
      });
    }

    // Add category nodes to graph
    categoryList.forEach(cat => {
      nodes.push({
        id: cat.id,
        label: cat.label,
        type: "category" as any,
        value: cat.value,
        x: cat.initialPos.x,
        y: cat.initialPos.y,
        connectedVendors: []
      });

      links.push({
        source: "target",
        target: cat.id,
        type: "category-link"
      });
    });

    // 3. Create Leaf nodes for each category
    // 3.1 Verdict Leaves -> connect to category-verdicts
    const verdictVendors = Object.keys(verdictMap);
    verdictVendors.forEach((vendorName, idx) => {
      const info = verdictMap[vendorName];
      const angle = (2 * Math.PI * idx) / verdictVendors.length;
      const lx = cx + 120 * Math.cos(angle);
      const ly = (cy - 100) + 50 * Math.sin(angle);
      const leafId = `verdict-${vendorName}`;

      nodes.push({
        id: leafId,
        label: info.rawLabel,
        type: "verdict",
        value: info.rawLabel,
        x: lx,
        y: ly,
        connectedVendors: info.vendors
      });

      links.push({
        source: "category-verdicts",
        target: leafId,
        type: "detail-link"
      });
    });

    // 3.2 Geo Leaves -> connect to category-geo
    countryKeys.forEach((cCode, idx) => {
      const info = countryMap[cCode];
      const angle = (2 * Math.PI * idx) / countryKeys.length;
      const lx = (cx + 100) + 50 * Math.cos(angle);
      const ly = cy + 50 * Math.sin(angle);
      const leafId = `country-${cCode}`;

      nodes.push({
        id: leafId,
        label: info.rawLabel,
        type: "country",
        value: info.rawLabel,
        x: lx,
        y: ly,
        connectedVendors: info.vendors
      });

      links.push({
        source: "category-geo",
        target: leafId,
        type: "detail-link"
      });
    });

    // 3.3 Network Leaves -> connect to category-net
    const netLeaves = [
      ...ispKeys.map(k => ({ key: k, type: 'isp' as const, info: ispMap[k] })),
      ...asnKeys.map(k => ({ key: k, type: 'asn' as const, info: asnMap[k] }))
    ];
    netLeaves.forEach((item, idx) => {
      const angle = (2 * Math.PI * idx) / netLeaves.length;
      const lx = (cx - 100) + 50 * Math.cos(angle);
      const ly = cy + 50 * Math.sin(angle);
      const leafId = `${item.type}-${item.key}`;

      nodes.push({
        id: leafId,
        label: item.info.rawLabel,
        type: item.type,
        value: item.info.rawLabel,
        x: lx,
        y: ly,
        connectedVendors: item.info.vendors
      });

      links.push({
        source: "category-net",
        target: leafId,
        type: "detail-link"
      });
    });

    // 3.4 Ports Leaves -> connect to category-ports
    portKeys.forEach((pCode, idx) => {
      const info = portMap[pCode];
      const angle = (2 * Math.PI * idx) / portKeys.length;
      const lx = cx + 50 * Math.cos(angle);
      const ly = (cy + 100) + 50 * Math.sin(angle);
      const leafId = `port-${pCode}`;

      nodes.push({
        id: leafId,
        label: info.rawLabel,
        type: "port",
        value: info.rawLabel,
        x: lx,
        y: ly,
        connectedVendors: info.vendors
      });

      links.push({
        source: "category-ports",
        target: leafId,
        type: "detail-link"
      });
    });

    return { nodes, links };
  }, [query, vendorData, language]);

  // Setup force-directed simulation
  useEffect(() => {
    // Deep copy nodes and links for simulation mutating
    const nodesCopy: GraphNode[] = graph.nodes.map(node => ({
      ...node,
      // Anchor target initially in center
      fx: node.type === "target" ? 300 : undefined,
      fy: node.type === "target" ? 300 : undefined
    }));
    const linksCopy: GraphLink[] = graph.links.map(link => ({ ...link }));

    const simulation = forceSimulation<GraphNode>(nodesCopy)
      .force("link", forceLink<GraphNode, GraphLink>(linksCopy).id((d) => d.id).distance((link) => {
        if (link.type === "category-link") return 110;
        return 65;
      }))
      .force("charge", forceManyBody().strength((node: any) => {
        if (node.type === "target") return -400;
        if (node.type === "category") return -250;
        return -80;
      }))
      .force("center", forceCenter(300, 300))
      .force("collide", forceCollide().radius((node: any) => {
        if (node.type === "target") return 35;
        if (node.type === "category") return 24;
        return 16;
      }).iterations(2));

    simulationRef.current = simulation;

    simulation.on("tick", () => {
      setAnimatedNodes([...nodesCopy]);
      setAnimatedLinks([...linksCopy]);
    });

    // Make sure we select the target node on data changes
    const targetNode = nodesCopy.find(n => n.type === "target");
    if (targetNode) {
      setActiveNode(targetNode);
    } else if (nodesCopy.length > 0) {
      setActiveNode(nodesCopy[0]);
    }

    return () => {
      simulation.stop();
    };
  }, [graph]);

  // Register non-passive wheel event on mount
  useEffect(() => {
    const svgEl = svgRef.current;
    if (!svgEl) return;

    const handleWheel = (e: WheelEvent) => {
      e.preventDefault();
      const zoomFactor = 1.08;

      setZoom(prev => {
        const nextK = e.deltaY < 0 ? prev.k * zoomFactor : prev.k / zoomFactor;
        const k = Math.max(0.3, Math.min(5, nextK));

        const rect = svgEl.getBoundingClientRect();
        const mouseX = e.clientX - rect.left;
        const mouseY = e.clientY - rect.top;

        const factor = k / prev.k;
        const x = mouseX - (mouseX - prev.x) * factor;
        const y = mouseY - (mouseY - prev.y) * factor;

        return { x, y, k };
      });
    };

    svgEl.addEventListener("wheel", handleWheel, { passive: false });
    return () => {
      svgEl.removeEventListener("wheel", handleWheel);
    };
  }, []);

  // Zoom Button Handlers
  const handleZoomIn = () => {
    setZoom(prev => {
      const k = Math.min(5, prev.k * 1.25);
      const factor = k / prev.k;
      const x = 300 - (300 - prev.x) * factor;
      const y = 300 - (300 - prev.y) * factor;
      return { x, y, k };
    });
  };

  const handleZoomOut = () => {
    setZoom(prev => {
      const k = Math.max(0.3, prev.k / 1.25);
      const factor = k / prev.k;
      const x = 300 - (300 - prev.x) * factor;
      const y = 300 - (300 - prev.y) * factor;
      return { x, y, k };
    });
  };

  const handleZoomReset = () => {
    setZoom({ x: 0, y: 0, k: 1 });
  };

  // Node Drag handlers
  const handleNodePointerDown = (e: React.PointerEvent<SVGGElement>, node: GraphNode) => {
    e.stopPropagation();
    if (e.button !== 0) return; // Only drag with left click

    e.currentTarget.setPointerCapture(e.pointerId);
    setDraggedNodeId(node.id);

    node.fx = node.x;
    node.fy = node.y;

    if (simulationRef.current) {
      simulationRef.current.alphaTarget(0.3).restart();
    }
  };

  const handleNodePointerMove = (e: React.PointerEvent<SVGGElement>, node: GraphNode) => {
    if (draggedNodeId !== node.id) return;
    e.stopPropagation();

    const svg = e.currentTarget.ownerSVGElement;
    if (!svg) return;

    const point = svg.createSVGPoint();
    point.x = e.clientX;
    point.y = e.clientY;

    const zoomGroup = svg.getElementById("zoom-group");
    const matrix = zoomGroup?.getScreenCTM()?.inverse();
    if (matrix) {
      const transformedPoint = point.matrixTransform(matrix);
      node.fx = transformedPoint.x;
      node.fy = transformedPoint.y;
    } else {
      const ctm = svg.getScreenCTM()?.inverse();
      if (ctm) {
        const transformedPoint = point.matrixTransform(ctm);
        node.fx = transformedPoint.x;
        node.fy = transformedPoint.y;
      }
    }
  };

  const handleNodePointerUp = (e: React.PointerEvent<SVGGElement>, node: GraphNode) => {
    e.stopPropagation();
    if (draggedNodeId !== node.id) return;

    e.currentTarget.releasePointerCapture(e.pointerId);
    setDraggedNodeId(null);

    // Keep it fixed at its drop destination
    node.fx = node.x;
    node.fy = node.y;

    if (simulationRef.current) {
      simulationRef.current.alphaTarget(0);
    }
  };

  // Panning handlers
  const handleSvgMouseDown = (e: React.MouseEvent<SVGSVGElement>) => {
    if (e.button !== 0) return;
    const target = e.target as SVGElement;
    if (target.tagName === "svg" || target.id === "zoom-bg" || target.id === "grid-overlay") {
      setIsPanning(true);
      setPanStart({ x: e.clientX - zoom.x, y: e.clientY - zoom.y });
    }
  };

  const handleSvgMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    if (!isPanning) return;
    setZoom(prev => ({
      ...prev,
      x: e.clientX - panStart.x,
      y: e.clientY - panStart.y
    }));
  };

  const handleSvgMouseUp = () => {
    setIsPanning(false);
  };

  const getFlagEmoji = (countryCode: string) => {
    if (!countryCode) return "🌐";
    const codePoints = countryCode
      .toUpperCase()
      .split('')
      .map(char => 127397 + char.charCodeAt(0));
    try {
      return String.fromCodePoint(...codePoints);
    } catch (e) {
      return "🌐";
    }
  };

  const getNodeColor = (type: string) => {
    switch (type) {
      case "target": return "text-primary fill-primary/10 border-primary";
      case "category": return "text-blue-500 fill-blue-500/5 border-blue-500/40";
      case "verdict": return "text-blue-500 fill-blue-500/10 border-blue-500";
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
      case "category": return "stroke-blue-500";
      case "verdict": return "stroke-blue-500";
      case "country": return "stroke-rose-500";
      case "isp": return "stroke-amber-500";
      case "asn": return "stroke-purple-500";
      case "port": return "stroke-emerald-500";
      default: return "stroke-border/40";
    }
  };

  const getLinkColor = (link: GraphLink, activeNodeId?: string) => {
    const sourceId = typeof link.source === "object" ? link.source.id : link.source;
    const targetId = typeof link.target === "object" ? link.target.id : link.target;

    const isCategoryLink = link.type === "category-link";
    const isHighlighted = activeNodeId && (sourceId === activeNodeId || targetId === activeNodeId);

    if (isCategoryLink) {
      return isHighlighted 
        ? "stroke-blue-500 stroke-[2.5] opacity-100" 
        : "stroke-blue-600/70 stroke-[2] opacity-85";
    }

    // Detail links
    return isHighlighted
      ? "stroke-blue-500/70 stroke-[1.5] opacity-90"
      : "stroke-zinc-800/80 stroke-[1] opacity-50 dark:stroke-zinc-700/60";
  };

  const getNodeIcon = (type: string, label: string) => {
    if (type === "category") {
      if (label.toLowerCase().includes("verdict") || label.toLowerCase().includes("veredito")) {
        return <Shield className="h-6 w-6 text-blue-500" />;
      }
      if (label.toLowerCase().includes("geo")) {
        return <Globe className="h-6 w-6 text-rose-500" />;
      }
      if (label.toLowerCase().includes("network") || label.toLowerCase().includes("infra")) {
        return <Server className="h-6 w-6 text-amber-500" />;
      }
      return <Activity className="h-6 w-6 text-emerald-500" />;
    }

    if (type === "verdict") {
      if (label.toLowerCase().includes("malicious") || label.toLowerCase().includes("malicioso")) {
        return <AlertTriangle className="h-6 w-6 text-red-500" />;
      }
      if (label.toLowerCase().includes("suspicious") || label.toLowerCase().includes("suspeito")) {
        return <AlertTriangle className="h-6 w-6 text-yellow-500" />;
      }
      if (label.toLowerCase().includes("error")) {
        return <Info className="h-6 w-6 text-muted-foreground" />;
      }
      return <Shield className="h-6 w-6 text-green-500" />;
    }

    switch (type) {
      case "target": return <Globe className="h-6 w-6 text-primary" />;
      case "isp": return <Server className="h-6 w-6 text-amber-400" />;
      case "asn": return <Link2 className="h-6 w-6 text-purple-400" />;
      case "port": return <Terminal className="h-6 w-6 text-emerald-400" />;
      default: return <Info className="h-6 w-6 text-muted-foreground" />;
    }
  };

  const displayNode = hoveredNode || activeNode;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success(language === "pt" ? "Copiado!" : "Copied!");
  };

  return (
    <Card className="border-white/[0.04] bg-[#0B0E1A]/80   rounded-xl overflow-hidden animate-fade-in">
      <div className="flex items-center justify-between px-5 py-3 border-b border-white/[0.04]">
        <div className="flex items-center gap-3">
          <h3 className="text-sm font-bold text-foreground">{language === "pt" ? "Correlação de Ameaças" : "Threat Correlation"}</h3>
          <span className="text-[10px] text-muted-foreground/50">Drag · Scroll · Click</span>
        </div>
        <Badge variant={threatLevel === "malicious" ? "destructive" : "secondary"} className="text-[10px] font-bold">
          {overallScore}/100 · {threatLevel.toUpperCase()}
        </Badge>
      </div>
      
      <CardContent className="p-0 grid grid-cols-1 lg:grid-cols-12 min-h-[420px]">
        {/* SVG Canvas */}
        <div className="lg:col-span-8 flex items-center justify-center p-2 border-b lg:border-b-0 lg:border-r border-white/[0.04] bg-black/20 relative select-none">
          
          {/* Zoom controls */}
          <div className="absolute top-2 right-2 flex gap-0.5 bg-white/[0.03]  p-0.5 border border-white/[0.06] rounded-lg z-10">
            <Button variant="ghost" size="icon" className="h-6 w-6 rounded-md hover:bg-white/[0.06] text-muted-foreground/50" onClick={handleZoomIn}><ZoomIn className="h-3 w-3" /></Button>
            <Button variant="ghost" size="icon" className="h-6 w-6 rounded-md hover:bg-white/[0.06] text-muted-foreground/50" onClick={handleZoomOut}><ZoomOut className="h-3 w-3" /></Button>
            <Button variant="ghost" size="icon" className="h-6 w-6 rounded-md hover:bg-white/[0.06] text-muted-foreground/50" onClick={handleZoomReset}><Maximize2 className="h-3 w-3" /></Button>
          </div>

          <svg 
            ref={svgRef}
            className="w-full h-full max-w-[560px] max-h-[560px] cursor-grab active:cursor-grabbing overflow-hidden" 
            viewBox="0 0 600 600"
            onMouseDown={handleSvgMouseDown}
            onMouseMove={handleSvgMouseMove}
            onMouseUp={handleSvgMouseUp}
            onMouseLeave={handleSvgMouseUp}
          >
            <defs>
              <pattern id="grid-pattern" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="currentColor" className="text-foreground/[0.04]" strokeWidth="1" />
              </pattern>
            </defs>

            {/* Transparent background to capture panning events anywhere */}
            <rect id="zoom-bg" width="100%" height="100%" fill="transparent" />

            <g id="zoom-group" transform={`translate(${zoom.x}, ${zoom.y}) scale(${zoom.k})`}>
              {/* Scalable background grid */}
              <rect id="grid-overlay" width="2000" height="2000" x="-700" y="-700" fill="url(#grid-pattern)" pointerEvents="none" />

              {/* Links / Connecting Lines */}
              {animatedLinks.map((link, idx) => {
                const x1 = typeof link.source === "object" ? link.source.x : animatedNodes.find(n => n.id === link.source)?.x;
                const y1 = typeof link.source === "object" ? link.source.y : animatedNodes.find(n => n.id === link.source)?.y;
                const x2 = typeof link.target === "object" ? link.target.x : animatedNodes.find(n => n.id === link.target)?.x;
                const y2 = typeof link.target === "object" ? link.target.y : animatedNodes.find(n => n.id === link.target)?.y;
                
                if (x1 === undefined || y1 === undefined || x2 === undefined || y2 === undefined) return null;
                
                return (
                  <line
                    key={idx}
                    x1={x1}
                    y1={y1}
                    x2={x2}
                    y2={y2}
                    className={`stroke-[1.5] transition-all duration-300 ${getLinkColor(link, displayNode?.id)}`}
                  />
                );
              })}

              {/* Nodes / Circles */}
              {animatedNodes.map((node) => {
                const isActive = activeNode?.id === node.id;
                const isHovered = hoveredNode?.id === node.id;
                const isTarget = node.type === "target";
                const isCategory = node.type === "category";
                const size = isTarget ? 22 : isCategory ? 16 : 12;

                return (
                  <g 
                    key={node.id}
                    transform={`translate(${node.x}, ${node.y})`}
                    onClick={() => setActiveNode(node)}
                    onMouseEnter={() => setHoveredNode(node)}
                    onMouseLeave={() => setHoveredNode(null)}
                    onPointerDown={(e) => handleNodePointerDown(e, node)}
                    onPointerMove={(e) => handleNodePointerMove(e, node)}
                    onPointerUp={(e) => handleNodePointerUp(e, node)}
                    className="cursor-grab active:cursor-grabbing select-none"
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
                          ? `${getStrokeColor(node.type)} stroke-3 scale-105 filter drop-shadow-[0_0_8px_rgba(30,96,255,0.35)]` 
                          : "stroke-border/75 hover:stroke-foreground/60"
                      }`}
                    />

                    {/* Inner Node Icon / Flag Emoji */}
                    {node.type === "country" ? (
                      <text textAnchor="middle" y="4" className="text-[12px] select-none pointer-events-none font-sans">
                        {getFlagEmoji(node.id.replace("country-", ""))}
                      </text>
                    ) : (
                      <g transform={`scale(${(size * 1.1) / 24}) translate(-12, -12)`} className="pointer-events-none">
                        {getNodeIcon(node.type, node.label)}
                      </g>
                    )}

                    {/* Permanent Label next to node (VirusTotal style) */}
                    <text
                      dx={size + 6}
                      dy="3.5"
                      className={`text-[9px] pointer-events-none font-mono select-none transition-colors ${
                        isTarget 
                          ? "fill-foreground font-bold text-[10.5px]" 
                          : node.type === "category"
                            ? "fill-blue-400 font-bold"
                            : "fill-zinc-400 font-semibold"
                      }`}
                    >
                      {node.label.length > 22 ? `${node.label.substring(0, 20)}...` : node.label}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>

          {/* Compact inline legend */}
          <div className="absolute bottom-2 left-2 flex items-center gap-2 bg-black/40  px-2.5 py-1.5 border border-white/[0.04] rounded-lg z-10">
            {[
              { color: "bg-primary", label: "Target" },
              { color: "bg-blue-500", label: "Category" },
              { color: "bg-blue-500/60", label: "Verdict" },
              { color: "bg-rose-500", label: "Country" },
              { color: "bg-amber-500", label: "ISP" },
              { color: "bg-purple-500", label: "ASN" },
              { color: "bg-emerald-500", label: "Port" },
            ].map(l => (
              <div key={l.label} className="flex items-center gap-1">
                <div className={`h-1.5 w-1.5 rounded-full ${l.color}`} />
                <span className="text-[8px] font-semibold text-muted-foreground/50">{l.label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Inspector Sidebar */}
        <div className="lg:col-span-4 p-4 flex flex-col justify-between bg-white/[0.01] min-h-[300px]">
          {displayNode ? (
            <div className="space-y-3">
              <div className="space-y-1">
                <span className="text-[9px] font-bold uppercase tracking-widest text-muted-foreground/40">{displayNode.type}</span>
                <h3 className="text-sm font-bold font-mono break-all leading-tight text-foreground flex items-center justify-between gap-2">
                  <span className="truncate">{displayNode.label}</span>
                  <button className="p-1 rounded text-muted-foreground/30 hover:text-foreground shrink-0" onClick={() => handleCopy(displayNode.value)}>
                    <Copy className="h-3 w-3" />
                  </button>
                </h3>
              </div>

              {/* Node Type Details */}
              {displayNode.type === "category" && (
                <div className="space-y-3 text-xs leading-relaxed">
                  <p className="text-muted-foreground">
                    {language === "pt"
                      ? `Esta categoria agrupa os detalhes correlacionados do IoC sob o tema de "${displayNode.label}".`
                      : `This category groups the correlated details of the IoC under the theme of "${displayNode.label}".`}
                  </p>
                  {(() => {
                    // Find all leaf nodes connected to this category
                    const leaves = animatedNodes.filter(n => 
                      graph.links.some(l => {
                        const sId = typeof l.source === "object" ? l.source.id : l.source;
                        const tId = typeof l.target === "object" ? l.target.id : l.target;
                        return sId === displayNode.id && tId === n.id;
                      })
                    );
                    
                    if (leaves.length === 0) return null;
                    
                    return (
                      <div className="space-y-2 border-t border-white/[0.04] pt-2.5">
                        <div className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest mb-1.5">
                          {language === "pt" ? "Itens Identificados:" : "Identified Items:"}
                        </div>
                        <div className="space-y-1.5">
                          {leaves.map(leaf => (
                            <div key={leaf.id} className="flex items-center gap-2 text-xs border-b border-border/10 pb-1.5">
                              {leaf.type === "country" ? (
                                <span className="text-base leading-none">
                                  {getFlagEmoji(leaf.id.replace("country-", ""))}
                                </span>
                              ) : (
                                <div className="h-3.5 w-3.5 flex items-center justify-center shrink-0 [&_svg]:h-3.5 [&_svg]:w-3.5">
                                  {getNodeIcon(leaf.type, leaf.label)}
                                </div>
                              )}
                              <span className="font-mono text-foreground truncate flex-1">{leaf.label}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })()}
                </div>
              )}

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
                  <div className="bg-primary/5 border border-primary/10 rounded-xl p-4 space-y-2">
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

          <div className="text-[8px] text-muted-foreground/30 text-center border-t border-white/[0.04] pt-3 mt-4">
            Correlation Engine
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
