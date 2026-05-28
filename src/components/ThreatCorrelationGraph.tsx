import React, { useState, useMemo, useEffect, useRef } from "react";
import { 
  Globe, Shield, AlertTriangle, Database, Info, Copy, Server, Link2, ExternalLink,
  ZoomIn, ZoomOut, Maximize2
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
  type: 'target' | 'vendor' | 'country' | 'isp' | 'asn' | 'port' | 'verdict' | 'misc';
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
    const verdictMap: Record<string, { rawLabel: string; vendors: string[] }> = {};

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

    // 3. Position Fact Nodes in their sectors (Outer circle radius R2 = 240)
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
    const ispKeys = Object.keys(ispMap).slice(0, 5);
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
        if (link.type === "vendor-link") return 110;
        return 75;
      }))
      .force("charge", forceManyBody().strength((node: any) => {
        if (node.type === "target") return -450;
        if (node.type === "vendor") return -200;
        return -90;
      }))
      .force("center", forceCenter(300, 300))
      .force("collide", forceCollide().radius((node: any) => {
        if (node.type === "target") return 35;
        if (node.type === "vendor") return 22;
        return 18;
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
    
    const sourceId = typeof link.source === "object" ? link.source.id : link.source;
    const targetId = typeof link.target === "object" ? link.target.id : link.target;

    const isConnected = sourceId === activeNodeId || targetId === activeNodeId ||
      (activeNodeId === "target" && sourceId === "target");

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
    <Card className="border-white/[0.04] bg-[#0B0E1A]/80 backdrop-blur-xl shadow-lg rounded-2xl overflow-hidden animate-fade-in">
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
          <div className="absolute top-2 right-2 flex gap-0.5 bg-white/[0.03] backdrop-blur-md p-0.5 border border-white/[0.06] rounded-lg z-10">
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
                const size = isTarget ? 24 : 12;

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
            </g>
          </svg>

          {/* Compact inline legend */}
          <div className="absolute bottom-2 left-2 flex items-center gap-2 bg-black/40 backdrop-blur-md px-2.5 py-1.5 border border-white/[0.04] rounded-lg z-10">
            {[
              { color: "bg-primary", label: "Target" },
              { color: "bg-muted-foreground", label: "Vendor" },
              { color: "bg-indigo-500", label: "Verdict" },
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

          <div className="text-[8px] text-muted-foreground/30 text-center border-t border-white/[0.04] pt-3 mt-4">
            Correlation Engine
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
