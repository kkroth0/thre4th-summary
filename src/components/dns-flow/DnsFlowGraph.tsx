import { useCallback, useMemo, useState, useEffect } from "react";
import {
  ReactFlow, Background, Controls, MiniMap, useNodesState, useEdgesState,
  type Node, type Edge, BackgroundVariant, Panel, useReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { dnsNodeTypes, TYPE_COLORS } from "./DnsNodes";
import { dnsEdgeTypes } from "./DnsEdge";
import type { DnsLookupResult } from "@/services/threatApi";

interface DnsFlowGraphProps {
  dnsData: DnsLookupResult;
  onNodeSelect: (nodeData: { id: string; type: string; value: string; label: string; meta?: any } | null) => void;
  selectedNodeId?: string | null;
}

// Helper to compute node positions, distributing them in multi-row outward-facing fans if there are many nodes
function getItemPosition(
  idx: number,
  itemsCount: number,
  baseAngle: number,
  gx: number,
  gy: number,
  itemRadius: number
) {
  if (itemsCount <= 5) {
    // Single arc fan layout for small sets
    const spread = Math.min(0.8, 1.2 / itemsCount);
    const itemAngle = itemsCount === 1
      ? baseAngle
      : baseAngle + (idx - (itemsCount - 1) / 2) * spread;
    return {
      x: gx + itemRadius * Math.cos(itemAngle),
      y: gy + itemRadius * Math.sin(itemAngle),
      angle: itemAngle
    };
  } else {
    // Dynamic layout parameters based on itemsCount to avoid overlaps in large lists (e.g. 50 subdomains)
    const sectorWidth = itemsCount > 30 ? 3.4 : (itemsCount > 15 ? 2.8 : 2.0);
    const startRadius = itemsCount > 30 ? 220 : (itemsCount > 15 ? 180 : itemRadius);
    const rowSpacing = itemsCount > 30 ? 145 : (itemsCount > 15 ? 125 : 105);

    let rowIdx = 0;
    let itemsInPrevRows = 0;
    let itemsInCurrentRow = 5;
    while (idx >= itemsInPrevRows + itemsInCurrentRow) {
      itemsInPrevRows += itemsInCurrentRow;
      rowIdx++;
      itemsInCurrentRow = 5 + rowIdx * 3;
    }
    const idxInRow = idx - itemsInPrevRows;
    const rowRadius = startRadius + rowIdx * rowSpacing;
    
    // Spread the nodes in this row evenly within the outward-facing sector
    const step = itemsInCurrentRow === 1 ? 0 : sectorWidth / (itemsInCurrentRow - 1);
    const itemAngle = baseAngle + (idxInRow - (itemsInCurrentRow - 1) / 2) * step;
    
    return {
      x: gx + rowRadius * Math.cos(itemAngle),
      y: gy + rowRadius * Math.sin(itemAngle),
      angle: itemAngle
    };
  }
}

// Build nodes & edges from DNS data
function buildGraph(
  dnsData: DnsLookupResult,
  expandedCategories: Set<string>,
  expandedSubdomains: Set<string>
) {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const cx = 0, cy = 0;

  // Center domain node
  nodes.push({
    id: "domain-center",
    type: "domainNode",
    position: { x: cx - 75, y: cy },
    data: { label: dnsData.domain, value: dnsData.domain, recordType: "domain" },
    draggable: true,
  });

  const records = { ...dnsData.records } as any;

  // Extract subdomains from dnsDumpster
  const subdomains = dnsData.dnsDumpster?.a?.filter((item: any) => item.host !== dnsData.domain) || [];

  const recordTypes = (Object.keys(records) as string[]).filter(
    (t) => records[t] && records[t].length > 0
  );

  if (subdomains.length > 0) {
    recordTypes.push("Subdomain");
  }

  const K = recordTypes.length;
  const itemRadius = 150;

  const createdNodeIds = new Set<string>();

  recordTypes.forEach((type, catIdx) => {
    const baseAngle = (2 * Math.PI * catIdx) / K - Math.PI / 2;
    const itemsCount = type === "Subdomain" ? subdomains.length : records[type].length;
    
    // Dynamic group radius based on itemsCount to push large groups outward
    const dynamicGroupRadius = 340 + Math.max(0, (itemsCount - 5) * 9);
    const gx = cx + dynamicGroupRadius * Math.cos(baseAngle);
    const gy = cy + dynamicGroupRadius * Math.sin(baseAngle);
    const groupId = `group-${type}`;

    const isCatExpanded = expandedCategories.has(type);

    // Group label node
    nodes.push({
      id: groupId,
      type: "groupNode",
      position: { x: gx - 40, y: gy - 12 },
      data: {
        label: type === "Subdomain" ? "Subdomains" : type,
        recordType: type,
        count: itemsCount,
        isExpanded: isCatExpanded
      },
      draggable: true,
    });

    // Edge from domain to group
    edges.push({
      id: `e-domain-${type}`,
      source: "domain-center",
      target: groupId,
      type: "dnsEdge",
      data: { recordType: type },
      animated: true,
    });

    // Only render child records if the group category itself is expanded!
    if (isCatExpanded) {
      if (type === "Subdomain") {
        subdomains.forEach((item: any, idx: number) => {
          const nodeId = `Subdomain-${item.host}`;
          const pos = getItemPosition(idx, subdomains.length, baseAngle, gx, gy, itemRadius);
          const nx = pos.x;
          const ny = pos.y;
          const itemAngle = pos.angle;

          const hasIps = Array.isArray(item.ips) && item.ips.length > 0;
          const ipCount = item.ips?.length || 0;
          const isSubExpanded = expandedSubdomains.has(item.host);

          nodes.push({
            id: nodeId,
            type: "recordNode",
            position: { x: nx - 60, y: ny - 16 },
            data: {
              label: item.host,
              value: item.host,
              recordType: "Subdomain",
              meta: item,
              hasIps,
              ipCount,
              isExpanded: isSubExpanded
            },
            draggable: true,
          });
          createdNodeIds.add(nodeId);

          edges.push({
            id: `e-${groupId}-${nodeId}`,
            source: groupId,
            target: nodeId,
            type: "dnsEdge",
            data: { recordType: "Subdomain" },
          });

          // Only render subdomain resolved IP nodes if the subdomain is expanded!
          if (isSubExpanded && Array.isArray(item.ips)) {
            item.ips.forEach((ipObj: any, ipIdx: number) => {
              const ipNodeId = `A-${ipObj.ip}`;
              if (!createdNodeIds.has(ipNodeId)) {
                const ipAngle = itemAngle + (ipIdx - (item.ips.length - 1) / 2) * 0.25;
                const ipDist = 130;
                const ipx = nx + ipDist * Math.cos(ipAngle);
                const ipy = ny + ipDist * Math.sin(ipAngle);

                nodes.push({
                  id: ipNodeId,
                  type: "recordNode",
                  position: { x: ipx - 60, y: ipy - 16 },
                  data: {
                    label: ipObj.ip,
                    value: ipObj.ip,
                    recordType: "A",
                    meta: {
                      asn: ipObj.asn,
                      asn_name: ipObj.asn_name,
                      country: ipObj.country,
                      banners: ipObj.banners,
                      ptr: ipObj.ptr
                    }
                  },
                  draggable: true,
                });
                createdNodeIds.add(ipNodeId);
              }

              edges.push({
                id: `e-${nodeId}-${ipNodeId}`,
                source: nodeId,
                target: ipNodeId,
                type: "dnsEdge",
                data: { recordType: "A" },
              });
            });
          }
        });
      } else {
        const items = records[type] as string[];
        items.forEach((val, idx) => {
          const nodeId = `${type}-${val.replace(/[^a-zA-Z0-9.-]/g, '_')}`;
          const pos = getItemPosition(idx, items.length, baseAngle, gx, gy, itemRadius);
          const nx = pos.x;
          const ny = pos.y;

          let nodeMeta = undefined;
          if (type === "A") {
            const matchedDumpsterA = dnsData.dnsDumpster?.a?.find((hostObj: any) =>
              hostObj.ips?.some((ipObj: any) => ipObj.ip === val)
            );
            if (matchedDumpsterA) {
              const matchedIp = matchedDumpsterA.ips.find((ipObj: any) => ipObj.ip === val);
              if (matchedIp) {
                nodeMeta = {
                  asn: matchedIp.asn,
                  asn_name: matchedIp.asn_name,
                  country: matchedIp.country,
                  banners: matchedIp.banners,
                  ptr: matchedIp.ptr
                };
              }
            }
          }

          if (!createdNodeIds.has(nodeId)) {
            nodes.push({
              id: nodeId,
              type: "recordNode",
              position: { x: nx - 60, y: ny - 16 },
              data: { label: val, value: val, recordType: type, meta: nodeMeta },
              draggable: true,
            });
            createdNodeIds.add(nodeId);
          }

          edges.push({
            id: `e-${groupId}-${nodeId}`,
            source: groupId,
            target: nodeId,
            type: "dnsEdge",
            data: { recordType: type },
          });
        });
      }
    }
  });

  return { nodes, edges };
}

export function DnsFlowGraph({ dnsData, onNodeSelect, selectedNodeId }: DnsFlowGraphProps) {
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set());
  const [expandedSubdomains, setExpandedSubdomains] = useState<Set<string>>(new Set());

  // Initialize expanded categories (expand if list size <= 5, collapse if > 5)
  useEffect(() => {
    const defaultExpanded = new Set<string>();
    const records = dnsData.records || {};

    Object.entries(records).forEach(([type, list]) => {
      if (Array.isArray(list) && list.length > 0 && list.length <= 5) {
        defaultExpanded.add(type);
      }
    });

    const subdomainsCount = dnsData.dnsDumpster?.a?.filter((item: any) => item.host !== dnsData.domain).length || 0;
    if (subdomainsCount > 0 && subdomainsCount <= 5) {
      defaultExpanded.add("Subdomain");
    }

    setExpandedCategories(defaultExpanded);
    setExpandedSubdomains(new Set());
  }, [dnsData]);

  const { nodes: initialNodes, edges: initialEdges } = useMemo(() => {
    return buildGraph(dnsData, expandedCategories, expandedSubdomains);
  }, [dnsData, expandedCategories, expandedSubdomains]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Sync stateful React Flow nodes/edges when graph updates
  useEffect(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
  }, [initialNodes, setNodes, setEdges]);

  const reactFlowInstance = useReactFlow();

  // Watch selectedNodeId to handle centering/auto-expanding
  useEffect(() => {
    if (selectedNodeId) {
      let categoryToExpand: string | null = null;
      let subdomainToExpand: string | null = null;

      if (selectedNodeId.startsWith("Subdomain-")) {
        categoryToExpand = "Subdomain";
      } else if (selectedNodeId.startsWith("A-") || selectedNodeId.startsWith("AAAA-") || selectedNodeId.startsWith("MX-") || selectedNodeId.startsWith("NS-") || selectedNodeId.startsWith("TXT-")) {
        const firstDash = selectedNodeId.indexOf("-");
        if (firstDash !== -1) {
          const type = selectedNodeId.substring(0, firstDash);
          // If it matches standard types, expand that category group
          if (["A", "AAAA", "MX", "NS", "TXT"].includes(type)) {
            categoryToExpand = type;
          }
        }
      }

      // Special check: resolved IP connected to a subdomain (A record mapped from dnsDumpster)
      if (selectedNodeId.startsWith("A-")) {
        const ip = selectedNodeId.substring(2);
        const parentSub = dnsData.dnsDumpster?.a?.find((sub: any) =>
          sub.ips?.some((ipObj: any) => ipObj.ip === ip)
        );
        if (parentSub) {
          categoryToExpand = "Subdomain";
          subdomainToExpand = parentSub.host;
        }
      }

      let stateChanged = false;
      if (categoryToExpand && !expandedCategories.has(categoryToExpand)) {
        setExpandedCategories(prev => {
          const next = new Set(prev);
          next.add(categoryToExpand!);
          return next;
        });
        stateChanged = true;
      }

      if (subdomainToExpand && !expandedSubdomains.has(subdomainToExpand)) {
        setExpandedSubdomains(prev => {
          const next = new Set(prev);
          next.add(subdomainToExpand!);
          return next;
        });
        stateChanged = true;
      }

      const delay = stateChanged ? 250 : 50;
      const timer = setTimeout(() => {
        const targetNode = nodes.find(n => n.id === selectedNodeId);
        if (targetNode) {
          reactFlowInstance.setCenter(targetNode.position.x + 60, targetNode.position.y + 16, { zoom: 1.1, duration: 800 });
        }
      }, delay);

      return () => clearTimeout(timer);
    }
  }, [selectedNodeId, dnsData, reactFlowInstance, nodes, expandedCategories, expandedSubdomains]);

  const onNodeClick = useCallback((_: any, node: Node) => {
    const d = node.data as any;

    if (node.type === "groupNode") {
      setExpandedCategories((prev) => {
        const next = new Set(prev);
        if (next.has(d.recordType)) {
          next.delete(d.recordType);
        } else {
          next.add(d.recordType);
        }
        return next;
      });
    } else if (node.type === "recordNode" && d.recordType === "Subdomain" && d.hasIps) {
      setExpandedSubdomains((prev) => {
        const next = new Set(prev);
        if (next.has(d.label)) {
          next.delete(d.label);
        } else {
          next.add(d.label);
        }
        return next;
      });
    }

    onNodeSelect({ id: node.id, type: d.recordType, value: d.value || d.label, label: d.label, meta: d.meta });
  }, [onNodeSelect]);

  const onPaneClick = useCallback(() => {
    onNodeSelect(null);
  }, [onNodeSelect]);

  const styledNodes = useMemo(() => nodes.map(n => ({
    ...n,
    selected: n.id === selectedNodeId,
  })), [nodes, selectedNodeId]);

  const edgeColorVars = useMemo(() => {
    const vars: Record<string, string> = {};
    Object.entries(TYPE_COLORS).forEach(([type, colors]) => {
      const hueMap: Record<string, string> = {
        domain: "hsl(var(--primary) / 0.35)",
        A: "rgba(239,68,68,0.35)",
        AAAA: "rgba(249,115,22,0.35)",
        MX: "rgba(59,130,246,0.35)",
        NS: "rgba(168,85,247,0.35)",
        TXT: "rgba(16,185,129,0.30)",
        CNAME: "rgba(6,182,212,0.35)",
        Subdomain: "rgba(236,72,153,0.35)",
      };
      vars[`--edge-color-${type}`] = hueMap[type] || "hsl(var(--primary) / 0.3)";
    });
    return vars;
  }, []);

  return (
    <div className="w-full h-full rounded-2xl overflow-hidden border border-border/30 bg-background/30 backdrop-blur-sm" style={edgeColorVars as any}>
      <ReactFlow
        nodes={styledNodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        onPaneClick={onPaneClick}
        nodeTypes={dnsNodeTypes}
        edgeTypes={dnsEdgeTypes}
        fitView
        fitViewOptions={{ padding: 0.3, maxZoom: 1.2 }}
        minZoom={0.2}
        maxZoom={2.5}
        proOptions={{ hideAttribution: true }}
        className="dns-flow-graph"
      >
        <Background variant={BackgroundVariant.Dots} gap={24} size={1} className="!bg-transparent" color="hsl(var(--muted-foreground) / 0.08)" />
        <Controls
          showInteractive={false}
          className="!bg-card/80 !backdrop-blur-md !border-border/40 !rounded-xl !shadow-lg [&>button]:!bg-transparent [&>button]:!border-border/20 [&>button]:!text-muted-foreground [&>button:hover]:!bg-muted/30 [&>button]:!rounded-lg"
        />
        <MiniMap
          className="!bg-card/60 !backdrop-blur-md !border-border/30 !rounded-xl !shadow-md"
          maskColor="hsl(var(--background) / 0.7)"
          nodeColor={(n) => {
            const type = (n.data as any)?.recordType || "domain";
            const colorMap: Record<string, string> = {
              domain: "hsl(var(--primary))", A: "#ef4444", AAAA: "#f97316",
              MX: "#3b82f6", NS: "#a855f7", TXT: "#10b981", CNAME: "#06b6d4",
              Subdomain: "#ec4899",
            };
            return colorMap[type] || "hsl(var(--muted-foreground))";
          }}
          pannable
          zoomable
        />
        <Panel position="bottom-left" className="!m-3">
          <div className="bg-card/80 backdrop-blur-md border border-border/40 rounded-xl p-3 space-y-1.5 text-[10px] font-semibold shadow-md">
            <div className="text-[9px] font-bold text-muted-foreground/60 uppercase tracking-wider mb-1">Legend</div>
            {[
              { type: "domain", label: "Domain" },
              { type: "A", label: "A (IPv4)" },
              { type: "AAAA", label: "AAAA (IPv6)" },
              { type: "MX", label: "MX (Mail)" },
              { type: "NS", label: "NS (Nameserver)" },
              { type: "TXT", label: "TXT (Text)" },
              { type: "CNAME", label: "CNAME (Alias)" },
              { type: "Subdomain", label: "Subdomain" },
            ].map(({ type, label }) => (
              <div key={type} className="flex items-center gap-2 text-muted-foreground/70">
                <div className={`h-2 w-2 rounded-full ${TYPE_COLORS[type]?.dot}`} />
                {label}
              </div>
            ))}
          </div>
        </Panel>
      </ReactFlow>
    </div>
  );
}
