import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import {
  Globe, Shield, Server, Mail, Database, FileText, Link2, Info
} from "lucide-react";

// ── Color config per record type ──────────────────────────
export const TYPE_COLORS: Record<string, { bg: string; border: string; text: string; ring: string; dot: string; edgeStroke: string }> = {
  domain: { bg: "bg-primary/10", border: "border-primary/60", text: "text-primary", ring: "ring-primary/20", dot: "bg-primary", edgeStroke: "stroke-primary/40" },
  A:      { bg: "bg-red-500/10", border: "border-red-500/50", text: "text-red-400", ring: "ring-red-500/20", dot: "bg-red-500", edgeStroke: "stroke-red-500/40" },
  AAAA:   { bg: "bg-orange-500/10", border: "border-orange-500/50", text: "text-orange-400", ring: "ring-orange-500/20", dot: "bg-orange-500", edgeStroke: "stroke-orange-500/40" },
  MX:     { bg: "bg-blue-500/10", border: "border-blue-500/50", text: "text-blue-400", ring: "ring-blue-500/20", dot: "bg-blue-500", edgeStroke: "stroke-blue-500/40" },
  NS:     { bg: "bg-purple-500/10", border: "border-purple-500/50", text: "text-purple-400", ring: "ring-purple-500/20", dot: "bg-purple-500", edgeStroke: "stroke-purple-500/40" },
  TXT:    { bg: "bg-emerald-500/10", border: "border-emerald-500/50", text: "text-emerald-400", ring: "ring-emerald-500/20", dot: "bg-emerald-500", edgeStroke: "stroke-emerald-500/40" },
  CNAME:  { bg: "bg-cyan-500/10", border: "border-cyan-500/50", text: "text-cyan-400", ring: "ring-cyan-500/20", dot: "bg-cyan-500", edgeStroke: "stroke-cyan-500/40" },
  Subdomain: { bg: "bg-pink-500/10", border: "border-pink-500/50", text: "text-pink-400", ring: "ring-pink-500/20", dot: "bg-pink-500", edgeStroke: "stroke-pink-500/40" },
};

const typeIcon = (type: string, size = "h-4 w-4") => {
  switch (type) {
    case "domain": return <Globe className={size} />;
    case "A": return <Shield className={size} />;
    case "AAAA": return <Server className={size} />;
    case "MX": return <Mail className={size} />;
    case "NS": return <Database className={size} />;
    case "TXT": return <FileText className={size} />;
    case "CNAME": return <Link2 className={size} />;
    case "Subdomain": return <Server className={size} />;
    default: return <Info className={size} />;
  }
};

// ── Domain Hub Node (center) ──────────────────────────────
export type DomainNodeData = { label: string; value: string; recordType: string; };

export const DomainNode = memo(({ data, selected }: NodeProps) => {
  const d = data as unknown as DomainNodeData;
  const colors = TYPE_COLORS["domain"];
  return (
    <div className={`relative group`}>
      {/* Pulsing ring */}
      <div className={`absolute -inset-2.5 rounded-full ${colors.ring} ring-2 ring-inset opacity-0 group-hover:opacity-100 transition-opacity duration-500 ${selected ? "opacity-100 animate-pulse" : ""}`} />

      {/* Main body */}
      <div className={`
        relative flex flex-col items-center gap-1 px-5 py-3.5 rounded-2xl border-2 backdrop-blur-xl shadow-lg
        ${colors.bg} ${colors.border} ${colors.text}
        transition-all duration-300 cursor-grab active:cursor-grabbing
        ${selected ? "shadow-primary/20 shadow-xl scale-105 border-primary" : "hover:shadow-lg hover:scale-[1.02]"}
      `}>
        <div className="flex items-center gap-2">
          {typeIcon("domain", "h-5 w-5")}
          <span className="text-[13px] font-extrabold tracking-tight font-mono">{d.label}</span>
        </div>
        <span className="text-[9px] font-bold uppercase tracking-widest text-muted-foreground/60">DOMAIN</span>
      </div>

      {/* Handles (hidden but functional) */}
      <Handle type="source" position={Position.Top} className="!w-0 !h-0 !border-0 !bg-transparent" />
      <Handle type="source" position={Position.Bottom} className="!w-0 !h-0 !border-0 !bg-transparent" id="bottom" />
      <Handle type="source" position={Position.Left} className="!w-0 !h-0 !border-0 !bg-transparent" id="left" />
      <Handle type="source" position={Position.Right} className="!w-0 !h-0 !border-0 !bg-transparent" id="right" />
    </div>
  );
});
DomainNode.displayName = "DomainNode";

// ── Record Node (A, AAAA, MX, NS, TXT, CNAME) ───────────
export type RecordNodeData = {
  label: string;
  value: string;
  recordType: string;
  count?: number;
  isExpanded?: boolean;
  hasIps?: boolean;
  ipCount?: number;
};

export const RecordNode = memo(({ data, selected }: NodeProps) => {
  const d = data as unknown as RecordNodeData;
  const colors = TYPE_COLORS[d.recordType] || TYPE_COLORS["domain"];
  const truncatedLabel = d.label.length > 32 ? d.label.substring(0, 29) + "..." : d.label;

  return (
    <div className="relative group cursor-pointer">
      {/* Selection glow */}
      {selected && (
        <div className={`absolute -inset-1.5 rounded-xl ${colors.ring} ring-2 ring-inset opacity-80 animate-pulse`} />
      )}

      {/* Main body */}
      <div className={`
        relative flex items-center gap-2.5 px-3.5 py-2 rounded-xl border backdrop-blur-lg shadow-sm
        ${colors.bg} ${colors.border}
        transition-all duration-300 min-w-[120px] max-w-[280px]
        ${selected ? "shadow-lg scale-105 border-primary/50" : "hover:shadow-md hover:scale-[1.02]"}
      `}>
        {/* Icon */}
        <div className={`shrink-0 flex items-center justify-center h-7 w-7 rounded-lg ${colors.bg} ${colors.text} border ${colors.border}`}>
          {typeIcon(d.recordType, "h-3.5 w-3.5")}
        </div>

        {/* Text */}
        <div className="flex flex-col min-w-0">
          <span className={`text-[11px] font-bold font-mono leading-tight truncate ${colors.text}`}>
            {truncatedLabel}
          </span>
          <span className="text-[8px] font-bold uppercase tracking-widest text-muted-foreground/50 mt-0.5">
            {d.recordType} RECORD
          </span>
        </div>

        {/* Resolved IP expansion badge for subdomains */}
        {d.hasIps && (
          <div className="ml-auto shrink-0 pl-1">
            {d.isExpanded ? (
              <span className="text-[8px] font-extrabold font-mono px-1 py-0.5 rounded bg-orange-500/10 border border-orange-500/20 text-orange-400/90 hover:bg-orange-500/20">
                - {d.ipCount} IP{d.ipCount! > 1 ? "s" : ""}
              </span>
            ) : (
              <span className="text-[8px] font-extrabold font-mono px-1 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400/90 hover:bg-emerald-500/20 animate-pulse">
                + {d.ipCount} IP{d.ipCount! > 1 ? "s" : ""}
              </span>
            )}
          </div>
        )}
      </div>

      {/* Incoming handle */}
      <Handle type="target" position={Position.Left} className="!w-0 !h-0 !border-0 !bg-transparent" />
      <Handle type="target" position={Position.Top} className="!w-0 !h-0 !border-0 !bg-transparent" id="top" />
      <Handle type="target" position={Position.Bottom} className="!w-0 !h-0 !border-0 !bg-transparent" id="bottom" />
      <Handle type="target" position={Position.Right} className="!w-0 !h-0 !border-0 !bg-transparent" id="right" />
    </div>
  );
});
RecordNode.displayName = "RecordNode";

// ── Group Header Node (optional category label) ──────────
export type GroupNodeData = { label: string; recordType: string; count: number; isExpanded?: boolean; };

export const GroupNode = memo(({ data, selected }: NodeProps) => {
  const d = data as unknown as GroupNodeData;
  const colors = TYPE_COLORS[d.recordType] || TYPE_COLORS["domain"];

  return (
    <div className="relative group cursor-pointer">
      <div className={`
        relative flex items-center gap-2 px-3 py-1.5 rounded-full border backdrop-blur-lg shadow-sm
        ${colors.bg} ${colors.border}
        transition-all duration-300
        ${selected ? "shadow-lg scale-105 border-primary/50" : "hover:shadow-md hover:scale-[1.02]"}
      `}>
        <div className={`h-2 w-2 rounded-full ${colors.dot}`} />
        <span className={`text-[10px] font-extrabold uppercase tracking-wider ${colors.text}`}>
          {d.recordType}
        </span>
        <span className="text-[9px] font-bold text-muted-foreground/50">
          ({d.count})
        </span>

        {/* Expand / Collapse Toggle Badge */}
        {d.isExpanded ? (
          <span className="text-[8px] font-extrabold font-mono px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400/90 ml-1">
            COLLAPSE
          </span>
        ) : (
          <span className="text-[8px] font-extrabold font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400/90 ml-1 animate-pulse">
            EXPAND
          </span>
        )}
      </div>

      <Handle type="target" position={Position.Left} className="!w-0 !h-0 !border-0 !bg-transparent" />
      <Handle type="source" position={Position.Right} className="!w-0 !h-0 !border-0 !bg-transparent" />
      <Handle type="target" position={Position.Top} className="!w-0 !h-0 !border-0 !bg-transparent" id="top" />
      <Handle type="source" position={Position.Bottom} className="!w-0 !h-0 !border-0 !bg-transparent" id="bottom" />
    </div>
  );
});
GroupNode.displayName = "GroupNode";

// ── Export node types map for ReactFlow ───────────────────
export const dnsNodeTypes = {
  domainNode: DomainNode,
  recordNode: RecordNode,
  groupNode: GroupNode,
};
