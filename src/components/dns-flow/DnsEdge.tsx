import { BaseEdge, getSmoothStepPath, type EdgeProps } from "@xyflow/react";
import { TYPE_COLORS } from "./DnsNodes";

export function DnsEdge(props: EdgeProps) {
  const { sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data } = props;
  const recordType = (data as any)?.recordType || "domain";
  const colors = TYPE_COLORS[recordType] || TYPE_COLORS["domain"];

  const [edgePath] = getSmoothStepPath({
    sourceX, sourceY, targetX, targetY,
    sourcePosition, targetPosition,
    borderRadius: 16,
  });

  return (
    <BaseEdge
      {...props}
      path={edgePath}
      style={{
        stroke: `var(--edge-color-${recordType}, hsl(var(--primary) / 0.3))`,
        strokeWidth: 1.5,
        strokeDasharray: recordType === "TXT" ? "4 3" : undefined,
      }}
    />
  );
}

export const dnsEdgeTypes = { dnsEdge: DnsEdge };
