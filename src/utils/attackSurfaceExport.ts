import type ExcelJS from "exceljs";
import type { AttackSurfaceResponse, AttackSurfaceRisk } from "@/services/threatApi";

const INK = "0F172A";
const BRAND = "2563EB";
const RISK_HEX: Record<AttackSurfaceRisk, string> = {
  critical: "DC2626",
  high: "EA580C",
  medium: "CA8A04",
  low: "16A34A",
};

export interface ExcelWorkbookFactory {
  Workbook: new () => ExcelJS.Workbook;
};

const headerFill = (worksheet: ExcelJS.Worksheet, rowNumber: number, lastCol: number, color = INK) => {
  const row = worksheet.getRow(rowNumber);
  for (let column = 1; column <= lastCol; column += 1) {
    const cell = row.getCell(column);
    cell.font = { bold: true, color: { argb: "FFFFFFFF" } };
    cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: `FF${color}` } };
    cell.alignment = { vertical: "middle" };
    cell.border = { bottom: { style: "thin", color: { argb: "FFCBD5E1" } } };
  }
  row.height = 20;
};

export function buildAttackSurfaceWorkbook(
  result: AttackSurfaceResponse,
  ExcelLib: ExcelWorkbookFactory,
): ExcelJS.Workbook {
  const workbook = new ExcelLib.Workbook();
  workbook.creator = "ThreatSumm4ry";
  workbook.created = new Date();

  const overview = workbook.addWorksheet("Overview", { properties: { tabColor: { argb: `FF${BRAND}` } } });
  overview.mergeCells("A1:D1");
  overview.getCell("A1").value = "ThreatSumm4ry Attack Surface";
  overview.getCell("A1").font = { bold: true, size: 18, color: { argb: `FF${INK}` } };
  overview.mergeCells("A2:D2");
  overview.getCell("A2").value = `Generated ${result.generatedAt} - Query ${result.query}`;
  overview.getCell("A2").font = { size: 10, color: { argb: "FF64748B" } };
  overview.getRow(4).values = ["Metric", "Value"];
  headerFill(overview, 4, 2);
  [
    ["Query kind", result.queryKind],
    ["Limit", result.limit],
    ["Active validation", result.activeValidation ? "Yes" : "No"],
    ["Assets", result.summary.totalAssets],
    ["Services", result.summary.totalServices],
    ["Critical / High", result.summary.criticalHighFindings],
    ["TCP open", result.summary.activelyConfirmedOpen],
    ["Warnings", result.warnings.join(" | ") || "-"],
  ].forEach((row) => overview.addRow(row));
  overview.getColumn(1).width = 24;
  overview.getColumn(2).width = 70;

  const findings = workbook.addWorksheet("Findings", {
    properties: { tabColor: { argb: `FF${INK}` } },
    views: [{ state: "frozen", ySplit: 1 }],
  });
  const columns = [
    { header: "Risk", key: "risk", width: 12 },
    { header: "Score", key: "riskScore", width: 8 },
    { header: "IP", key: "ip", width: 16 },
    { header: "Port", key: "port", width: 8 },
    { header: "Transport", key: "transport", width: 10 },
    { header: "Service", key: "service", width: 18 },
    { header: "Product", key: "product", width: 22 },
    { header: "Version", key: "version", width: 18 },
    { header: "CVEs", key: "cves", width: 34 },
    { header: "Organization", key: "organization", width: 28 },
    { header: "ASN", key: "asn", width: 14 },
    { header: "Location", key: "location", width: 24 },
    { header: "Sources", key: "sources", width: 18 },
    { header: "Observed", key: "observedAt", width: 24 },
    { header: "TCP", key: "validation", width: 18 },
    { header: "Reasons", key: "riskReasons", width: 60 },
  ];
  findings.columns = columns;
  headerFill(findings, 1, columns.length);
  result.findings.forEach((finding) => {
    const row = findings.addRow({
      risk: finding.risk,
      riskScore: finding.riskScore,
      ip: finding.ip,
      port: finding.port,
      transport: finding.transport,
      service: finding.service || "",
      product: finding.product || "",
      version: finding.version || "",
      cves: finding.cves.join(", "),
      organization: finding.organization || "",
      asn: finding.asn || "",
      location: [finding.city, finding.country].filter(Boolean).join(", "),
      sources: [finding.source.shodan && "Shodan", finding.source.censys && "Censys"].filter(Boolean).join(", "),
      observedAt: finding.observedAt || "",
      validation: finding.validation.status,
      riskReasons: finding.riskReasons.join(" | "),
    });
    row.getCell("risk").font = { bold: true, color: { argb: `FF${RISK_HEX[finding.risk]}` } };
  });
  findings.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: columns.length } };

  const risks = workbook.addWorksheet("Risk Summary");
  risks.getRow(1).values = ["Risk", "Count"];
  headerFill(risks, 1, 2, BRAND);
  (["critical", "high", "medium", "low"] as AttackSurfaceRisk[]).forEach((risk) => {
    const row = risks.addRow([risk, result.summary.byRisk[risk] || 0]);
    row.getCell(1).font = { bold: true, color: { argb: `FF${RISK_HEX[risk]}` } };
  });
  risks.getColumn(1).width = 14;
  risks.getColumn(2).width = 12;

  return workbook;
}
