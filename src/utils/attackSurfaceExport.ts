import type ExcelJS from "exceljs";
import type { AttackSurfaceFinding, AttackSurfaceResponse, AttackSurfaceRisk } from "@/services/threatApi";

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

type ExportColumn = {
  header: string;
  key: string;
  width: number;
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

const serviceKey = (finding: AttackSurfaceFinding) => `${finding.ip}:${finding.port}/${finding.transport}`;

const sources = (finding: AttackSurfaceFinding) => [
  finding.source.shodan && "Shodan",
].filter(Boolean).join(", ");

const percent = (part: number, total: number) => (total > 0 ? Number(((part / total) * 100).toFixed(1)) : 0);

const addStructuredSheet = (
  workbook: ExcelJS.Workbook,
  name: string,
  columns: ExportColumn[],
  rows: Record<string, unknown>[],
  tabColor = INK,
) => {
  const worksheet = workbook.addWorksheet(name, {
    properties: { tabColor: { argb: `FF${tabColor}` } },
    views: [{ state: "frozen", ySplit: 1 }],
  });
  worksheet.columns = columns;
  headerFill(worksheet, 1, columns.length, tabColor);
  rows.forEach((row) => worksheet.addRow(row));
  worksheet.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: columns.length } };
  worksheet.eachRow((row, rowNumber) => {
    if (rowNumber === 1) return;
    row.alignment = { vertical: "top", wrapText: true };
  });
  return worksheet;
};

const buildAssets = (findings: AttackSurfaceFinding[]) => {
  const assets = new Map<string, {
    ip: string;
    serviceCount: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    maxScore: number;
    organization: Set<string>;
    asn: Set<string>;
    country: Set<string>;
    city: Set<string>;
    hostnames: Set<string>;
    sources: Set<string>;
  }>();

  findings.forEach((finding) => {
    if (!assets.has(finding.ip)) {
      assets.set(finding.ip, {
        ip: finding.ip,
        serviceCount: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        maxScore: 0,
        organization: new Set(),
        asn: new Set(),
        country: new Set(),
        city: new Set(),
        hostnames: new Set(),
        sources: new Set(),
      });
    }
    const asset = assets.get(finding.ip)!;
    asset.serviceCount += 1;
    asset[finding.risk] += 1;
    asset.maxScore = Math.max(asset.maxScore, finding.riskScore);
    if (finding.organization) asset.organization.add(finding.organization);
    if (finding.asn) asset.asn.add(finding.asn);
    if (finding.country) asset.country.add(finding.country);
    if (finding.city) asset.city.add(finding.city);
    finding.hostnames.forEach((hostname) => asset.hostnames.add(hostname));
    if (finding.source.shodan) asset.sources.add("Shodan");
  });

  return Array.from(assets.values()).map((asset) => ({
    ip: asset.ip,
    serviceCount: asset.serviceCount,
    critical: asset.critical,
    high: asset.high,
    medium: asset.medium,
    low: asset.low,
    maxScore: asset.maxScore,
    organization: Array.from(asset.organization).join(", "),
    asn: Array.from(asset.asn).join(", "),
    country: Array.from(asset.country).join(", "),
    city: Array.from(asset.city).join(", "),
    hostnames: Array.from(asset.hostnames).join(", "),
    sources: Array.from(asset.sources).join(", "),
  }));
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
  const columns: ExportColumn[] = [
    { header: "Finding ID", key: "id", width: 30 },
    { header: "Service Key", key: "serviceKey", width: 24 },
    { header: "Risk", key: "risk", width: 12 },
    { header: "Score", key: "riskScore", width: 8 },
    { header: "IP", key: "ip", width: 16 },
    { header: "Port", key: "port", width: 8 },
    { header: "Transport", key: "transport", width: 10 },
    { header: "Service", key: "service", width: 18 },
    { header: "Product", key: "product", width: 22 },
    { header: "Version", key: "version", width: 18 },
    { header: "Organization", key: "organization", width: 28 },
    { header: "ASN", key: "asn", width: 14 },
    { header: "Country", key: "country", width: 16 },
    { header: "City", key: "city", width: 20 },
    { header: "Sources", key: "sources", width: 18 },
    { header: "Observed", key: "observedAt", width: 24 },
    { header: "TCP Status", key: "validation", width: 18 },
    { header: "Risk Reason Count", key: "riskReasonCount", width: 18 },
    { header: "CVE Count", key: "cveCount", width: 12 },
    { header: "Hostname Count", key: "hostnameCount", width: 16 },
    { header: "Tag Count", key: "tagCount", width: 12 },
  ];
  findings.columns = columns;
  headerFill(findings, 1, columns.length);
  result.findings.forEach((finding) => {
    const row = findings.addRow({
      id: finding.id,
      serviceKey: serviceKey(finding),
      risk: finding.risk,
      riskScore: finding.riskScore,
      ip: finding.ip,
      port: finding.port,
      transport: finding.transport,
      service: finding.service || "",
      product: finding.product || "",
      version: finding.version || "",
      organization: finding.organization || "",
      asn: finding.asn || "",
      country: finding.country || "",
      city: finding.city || "",
      sources: sources(finding),
      observedAt: finding.observedAt || "",
      validation: finding.validation.status,
      riskReasonCount: finding.riskReasons.length,
      cveCount: finding.cves.length,
      hostnameCount: finding.hostnames.length,
      tagCount: finding.tags.length,
    });
    row.getCell("risk").font = { bold: true, color: { argb: `FF${RISK_HEX[finding.risk]}` } };
  });
  findings.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: columns.length } };
  findings.eachRow((row, rowNumber) => {
    if (rowNumber > 1) row.alignment = { vertical: "top", wrapText: true };
  });

  addStructuredSheet(
    workbook,
    "Assets",
    [
      { header: "IP", key: "ip", width: 16 },
      { header: "Service Count", key: "serviceCount", width: 14 },
      { header: "Critical", key: "critical", width: 10 },
      { header: "High", key: "high", width: 10 },
      { header: "Medium", key: "medium", width: 10 },
      { header: "Low", key: "low", width: 10 },
      { header: "Max Score", key: "maxScore", width: 10 },
      { header: "Organization", key: "organization", width: 28 },
      { header: "ASN", key: "asn", width: 14 },
      { header: "Country", key: "country", width: 16 },
      { header: "City", key: "city", width: 20 },
      { header: "Hostnames", key: "hostnames", width: 40 },
      { header: "Sources", key: "sources", width: 18 },
    ],
    buildAssets(result.findings),
    BRAND,
  );

  addStructuredSheet(
    workbook,
    "Services",
    [
      { header: "Finding ID", key: "id", width: 30 },
      { header: "Service Key", key: "serviceKey", width: 24 },
      { header: "IP", key: "ip", width: 16 },
      { header: "Port", key: "port", width: 8 },
      { header: "Transport", key: "transport", width: 10 },
      { header: "Risk", key: "risk", width: 12 },
      { header: "Service", key: "service", width: 18 },
      { header: "Product", key: "product", width: 22 },
      { header: "Version", key: "version", width: 18 },
      { header: "Organization", key: "organization", width: 28 },
      { header: "ASN", key: "asn", width: 14 },
      { header: "Sources", key: "sources", width: 18 },
      { header: "Observed", key: "observedAt", width: 24 },
    ],
    result.findings.map((finding) => ({
      id: finding.id,
      serviceKey: serviceKey(finding),
      ip: finding.ip,
      port: finding.port,
      transport: finding.transport,
      risk: finding.risk,
      service: finding.service || "",
      product: finding.product || "",
      version: finding.version || "",
      organization: finding.organization || "",
      asn: finding.asn || "",
      sources: sources(finding),
      observedAt: finding.observedAt || "",
    })),
  );

  addStructuredSheet(
    workbook,
    "CVEs",
    [
      { header: "Finding ID", key: "id", width: 30 },
      { header: "Service Key", key: "serviceKey", width: 24 },
      { header: "IP", key: "ip", width: 16 },
      { header: "Port", key: "port", width: 8 },
      { header: "CVE", key: "cve", width: 18 },
      { header: "Risk", key: "risk", width: 12 },
      { header: "Product", key: "product", width: 22 },
      { header: "Version", key: "version", width: 18 },
    ],
    result.findings.flatMap((finding) => finding.cves.map((cve) => ({
      id: finding.id,
      serviceKey: serviceKey(finding),
      ip: finding.ip,
      port: finding.port,
      cve,
      risk: finding.risk,
      product: finding.product || "",
      version: finding.version || "",
    }))),
    RISK_HEX.critical,
  );

  addStructuredSheet(
    workbook,
    "Hostnames",
    [
      { header: "Finding ID", key: "id", width: 30 },
      { header: "Service Key", key: "serviceKey", width: 24 },
      { header: "IP", key: "ip", width: 16 },
      { header: "Port", key: "port", width: 8 },
      { header: "Hostname", key: "hostname", width: 36 },
    ],
    result.findings.flatMap((finding) => finding.hostnames.map((hostname) => ({
      id: finding.id,
      serviceKey: serviceKey(finding),
      ip: finding.ip,
      port: finding.port,
      hostname,
    }))),
    BRAND,
  );

  addStructuredSheet(
    workbook,
    "Tags",
    [
      { header: "Finding ID", key: "id", width: 30 },
      { header: "Service Key", key: "serviceKey", width: 24 },
      { header: "IP", key: "ip", width: 16 },
      { header: "Port", key: "port", width: 8 },
      { header: "Tag", key: "tag", width: 24 },
      { header: "Risk", key: "risk", width: 12 },
    ],
    result.findings.flatMap((finding) => finding.tags.map((tag) => ({
      id: finding.id,
      serviceKey: serviceKey(finding),
      ip: finding.ip,
      port: finding.port,
      tag,
      risk: finding.risk,
    }))),
    BRAND,
  );

  addStructuredSheet(
    workbook,
    "Evidence",
    [
      { header: "Finding ID", key: "id", width: 30 },
      { header: "Service Key", key: "serviceKey", width: 24 },
      { header: "IP", key: "ip", width: 16 },
      { header: "Port", key: "port", width: 8 },
      { header: "Evidence Type", key: "type", width: 16 },
      { header: "Evidence", key: "evidence", width: 90 },
    ],
    result.findings.flatMap((finding) => [
      ...finding.riskReasons.map((reason) => ({
        id: finding.id,
        serviceKey: serviceKey(finding),
        ip: finding.ip,
        port: finding.port,
        type: "risk_reason",
        evidence: reason,
      })),
      ...(finding.bannerSnippet ? [{
        id: finding.id,
        serviceKey: serviceKey(finding),
        ip: finding.ip,
        port: finding.port,
        type: "banner",
        evidence: finding.bannerSnippet,
      }] : []),
    ]),
  );

  addStructuredSheet(
    workbook,
    "Validation",
    [
      { header: "Finding ID", key: "id", width: 30 },
      { header: "Service Key", key: "serviceKey", width: 24 },
      { header: "IP", key: "ip", width: 16 },
      { header: "Port", key: "port", width: 8 },
      { header: "Attempted", key: "attempted", width: 12 },
      { header: "Status", key: "status", width: 18 },
      { header: "Detail", key: "detail", width: 60 },
    ],
    result.findings.map((finding) => ({
      id: finding.id,
      serviceKey: serviceKey(finding),
      ip: finding.ip,
      port: finding.port,
      attempted: finding.validation.attempted,
      status: finding.validation.status,
      detail: finding.validation.detail || "",
    })),
  );

  const risks = workbook.addWorksheet("Risk Summary");
  risks.getRow(1).values = ["Risk", "Count", "Percent"];
  headerFill(risks, 1, 3, BRAND);
  (["critical", "high", "medium", "low"] as AttackSurfaceRisk[]).forEach((risk) => {
    const count = result.summary.byRisk[risk] || 0;
    const row = risks.addRow([risk, count, percent(count, result.summary.totalServices)]);
    row.getCell(1).font = { bold: true, color: { argb: `FF${RISK_HEX[risk]}` } };
  });
  risks.getColumn(1).width = 14;
  risks.getColumn(2).width = 12;
  risks.getColumn(3).width = 12;

  addStructuredSheet(
    workbook,
    "Warnings",
    [{ header: "Warning", key: "warning", width: 120 }],
    result.warnings.map((warning) => ({ warning })),
    RISK_HEX.medium,
  );

  return workbook;
}
