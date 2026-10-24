import type ExcelJS from "exceljs";
import type { AttackSurfaceFinding, AttackSurfaceResponse, AttackSurfaceRisk } from "@/services/threatApi";

// Padrão do relatório, igual ao modelo entregue ao cliente: cabeçalho vermelho escuro,
// Calibri 14 em branco, borda fina, linha congelada e autofiltro. Nada de cor
// nas linhas de dados — quem lê filtra pela coluna "Grau de Exposição".
const HEADER_FILL = "C00000";
const BORDER = { style: "thin" as const };
const HEADER_BORDER = { top: BORDER, left: BORDER, bottom: BORDER, right: BORDER };

export interface ExcelWorkbookFactory {
  Workbook: new () => ExcelJS.Workbook;
};

export interface AttackSurfaceExportOptions {
  /** Nome da investida avaliada; vai em toda linha, como no modelo. */
  investida?: string;
}

type ExportColumn = { header: string; key: string; width: number };

const RISK_PT: Record<AttackSurfaceRisk, string> = {
  critical: "Crítico",
  high: "Alto",
  medium: "Médio",
  low: "Baixo",
};

const RISK_ORDER: AttackSurfaceRisk[] = ["critical", "high", "medium", "low"];

// As razões vêm do backend em inglês e são frases fechadas (server/attackSurface.js).
// Traduzir aqui mantém a API estável e o relatório em PT-BR, sem mexer nos
// termos técnicos (SSH, RDP, HTTP, CVE seguem como estão).
const REASON_PT: Record<string, string> = {
  "Telnet exposed": "Telnet exposto",
  "SMB exposed": "SMB exposto",
  "RDP exposed": "RDP exposto",
  "FTP exposed": "FTP exposto",
  "SSH exposed": "SSH exposto",
  "MSSQL exposed": "MSSQL exposto",
  "MySQL exposed": "MySQL exposto",
  "VNC exposed": "VNC exposto",
  "SMTP exposed": "SMTP exposto",
  "Alternative HTTP port exposed": "Porta alternativa HTTP",
  "Alternative HTTPS port exposed": "Porta alternativa HTTPS",
  "Admin-like web service exposed": "Serviço web administrativo exposto",
  "Standard web service exposed": "Porta web padrão.",
  "Service has no high-risk rule match": "Serviço não classificado como de alto risco.",
};

const reasonPt = (reason: string) => {
  const known = reason.match(/^Known vulnerabilities reported: (.+)$/);
  if (known) return `Vulnerabilidades conhecidas: ${known[1]}`;
  return REASON_PT[reason] || reason;
};

const VALIDATION_PT: Record<string, { status: string; detail: string }> = {
  open: { status: "Sim", detail: "Conexão TCP Aceita (Porta Aberta)" },
  closed: { status: "Não", detail: "Falha TCP (Conexão Recusada)" },
  timeout: { status: "Não", detail: "Falha TCP (Tempo Esgotado)" },
  udp_not_supported: { status: "N/A (UDP)", detail: "Serviço UDP - Validação ativa não suportada" },
  not_requested: { status: "N/A", detail: "Validação ativa não solicitada" },
};

const validationPt = (finding: AttackSurfaceFinding) => {
  const known = VALIDATION_PT[finding.validation.status];
  if (known) return known;
  // Só sobra `error`: o backend manda "TCP validation failed: ECONNRESET".
  const code = (finding.validation.detail || "").match(/failed: (\S+)/);
  return { status: "Não", detail: code ? `Falha TCP (Código: ${code[1]})` : "Falha TCP" };
};

// "27/07/2026 00:57:47 UTC", como no modelo. Sempre UTC: o Shodan carimba em
// UTC e o relatório circula entre fusos.
const scanDate = (value: string | null) => {
  if (!value) return "N/A";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const iso = date.toISOString();
  return `${iso.slice(8, 10)}/${iso.slice(5, 7)}/${iso.slice(0, 4)} ${iso.slice(11, 19)} UTC`;
};

const serviceName = (finding: AttackSurfaceFinding) => finding.product || finding.service || "N/A";

const applyHeader = (worksheet: ExcelJS.Worksheet, rowNumber: number, lastColumn: number) => {
  const row = worksheet.getRow(rowNumber);
  for (let column = 1; column <= lastColumn; column += 1) {
    const cell = row.getCell(column);
    cell.font = { name: "Calibri", bold: true, size: 14, color: { argb: "FFFFFFFF" } };
    cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: `FF${HEADER_FILL}` } };
    cell.alignment = { horizontal: "left", vertical: "top" };
    cell.border = HEADER_BORDER;
  }
  row.height = 18.5;
};

const addSheet = (
  workbook: ExcelJS.Workbook,
  name: string,
  columns: ExportColumn[],
  rows: Record<string, unknown>[],
) => {
  const worksheet = workbook.addWorksheet(name, {
    properties: { tabColor: { argb: `FF${HEADER_FILL}` } },
    views: [{ state: "frozen", ySplit: 1 }],
  });
  worksheet.columns = columns;
  applyHeader(worksheet, 1, columns.length);
  rows.forEach((row) => worksheet.addRow(row));
  worksheet.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: columns.length } };
  return worksheet;
};

// Contagem por chave, maiores primeiro, cortada no topo N.
const rankBy = (findings: AttackSurfaceFinding[], key: (finding: AttackSurfaceFinding) => string, top: number) => {
  const counts = new Map<string, number>();
  findings.forEach((finding) => {
    const value = key(finding);
    if (!value) return;
    counts.set(value, (counts.get(value) || 0) + 1);
  });
  return Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, top);
};

const percent = (part: number, total: number) => (total > 0 ? Number(((part / total) * 100).toFixed(1)) : 0);

// ponytail: o ExcelJS não escreve gráfico nativo do Excel, então "gráfico" aqui
// é barra de dados condicional — nativa, imprime e acompanha o filtro. Trocar
// por gráfico de verdade exige outra biblioteca de xlsx.
const addChartBlock = (
  worksheet: ExcelJS.Worksheet,
  title: string,
  labelHeader: string,
  entries: [string, number][],
  total: number,
  startRow: number,
) => {
  const titleCell = worksheet.getRow(startRow).getCell(1);
  titleCell.value = title;
  titleCell.font = { name: "Calibri", bold: true, size: 12, color: { argb: `FF${HEADER_FILL}` } };

  const headerRow = startRow + 1;
  worksheet.getRow(headerRow).values = [labelHeader, "Serviços", "%"];
  applyHeader(worksheet, headerRow, 3);

  entries.forEach(([label, count], index) => {
    worksheet.getRow(headerRow + 1 + index).values = [label, count, percent(count, total)];
  });

  const firstDataRow = headerRow + 1;
  const lastDataRow = headerRow + entries.length;
  if (entries.length > 0) {
    worksheet.addConditionalFormatting({
      ref: `B${firstDataRow}:B${lastDataRow}`,
      rules: [{
        type: "dataBar",
        // Prioridade única por bloco; o Excel reclama de regras empatadas.
        priority: startRow,
        // O ExcelJS escreve os cfvo direto no XML: sem min/max ele quebra na gravação.
        cfvo: [{ type: "min" }, { type: "max" }],
        color: { argb: `FF${HEADER_FILL}` },
      } as ExcelJS.DataBarRuleType],
    });
  }

  return lastDataRow + 2;
};

export function buildAttackSurfaceWorkbook(
  result: AttackSurfaceResponse,
  ExcelLib: ExcelWorkbookFactory,
  options: AttackSurfaceExportOptions = {},
): ExcelJS.Workbook {
  const workbook = new ExcelLib.Workbook();
  workbook.creator = "ThreatSumm4ry";
  workbook.created = new Date();

  const investida = options.investida?.trim() || "";
  const findings = result.findings;

  addSheet(
    workbook,
    "Base de dados",
    [
      { header: "Investida", key: "investida", width: 19 },
      { header: "Data da Varredura", key: "scanDate", width: 33.9 },
      { header: "Query", key: "query", width: 38.8 },
      { header: "Grau de Exposição", key: "risk", width: 25.7 },
      { header: "IP", key: "ip", width: 27.1 },
      { header: "Porta", key: "port", width: 15.5 },
      { header: "Serviço", key: "service", width: 21.5 },
      { header: "Observação", key: "note", width: 37 },
      { header: "ASN", key: "asn", width: 23.2 },
      { header: "Hostnames", key: "hostnames", width: 88.8 },
      { header: "Organização", key: "organization", width: 19.5 },
      { header: "País", key: "country", width: 11.8 },
      // O modelo traz 255 (autoajuste em cima de um banner gigante); 60 mantém
      // a coluna legível sem esconder nada — o texto continua inteiro na célula.
      { header: "Banner", key: "banner", width: 60 },
      { header: "Validação TCP (Ativa)", key: "validation", width: 18.7 },
      { header: "Detalhe Validação", key: "validationDetail", width: 29.8 },
    ],
    findings.map((finding) => {
      const validation = validationPt(finding);
      return {
        investida,
        scanDate: scanDate(finding.observedAt),
        query: finding.sourceQuery || result.query,
        risk: RISK_PT[finding.risk],
        ip: finding.ip,
        port: finding.port,
        service: serviceName(finding),
        note: finding.riskReasons.map(reasonPt).join(" "),
        asn: finding.asn || "",
        hostnames: finding.hostnames.join(", "),
        organization: finding.organization || "",
        country: finding.country || "",
        banner: finding.bannerSnippet || "",
        validation: validation.status,
        validationDetail: validation.detail,
      };
    }),
  );

  // Aba de CVEs só existe quando há CVE — planilha sem aba vazia.
  const cveRows = findings.flatMap((finding) => finding.cves.map((cve) => ({
    investida,
    scanDate: scanDate(finding.observedAt),
    cve,
    risk: RISK_PT[finding.risk],
    ip: finding.ip,
    port: finding.port,
    service: serviceName(finding),
    version: finding.version || "",
    organization: finding.organization || "",
    country: finding.country || "",
  })));

  if (cveRows.length > 0) {
    addSheet(
      workbook,
      "CVEs",
      [
        { header: "Investida", key: "investida", width: 19 },
        { header: "Data da Varredura", key: "scanDate", width: 33.9 },
        { header: "CVE", key: "cve", width: 20 },
        { header: "Grau de Exposição", key: "risk", width: 25.7 },
        { header: "IP", key: "ip", width: 27.1 },
        { header: "Porta", key: "port", width: 15.5 },
        { header: "Serviço", key: "service", width: 21.5 },
        { header: "Versão", key: "version", width: 18 },
        { header: "Organização", key: "organization", width: 19.5 },
        { header: "País", key: "country", width: 11.8 },
      ],
      cveRows,
    );
  }

  const charts = workbook.addWorksheet("Gráficos", {
    properties: { tabColor: { argb: `FF${HEADER_FILL}` } },
  });
  charts.getColumn(1).width = 46;
  charts.getColumn(2).width = 14;
  charts.getColumn(3).width = 10;

  const total = findings.length;
  let cursor = 1;
  cursor = addChartBlock(
    charts,
    "Distribuição por Grau de Exposição",
    "Grau de Exposição",
    RISK_ORDER.map((risk) => [RISK_PT[risk], result.summary.byRisk[risk] || 0] as [string, number]),
    total,
    cursor,
  );
  cursor = addChartBlock(charts, "Top 15 Portas", "Porta", rankBy(findings, (f) => String(f.port), 15), total, cursor);
  cursor = addChartBlock(charts, "Top 15 Serviços", "Serviço", rankBy(findings, serviceName, 15), total, cursor);
  cursor = addChartBlock(charts, "Top 15 Organizações", "Organização", rankBy(findings, (f) => f.organization || "", 15), total, cursor);
  cursor = addChartBlock(charts, "Top 15 Ativos por Serviços Expostos", "IP", rankBy(findings, (f) => f.ip, 15), total, cursor);
  if (cveRows.length > 0) {
    const cveCounts = new Map<string, number>();
    findings.forEach((finding) => finding.cves.forEach((cve) => cveCounts.set(cve, (cveCounts.get(cve) || 0) + 1)));
    const topCves = Array.from(cveCounts.entries())
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .slice(0, 15);
    addChartBlock(charts, "Top 15 CVEs", "CVE", topCves, cveRows.length, cursor);
  }

  return workbook;
}
