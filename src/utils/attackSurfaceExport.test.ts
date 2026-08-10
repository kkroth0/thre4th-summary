import test from "node:test";
import assert from "node:assert/strict";
import { buildAttackSurfaceWorkbook, type ExcelWorkbookFactory } from "./attackSurfaceExport.ts";
import type { AttackSurfaceFinding, AttackSurfaceResponse } from "@/services/threatApi";

class FakeCell {
  value: unknown = undefined;
  font: unknown = undefined;
  fill: unknown = undefined;
  alignment: unknown = undefined;
  border: unknown = undefined;
}

class FakeRow {
  cells = new Map<number | string, FakeCell>();
  height = 0;
  alignment: unknown = undefined;

  set values(values: unknown[]) {
    values.forEach((value, index) => {
      this.getCell(index + 1).value = value;
    });
  }

  getCell(key: number | string) {
    if (!this.cells.has(key)) this.cells.set(key, new FakeCell());
    return this.cells.get(key)!;
  }
}

class FakeWorksheet {
  columns: { header: string; key: string; width: number }[] = [];
  rows = new Map<number, FakeRow>();
  autoFilter: unknown = undefined;
  conditionalFormats: { ref: string }[] = [];

  constructor(public name: string) {}

  mergeCells() {}

  getCell(address: string) {
    return this.getRow(1).getCell(address);
  }

  getRow(rowNumber: number) {
    if (!this.rows.has(rowNumber)) this.rows.set(rowNumber, new FakeRow());
    return this.rows.get(rowNumber)!;
  }

  addRow(values: Record<string, unknown> | unknown[]) {
    const row = this.getRow(this.rows.size + 1);
    if (Array.isArray(values)) {
      row.values = values;
    } else {
      this.columns.forEach((column, index) => {
        row.getCell(index + 1).value = values[column.key];
        row.getCell(column.key).value = values[column.key];
      });
    }
    return row;
  }

  eachRow(callback: (row: FakeRow, rowNumber: number) => void) {
    Array.from(this.rows.entries())
      .sort(([a], [b]) => a - b)
      .forEach(([rowNumber, row]) => callback(row, rowNumber));
  }

  getColumn() {
    return { width: 0, numFmt: "" };
  }

  addConditionalFormatting(format: { ref: string }) {
    this.conditionalFormats.push(format);
  }
}

class FakeWorkbook {
  creator = "";
  created: Date | null = null;
  worksheets: FakeWorksheet[] = [];

  addWorksheet(name: string) {
    const worksheet = new FakeWorksheet(name);
    this.worksheets.push(worksheet);
    return worksheet;
  }

  getWorksheet(name: string) {
    return this.worksheets.find((worksheet) => worksheet.name === name);
  }
}

const FakeExcelLib = { Workbook: FakeWorkbook } as unknown as ExcelWorkbookFactory;

const finding = (overrides: Partial<AttackSurfaceFinding> = {}): AttackSurfaceFinding => ({
  id: "finding-1",
  ip: "8.8.8.8",
  port: 443,
  transport: "tcp",
  risk: "critical",
  riskScore: 95,
  riskReasons: ["Known vulnerabilities reported: CVE-2026-0001"],
  service: "https",
  product: "nginx",
  version: "1.25",
  organization: "Example",
  asn: "AS15169",
  hostnames: ["example.com"],
  country: "US",
  city: "Mountain View",
  source: { shodan: true, censys: false },
  observedAt: "2026-07-13T11:04:05.000Z",
  cves: ["CVE-2026-0001"],
  tags: ["cloud"],
  bannerSnippet: "nginx",
  validation: { attempted: true, status: "open", detail: "TCP connection accepted" },
  sourceQuery: "ip:8.8.8.8",
  ...overrides,
});

const response = (findings: AttackSurfaceFinding[]): AttackSurfaceResponse => ({
  generatedAt: "2026-07-13T12:00:00.000Z",
  query: "net:\"8.8.8.0/24\"",
  queryKind: "search",
  limit: 50,
  activeValidation: true,
  warnings: [],
  summary: {
    totalAssets: 1,
    totalServices: findings.length,
    criticalHighFindings: findings.filter((item) => item.risk === "critical" || item.risk === "high").length,
    activelyConfirmedOpen: 1,
    byRisk: {
      critical: findings.filter((item) => item.risk === "critical").length,
      high: 0,
      medium: 0,
      low: findings.filter((item) => item.risk === "low").length,
    },
    providers: { shodan: true, censys: false },
    warnings: [],
    totalObserved: findings.length,
  },
  findings,
});

const build = (findings: AttackSurfaceFinding[], investida?: string) =>
  buildAttackSurfaceWorkbook(response(findings), FakeExcelLib, { investida }) as unknown as FakeWorkbook;

test("Base de dados follows the EY reference columns, in PT-BR", () => {
  const workbook = build([finding()], "Auren");
  const sheet = workbook.getWorksheet("Base de dados")!;

  assert.deepEqual(sheet.columns.map((column) => column.header), [
    "Investida",
    "Data da Varredura",
    "Query",
    "Grau de Exposição",
    "IP",
    "Porta",
    "Serviço",
    "Observação",
    "ASN",
    "Hostnames",
    "Organização",
    "País",
    "Banner",
    "Validação TCP (Ativa)",
    "Detalhe Validação",
  ]);

  const row = sheet.getRow(2);
  assert.equal(row.getCell(1).value, "Auren");
  assert.equal(row.getCell(2).value, "13/07/2026 11:04:05 UTC");
  assert.equal(row.getCell(3).value, "ip:8.8.8.8");
  assert.equal(row.getCell(4).value, "Crítico");
  assert.equal(row.getCell(6).value, 443);
  assert.equal(row.getCell(7).value, "nginx");
  assert.equal(row.getCell(8).value, "Vulnerabilidades conhecidas: CVE-2026-0001");
  assert.equal(row.getCell(14).value, "Sim");
  assert.equal(row.getCell(15).value, "Conexão TCP Aceita (Porta Aberta)");

  const header = sheet.getRow(1).getCell(1);
  assert.deepEqual(header.fill, { type: "pattern", pattern: "solid", fgColor: { argb: "FFC00000" } });
  assert.equal(sheet.getRow(1).height, 18.5);
});

test("translates risk reasons and validation states without touching technical terms", () => {
  const sheet = build([
    finding({ riskReasons: ["SSH exposed"], validation: { attempted: true, status: "timeout", detail: "TCP connection timed out" } }),
    finding({
      id: "finding-2",
      port: 161,
      transport: "udp",
      risk: "low",
      riskReasons: ["Service has no high-risk rule match"],
      cves: [],
      validation: { attempted: false, status: "udp_not_supported", detail: "UDP service" },
    }),
    finding({
      id: "finding-3",
      port: 8080,
      risk: "low",
      riskReasons: ["Alternative HTTP port exposed"],
      cves: [],
      validation: { attempted: true, status: "error", detail: "TCP validation failed: ECONNRESET" },
    }),
  ]).getWorksheet("Base de dados")!;

  assert.equal(sheet.getRow(2).getCell(8).value, "SSH exposto");
  assert.equal(sheet.getRow(2).getCell(15).value, "Falha TCP (Tempo Esgotado)");
  assert.equal(sheet.getRow(3).getCell(8).value, "Serviço não classificado como de alto risco.");
  assert.equal(sheet.getRow(3).getCell(14).value, "N/A (UDP)");
  assert.equal(sheet.getRow(4).getCell(8).value, "Porta alternativa HTTP");
  assert.equal(sheet.getRow(4).getCell(15).value, "Falha TCP (Código: ECONNRESET)");
});

test("CVE sheet appears only when there are CVEs", () => {
  const withCves = build([finding()]);
  assert.deepEqual(withCves.worksheets.map((sheet) => sheet.name), ["Base de dados", "CVEs", "Gráficos"]);
  assert.equal(withCves.getWorksheet("CVEs")?.getRow(2).getCell(3).value, "CVE-2026-0001");

  const withoutCves = build([finding({ cves: [], riskReasons: ["SSH exposed"] })]);
  assert.deepEqual(withoutCves.worksheets.map((sheet) => sheet.name), ["Base de dados", "Gráficos"]);
});

test("chart sheet carries the risk distribution with data bars", () => {
  const charts = build([finding(), finding({ id: "finding-2", risk: "low", cves: [] })]).getWorksheet("Gráficos")!;

  assert.equal(charts.getRow(1).getCell(1).value, "Distribuição por Grau de Exposição");
  assert.equal(charts.getRow(2).getCell(1).value, "Grau de Exposição");
  assert.equal(charts.getRow(3).getCell(1).value, "Crítico");
  assert.equal(charts.getRow(3).getCell(2).value, 1);
  assert.equal(charts.getRow(3).getCell(3).value, 50);
  assert.equal(charts.getRow(6).getCell(1).value, "Baixo");
  assert.ok(charts.conditionalFormats.some((format) => format.ref === "B3:B6"));
  assert.ok(charts.conditionalFormats.length >= 5);
});
