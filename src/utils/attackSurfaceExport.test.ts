import test from "node:test";
import assert from "node:assert/strict";
import { buildAttackSurfaceWorkbook, type ExcelWorkbookFactory } from "./attackSurfaceExport.ts";
import type { AttackSurfaceResponse } from "@/services/threatApi";

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
      if (index > 0) this.getCell(index).value = value;
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
      row.values = [undefined, ...values];
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

const sample: AttackSurfaceResponse = {
  generatedAt: "2026-07-13T12:00:00.000Z",
  query: "net:\"8.8.8.0/24\"",
  queryKind: "search",
  limit: 50,
  activeValidation: true,
  warnings: ["Censys unavailable"],
  summary: {
    totalAssets: 1,
    totalServices: 1,
    criticalHighFindings: 1,
    activelyConfirmedOpen: 1,
    byRisk: { critical: 1, high: 0, medium: 0, low: 0 },
    providers: { shodan: true, censys: false },
    warnings: ["Censys unavailable"],
    totalObserved: 1,
  },
  findings: [{
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
    observedAt: "2026-07-13T11:00:00.000Z",
    cves: ["CVE-2026-0001"],
    tags: ["cloud"],
    bannerSnippet: "nginx",
    validation: { attempted: true, status: "open", detail: "connected" },
  }],
};

test("builds an Attack Surface workbook with overview, findings and risk summary sheets", async () => {
  const workbook = buildAttackSurfaceWorkbook(sample, FakeExcelLib) as unknown as FakeWorkbook;

  assert.deepEqual(workbook.worksheets.map((sheet) => sheet.name), [
    "Overview",
    "Findings",
    "Assets",
    "Services",
    "CVEs",
    "Hostnames",
    "Tags",
    "Evidence",
    "Validation",
    "Risk Summary",
    "Warnings",
  ]);
  assert.equal(workbook.getWorksheet("Overview")?.getCell("A1").value, "ThreatSumm4ry Attack Surface");
  assert.deepEqual(workbook.getWorksheet("Findings")?.columns.map((column) => column.header), [
    "Finding ID",
    "Service Key",
    "Risk",
    "Score",
    "IP",
    "Port",
    "Transport",
    "Service",
    "Product",
    "Version",
    "Organization",
    "ASN",
    "Country",
    "City",
    "Sources",
    "Observed",
    "TCP Status",
    "Risk Reason Count",
    "CVE Count",
    "Hostname Count",
    "Tag Count",
  ]);
  assert.equal(workbook.getWorksheet("Findings")?.getRow(2).getCell(1).value, "finding-1");
  assert.equal(workbook.getWorksheet("Findings")?.getRow(2).getCell(2).value, "8.8.8.8:443/tcp");
  assert.equal(workbook.getWorksheet("Findings")?.getRow(2).getCell(17).value, "open");
  assert.equal(workbook.getWorksheet("Assets")?.getRow(2).getCell(1).value, "8.8.8.8");
  assert.equal(workbook.getWorksheet("Assets")?.getRow(2).getCell(2).value, 1);
  assert.equal(workbook.getWorksheet("Services")?.getRow(2).getCell(7).value, "https");
  assert.equal(workbook.getWorksheet("CVEs")?.getRow(2).getCell(1).value, "finding-1");
  assert.equal(workbook.getWorksheet("CVEs")?.getRow(2).getCell(5).value, "CVE-2026-0001");
  assert.equal(workbook.getWorksheet("Hostnames")?.getRow(2).getCell(5).value, "example.com");
  assert.equal(workbook.getWorksheet("Tags")?.getRow(2).getCell(5).value, "cloud");
  assert.equal(workbook.getWorksheet("Evidence")?.getRow(2).getCell(5).value, "risk_reason");
  assert.equal(workbook.getWorksheet("Evidence")?.getRow(3).getCell(5).value, "banner");
  assert.equal(workbook.getWorksheet("Validation")?.getRow(2).getCell(5).value, true);
  assert.equal(workbook.getWorksheet("Validation")?.getRow(2).getCell(6).value, "open");
  assert.equal(workbook.getWorksheet("Risk Summary")?.getRow(2).getCell(1).value, "critical");
  assert.equal(workbook.getWorksheet("Risk Summary")?.getRow(2).getCell(2).value, 1);
  assert.equal(workbook.getWorksheet("Warnings")?.getRow(2).getCell(1).value, "Censys unavailable");
});
