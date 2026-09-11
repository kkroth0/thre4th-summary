import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { boletimFilename, boletimIocsExcelFilename, buildBoletimIocsWorkbook, canExportBoletimIocs } from "./boletimExport.ts";
import type { BoletimJob, BoletimReport } from "@/services/threatApi";

const job = (json: BoletimReport | null): BoletimJob => ({
  id: "j1", url: "https://exemplo.test/aviso", type: "vuln", title: "Aviso",
  status: "done", json, error: null, createdAt: "", updatedAt: "",
});

// Os casos espelham tests/test_i18n.py do motor: os dois lados têm que gerar o
// mesmo nome pro mesmo título.
test("nome do arquivo é o padrão da casa, com fallback pro job", () => {
  assert.equal(boletimFilename(job({ titulo: "Ransomware X abusa de Y" })),
    "SRR - Surface Risk Report - Ransomware X abusa de Y");
  assert.equal(boletimFilename(job(null)), "SRR - Surface Risk Report - Aviso");
});

test("tira o que o Windows recusa em nome de arquivo, mantém acento", () => {
  const out = boletimFilename(job({ titulo: 'Falha crítica: RCE em Foo/Bar "v2"?' }));
  assert.ok(!/[<>:"/\\|?*]/.test(out), out);
  assert.ok(out.startsWith("SRR - Surface Risk Report - "));
  assert.match(out, /crítica/);
});

test("título vazio deixa só o prefixo, sem hífen solto no fim", () => {
  assert.equal(boletimFilename({ ...job(null), title: "", url: "" }), "SRR - Surface Risk Report");
});

// ---- IOCs (Excel) -----------------------------------------------------------

const jobWithIocs = (over: Partial<BoletimReport> = {}): BoletimJob =>
  job({
    titulo: "Grupo russos explora falha crítica em firewalls FortiGate",
    tlp: "TLP:CLEAR",
    ator: { threat_actor: "Grupo cibercriminoso de língua russa (não nomeado)" },
    iocs: [
      { categoria: "Rede", tipo: "Endereço IP", valor: "146.103.99.177" },
      { categoria: "Rede", tipo: "URL", valor: "https://146.103.99.177:8443/0c5b76709523" },
      { categoria: "Host", tipo: "Endpoint", valor: "/data/config/sys_global.conf.gz" },
    ],
    iocs_fontes: ["https://github.com/example/iocs-2026-08"],
    ...over,
  });

test("canExportBoletimIocs só libera quando há indicadores", () => {
  assert.equal(canExportBoletimIocs(jobWithIocs()), true);
  assert.equal(canExportBoletimIocs(job(null)), false);
  assert.equal(canExportBoletimIocs(job({ iocs: [] })), false);
  assert.equal(canExportBoletimIocs(null), false);
});

test("nome do arquivo de IOCs deriva do nome padrão do boletim", () => {
  assert.equal(
    boletimIocsExcelFilename(jobWithIocs()),
    "SRR - Surface Risk Report - Grupo russos explora falha crítica em firewalls FortiGate - IOCs.xlsx"
  );
});

test("a planilha de IOCs sai no padrão da casa, com TLP e fontes externas", () => {
  const runtimeRequire = createRequire(`${process.cwd()}/package.json`);
  const ExcelJS = runtimeRequire("exceljs") as typeof import("exceljs");
  const wb = buildBoletimIocsWorkbook(jobWithIocs(), ExcelJS);

  assert.deepEqual(wb.worksheets.map((ws) => ws.name), ["Resumo", "IOCs", "Fontes"]);

  const resumo = wb.getWorksheet("Resumo")!;
  assert.match(String(resumo.getCell("A1").value), /Grupo russos explora/);
  assert.match(String(resumo.getCell("A2").value), /TLP:CLEAR/);

  const sheet = wb.getWorksheet("IOCs")!;
  const header = sheet.getRow(1);
  assert.equal(header.getCell(1).value, "Categoria");
  assert.equal(header.getCell(2).value, "Tipo");
  assert.equal(header.getCell(3).value, "Indicador");
  // Black band, yellow bold Calibri 14 — same header style as the other exports.
  assert.deepEqual(header.getCell(1).font, { name: "Calibri", bold: true, size: 14, color: { argb: "FFFFE600" } });
  assert.deepEqual(sheet.views, [{ state: "frozen", ySplit: 1 }]);
  assert.ok(sheet.autoFilter);

  // A URL-shaped indicator becomes a clickable link; a plain endpoint path does not.
  assert.deepEqual(sheet.getRow(3).getCell(3).value, {
    text: "https://146.103.99.177:8443/0c5b76709523",
    hyperlink: "https://146.103.99.177:8443/0c5b76709523",
  });
  assert.equal(sheet.getRow(2).getCell(3).value, "146.103.99.177");
  assert.equal(sheet.getRow(4).getCell(3).value, "/data/config/sys_global.conf.gz");

  const fontes = wb.getWorksheet("Fontes")!;
  assert.deepEqual(fontes.getRow(2).getCell(1).value, {
    text: "https://github.com/example/iocs-2026-08",
    hyperlink: "https://github.com/example/iocs-2026-08",
  });
});

test("sem fontes externas, a aba Fontes não aparece", () => {
  const runtimeRequire = createRequire(`${process.cwd()}/package.json`);
  const ExcelJS = runtimeRequire("exceljs") as typeof import("exceljs");
  const wb = buildBoletimIocsWorkbook(jobWithIocs({ iocs_fontes: [] }), ExcelJS);
  assert.deepEqual(wb.worksheets.map((ws) => ws.name), ["Resumo", "IOCs"]);
});
