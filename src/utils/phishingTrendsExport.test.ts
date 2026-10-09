import assert from "node:assert/strict";
import test from "node:test";
import { createRequire } from "node:module";
import type { NewsArchiveRow } from "@/services/threatApi";
import { buildPhishingTrendsWorkbook, phishingTrendsExcelFilename } from "./phishingTrendsExport";

const runtimeRequire = createRequire(`${process.cwd()}/package.json`);
const ExcelJS = runtimeRequire("exceljs") as typeof import("exceljs");

const row = (over: Partial<NewsArchiveRow> = {}): NewsArchiveRow => ({
    link: "https://a.example/1", title: "LummaC2 infostealer spread via fake CAPTCHA",
    source: "BleepingComputer", pubDate: "2026-08-10T12:00:00.000Z",
    categories: ["Phishing"], primaryCategory: "Phishing",
    phishingTechniques: ["ClickFix"], archivedAt: "2026-08-10T12:05:00.000Z",
    ...over,
});

test("a planilha sai nas duas abas, cabeçalho no padrão EY", () => {
    const rows = [
        row(),
        row({ link: "https://b.example/2", title: "AiTM kit bypasses MFA at scale", phishingTechniques: ["AiTM / Adversary-in-the-Middle", "ClickFix"] }),
    ];
    const wb = buildPhishingTrendsWorkbook(rows, ExcelJS);
    assert.deepEqual(wb.worksheets.map((ws) => ws.name), ["Reports", "Técnicas"]);

    const reports = wb.getWorksheet("Reports")!;
    const header = reports.getRow(1);
    assert.equal(header.getCell(1).value, "Data");
    assert.equal(header.getCell(2).value, "Título");
    assert.equal(header.getCell(5).value, "Técnicas");
    assert.deepEqual(header.getCell(1).font, { name: "Calibri", bold: true, size: 14, color: { argb: "FFFFE600" } });
    assert.ok(reports.autoFilter);
    assert.deepEqual(reports.views, [{ state: "frozen", ySplit: 1 }]);

    assert.equal(reports.getRow(2).getCell(2).value, "LummaC2 infostealer spread via fake CAPTCHA");
    assert.equal(reports.getRow(3).getCell(5).value, "AiTM / Adversary-in-the-Middle, ClickFix");
    // Sem cor na linha de dado.
    assert.equal(reports.getRow(2).getCell(2).fill, undefined);
});

test("a aba Técnicas conta ocorrências, ordenada da mais comum pra menos", () => {
    const rows = [
        row({ phishingTechniques: ["ClickFix"] }),
        row({ link: "https://b.example/2", phishingTechniques: ["ClickFix", "Vishing"] }),
        row({ link: "https://c.example/3", phishingTechniques: ["Vishing"] }),
    ];
    const tecnicas = buildPhishingTrendsWorkbook(rows, ExcelJS).getWorksheet("Técnicas")!;
    assert.equal(tecnicas.getRow(2).getCell(1).value, "ClickFix");
    assert.equal(tecnicas.getRow(2).getCell(2).value, 2);
    assert.equal(tecnicas.getRow(3).getCell(1).value, "Vishing");
    assert.equal(tecnicas.getRow(3).getCell(2).value, 2);
});

test("lista vazia não quebra a planilha", () => {
    const wb = buildPhishingTrendsWorkbook([], ExcelJS);
    assert.deepEqual(wb.worksheets.map((ws) => ws.name), ["Reports", "Técnicas"]);
});

test("o nome do arquivo carrega a data de hoje", () => {
    assert.match(phishingTrendsExcelFilename(), /^Tendencias-de-Phishing-\d{4}-\d{2}-\d{2}\.xlsx$/);
});
