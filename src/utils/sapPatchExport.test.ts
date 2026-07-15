import assert from "node:assert/strict";
import test from "node:test";
import type { SapPatchSummary } from "@/services/sapApi";
import { buildSapPatchPresentation, buildSapPatchWorkbook, sapPatchBaseFilename, type ExcelWorkbookFactory } from "./sapPatchExport";

class FakeCell {
    value: unknown;
    font: unknown;
    fill: unknown;
    alignment: unknown;
    border: unknown;
}

class FakeRow {
    cells = new Map<number | string, FakeCell>();
    height = 0;

    set values(values: unknown[]) {
        values.forEach((value, index) => { this.getCell(index + 1).value = value; });
    }

    getCell(key: number | string) {
        if (!this.cells.has(key)) this.cells.set(key, new FakeCell());
        return this.cells.get(key)!;
    }
}

class FakeWorksheet {
    columns: Array<{ header: string; key: string; width: number }> = [];
    rows = new Map<number, FakeRow>();
    views: unknown[] = [];
    autoFilter: unknown;
    merges: string[] = [];

    constructor(public name: string) {}
    mergeCells(range: string) { this.merges.push(range); }
    getCell(address: string) {
        const match = /^([A-Z]+)(\d+)$/.exec(address);
        if (!match) return this.getRow(1).getCell(address);
        const column = match[1].split("").reduce((value, letter) => value * 26 + letter.charCodeAt(0) - 64, 0);
        return this.getRow(Number(match[2])).getCell(column);
    }
    getRow(rowNumber: number) {
        if (!this.rows.has(rowNumber)) this.rows.set(rowNumber, new FakeRow());
        return this.rows.get(rowNumber)!;
    }
    addRow(values: Record<string, unknown> | unknown[]) {
        const row = this.getRow(Math.max(0, ...this.rows.keys()) + 1);
        if (Array.isArray(values)) row.values = values;
        else this.columns.forEach((column, index) => { row.getCell(index + 1).value = values[column.key]; });
        return row;
    }
    getColumn(index: number) { return this.columns[index - 1] ?? { width: 0 }; }
}

class FakeWorkbook {
    creator = "";
    company = "";
    subject = "";
    title = "";
    lang = "";
    created: Date | null = null;
    worksheets: FakeWorksheet[] = [];
    addWorksheet(name: string, options?: { views?: unknown[] }) {
        const sheet = new FakeWorksheet(name);
        sheet.views = options?.views ?? [];
        this.worksheets.push(sheet);
        return sheet;
    }
    getWorksheet(name: string) { return this.worksheets.find((sheet) => sheet.name === name); }
}

const FakeExcelLib = { Workbook: FakeWorkbook } as unknown as ExcelWorkbookFactory;

class FakeSlide {
    texts: string[] = [];
    textEntries: Array<{ text: string; options: Record<string, unknown> }> = [];
    tables: Array<{ rows: Array<Array<{ text: string }>>; options: Record<string, unknown> }> = [];
    shapes: Array<{ type: unknown; options: Record<string, unknown> }> = [];
    charts: Array<{ type: unknown; data: unknown[]; options: Record<string, unknown> }> = [];
    background: unknown;
    addText(text: string | Array<{ text: string }>, options: Record<string, unknown> = {}) {
        const value = typeof text === "string" ? text : text.map((run) => run.text).join("");
        this.texts.push(value);
        this.textEntries.push({ text: value, options });
    }
    addTable(rows: Array<Array<{ text: string }>>, options: Record<string, unknown>) { this.tables.push({ rows, options }); }
    addShape(type: unknown, options: Record<string, unknown>) { this.shapes.push({ type, options }); }
    addChart(type: unknown, data: unknown[], options: Record<string, unknown>) { this.charts.push({ type, data, options }); }
    addTextBox() {}
}

class FakePptx {
    static ShapeType = { rect: "rect", roundRect: "roundRect", line: "line" };
    static ChartType = { bar: "bar" };
    ShapeType = FakePptx.ShapeType;
    ChartType = FakePptx.ChartType;
    slides: FakeSlide[] = [];
    masters: unknown[] = [];
    author = "";
    company = "";
    subject = "";
    title = "";
    lang = "";
    layout = "";
    defineLayout() {}
    defineSlideMaster(master: unknown) { this.masters.push(master); }
    addSlide() { const slide = new FakeSlide(); this.slides.push(slide); return slide; }
}

const sample: SapPatchSummary = {
    url: "https://support.sap.example/security-patch-day/july-2026",
    releaseDate: "2026-07-14",
    notes: [
        { note: "100001", noteUrl: "https://me.sap.example/notes/100001", title: "Remote code execution in SAP NetWeaver AS Java", cves: ["CVE-2026-1001"], priority: "Hot News", cvss: 9.9, cvssVector: null, isUpdate: false },
        { note: "100002", noteUrl: "https://me.sap.example/notes/100002", title: "Missing authorization check in SAP S/4HANA", cves: [], priority: "High", cvss: null, cvssVector: null, isUpdate: false },
        { note: "100003", noteUrl: "https://me.sap.example/notes/100001", title: "Information disclosure in SAP UI5", cves: ["CVE-2026-1003"], priority: "Medium", cvss: 6.5, cvssVector: null, isUpdate: true },
    ],
    summary: { total: 3, byPriority: { "Hot News": 1, High: 1, Medium: 1 }, hotNews: 1, high: 1, maxCvss: 9.9, cveCount: 2 },
};

test("cria workbook executivo em pt-BR com duas abas", () => {
    const workbook = buildSapPatchWorkbook(sample, FakeExcelLib) as unknown as FakeWorkbook;
    assert.deepEqual(workbook.worksheets.map((sheet) => sheet.name), ["Visão executiva", "Notas de segurança"]);
    assert.equal(workbook.creator, "ThreatSumm4ry");
    assert.deepEqual(workbook.getWorksheet("Notas de segurança")?.columns.map((column) => column.header), [
        "Nota", "CVE", "Título", "CVSS", "Prioridade", "Categoria", "Produto/Componente", "Atualização", "Vetor CVSS", "URL da SAP Note",
    ]);
});

test("preenche notas analisadas, links, filtros, fallbacks e metadados", () => {
    const workbook = buildSapPatchWorkbook(sample, FakeExcelLib) as unknown as FakeWorkbook;
    const notes = workbook.getWorksheet("Notas de segurança")!;
    const first = notes.getRow(2);
    assert.deepEqual(first.getCell(1).value, { text: sample.notes[0].note, hyperlink: sample.notes[0].noteUrl });
    assert.deepEqual(first.getCell(2).value, { text: sample.notes[0].cves[0], hyperlink: `https://www.cve.org/CVERecord?id=${sample.notes[0].cves[0]}` });
    assert.equal(first.getCell(6).value, "RCE / Corrupção de memória");
    assert.equal(first.getCell(7).value, "SAP NetWeaver AS Java");
    assert.deepEqual(first.getCell(10).value, { text: sample.notes[0].noteUrl, hyperlink: sample.notes[0].noteUrl });
    assert.equal(notes.getRow(4).getCell(2).value, "Não informada");
    assert.equal(notes.getRow(4).getCell(4).value, "Não informado");
    assert.deepEqual(notes.autoFilter, { from: { row: 1, column: 1 }, to: { row: 1, column: 10 } });
    assert.deepEqual(notes.views, [{ state: "frozen", ySplit: 1 }]);
    assert.equal(workbook.company, "");
    assert.equal(workbook.lang, "pt-BR");
    assert.equal(workbook.subject, "Relatório automático do SAP Security Patch Day");
    assert.match(workbook.title, /julho de 2026/);
});

test("cria seis slides na sequência aprovada e com metadados neutros", () => {
    const pptx = buildSapPatchPresentation(sample, FakePptx as never) as unknown as FakePptx;
    assert.equal(pptx.slides.length, 6);
    assert.deepEqual(pptx.slides.map((slide) => slide.texts[0]), [
        "SAP Security Patch Day",
        "Sumário executivo",
        "Consolidado de vulnerabilidades",
        "Highlights de vulnerabilidades",
        "Conclusão e recomendações",
        "Referências",
    ]);
    assert.equal(pptx.author, "ThreatSumm4ry");
    assert.equal(pptx.lang, "pt-BR");
    assert.equal(pptx.company, "");
    assert.equal(pptx.layout, "SAP_EXECUTIVO");
    assert.equal(pptx.masters.length, 1);
});

test("inclui conteúdo, fallbacks, tabela completa e linguagem neutra", () => {
    const pptx = buildSapPatchPresentation(sample, FakePptx as never) as unknown as FakePptx;
    const allText = pptx.slides.flatMap((slide) => slide.texts).join("\n");
    assert.match(allText, /Não informada/);
    assert.match(allText, /9\.9/);
    assert.match(allText, /Não informado/);
    assert.match(allText, /Fonte oficial SAP/);
    assert.doesNotMatch(allText, /cliente|consultoria/i);
    assert.equal(pptx.slides[3].tables.length, 1);
    assert.equal(pptx.slides[3].tables[0].rows.length, sample.notes.length + 1);
    assert.equal(pptx.slides[3].tables[0].options.fontSize, 8);
});

test("deriva o nome-base mensal e aplica fallback em português", () => {
    assert.equal(sapPatchBaseFilename(sample), "SAP-Security-Patch-Day-2026-07");
    assert.equal(sapPatchBaseFilename({ ...sample, releaseDate: null }), "SAP-Security-Patch-Day-mais-recente");
});

const withNoteCount = (count: number): SapPatchSummary => ({
    ...sample,
    notes: Array.from({ length: count }, (_, index) => ({
        ...sample.notes[index % sample.notes.length],
        note: String(200000 + index),
        noteUrl: `https://me.sap.example/notes/${200000 + index}`,
        title: `Remote code execution in SAP NetWeaver AS Java ${"x".repeat(120)} ${index}`,
        cves: [`CVE-2026-${String(index).padStart(4, "0")}`],
    })),
    summary: { ...sample.summary, total: count },
});

test("registra gráfico nativo, três cards e master executivo dentro da área útil", () => {
    const pptx = buildSapPatchPresentation(sample, FakePptx as never) as unknown as FakePptx;
    const consolidated = pptx.slides[2];
    assert.equal(consolidated.charts.length, 1);
    assert.equal(consolidated.charts[0].type, FakePptx.ChartType.bar);
    assert.equal(consolidated.shapes.filter((shape) => shape.type === FakePptx.ShapeType.roundRect).length, 3);
    assert.match(JSON.stringify(pptx.masters[0]), /SAP Security Patch Day/);
    for (const entry of consolidated.textEntries) {
        assert.ok(Number(entry.options.y ?? 0) + Number(entry.options.h ?? 0) < 7.05);
    }
});

test("contém 40 notas em uma tabela integral com escala, margens e títulos de até 100 caracteres", () => {
    const pptx = buildSapPatchPresentation(withNoteCount(40), FakePptx as never) as unknown as FakePptx;
    const table = pptx.slides[3].tables[0];
    assert.equal(table.rows.length, 41);
    assert.equal(table.options.fontSize, 7);
    assert.ok(Number(table.options.rowH) * table.rows.length + Number(table.options.y) < 7.05);
    assert.ok(Number(table.options.margin) <= 0.03);
    assert.equal(table.options.autoPage, false);
    for (const row of table.rows.slice(1)) {
        assert.ok(row[1].text.length <= 100);
        assert.ok(row[1].text.endsWith("…"));
    }
});

test("mantém fonte de 7 pt para qualquer volume acima de 20 notas", () => {
    for (const count of [41, 60]) {
        const pptx = buildSapPatchPresentation(withNoteCount(count), FakePptx as never) as unknown as FakePptx;
        assert.equal(pptx.slides.length, 6);
        assert.equal(pptx.slides[3].tables[0].options.fontSize, 7, `${count} notas`);
    }
});

test("distribui referências deduplicadas em colunas sem colidir com geração ou rodapé", () => {
    const summary = withNoteCount(30);
    summary.notes[29].noteUrl = summary.notes[0].noteUrl;
    const pptx = buildSapPatchPresentation(summary, FakePptx as never) as unknown as FakePptx;
    const slide = pptx.slides[5];
    const generated = slide.textEntries.find((entry) => entry.text.startsWith("Gerado em"));
    const expected = new Set([summary.url, ...summary.notes.map((note) => note.noteUrl)]);
    const links = slide.textEntries.filter((entry) => typeof entry.options.hyperlink === "object");
    assert.equal(links.length, expected.size);
    assert.equal(new Set(links.map((entry) => entry.text)).size, expected.size);
    assert.ok(new Set(links.map((entry) => entry.options.x)).size >= 2);
    assert.ok(generated);
    for (const link of links) {
        const bottom = Number(link.options.y) + Number(link.options.h);
        assert.ok(bottom < Number(generated.options.y));
        assert.ok(bottom < 7.05);
        assert.ok(Number(link.options.x) + Number(link.options.w) <= 13.333);
    }
});
