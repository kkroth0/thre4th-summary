import assert from "node:assert/strict";
import test from "node:test";
import { createRequire } from "node:module";
import type { SapPatchSummary } from "@/services/sapApi";
import { buildSapPatchPresentation, buildSapPatchWorkbook, sapPatchBaseFilename, sapPatchExcelFilename } from "./sapPatchExport";

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

const runtimeRequire = createRequire(`${process.cwd()}/package.json`);
const loadPptx = () => runtimeRequire("pptxgenjs") as typeof import("pptxgenjs").default;
const loadExcel = () => runtimeRequire("exceljs") as typeof import("exceljs");
const loadZip = () => runtimeRequire("jszip") as typeof import("jszip");

// Slides and speaker notes are separate parts of the package, so a test can say
// "this text is on the slide but not in the notes".
const buildXml = async (summary: SapPatchSummary) => {
    const bytes = await buildSapPatchPresentation(summary, loadPptx()).write({ outputType: "nodebuffer" });
    const zip = await loadZip().loadAsync(bytes as ArrayBuffer);
    const read = async (pattern: RegExp) => {
        const files = Object.values(zip.files).filter((file) => !file.dir && pattern.test(file.name));
        return (await Promise.all(files.map((file) => file.async("string")))).join("\n");
    };
    return { all: await read(/\.xml$/), slides: await read(/^ppt\/slides\/.+\.xml$/), notes: await read(/^ppt\/notesSlides\/.+\.xml$/) };
};

// The SAP deck is the same template the Patch Tuesday deck uses: six slides on
// the 10 × 5.625in canvas, Overpass throughout, nothing hanging off the artboard.
test("o deck SAP sai no gabarito: 6 slides, canvas 16:9 e fonte Overpass", async () => {
    const pptx = buildSapPatchPresentation(sample, loadPptx()) as unknown as {
        layout: string;
        slides: { _slideObjects: { options?: { x?: number; y?: number; w?: number; h?: number } }[] }[];
    };

    assert.equal(pptx.slides.length, 6, "capa + sumário + consolidado + highlights + recomendações + referências");
    assert.equal(pptx.layout, "LAYOUT_16x9");
    for (const [index, slide] of pptx.slides.entries()) {
        for (const o of slide._slideObjects.map((obj) => obj.options)) {
            if (o?.x == null || o?.y == null || o.w == null || o.h == null) continue;
            assert.ok(o.x + o.w <= 10.001, `slide ${index + 1}: elemento em x=${o.x} passa da margem direita`);
            assert.ok(o.y + o.h <= 5.626, `slide ${index + 1}: elemento em y=${o.y} passa do rodapé`);
        }
    }

    const { all: xml } = await buildXml(sample);
    assert.match(xml, /typeface="Overpass"/);
    assert.doesNotMatch(xml, /typeface="Inter/, "a fonte base do gabarito é Overpass");
});

test("o deck SAP sai em PT-BR, na sequência do relatório, sem identificar a consultoria", async () => {
    const { all: xml, slides } = await buildXml(sample);

    for (const title of ["SAP Security Patch Day", "Sumário executivo", "Consolidado de vulnerabilidades", "Highlights de vulnerabilidades", "Conclusão e recomendações", "Referências"]) {
        assert.match(slides, new RegExp(`<a:t>${title}</a:t>`), title);
    }
    assert.match(xml, /Cyber Threat Intelligence and Hunting/);
    assert.match(xml, /Avaliação de riscos de vulnerabilidades/);
    assert.match(xml, /14 de Julho de 2026/, "a capa usa a data por extenso do gabarito");
    assert.match(xml, /Fonte oficial SAP/);
    // Severity terms SAP publishes stay as published even though the deck is PT-BR.
    assert.match(xml, /Hot News/, "severidade da SAP preservada");

    for (const identifier of [/\bEY\b/i, /Ernst\s*&\s*Young/i, /\bcliente\b/i, /\bconsultoria\b/i, /executive summary/i]) {
        assert.doesNotMatch(xml, identifier, String(identifier));
    }
});

test("os indicadores do consolidado saem do resumo da SAP, não de contagem própria", async () => {
    const { slides } = await buildXml(sample);
    for (const label of ["NOTAS DE SEGURANÇA", "NOTAS CRÍTICAS \\(HOT NEWS\\)", "CVSS MÁXIMO DO CICLO"]) {
        assert.match(slides, new RegExp(`<a:t>${label}</a:t>`));
    }
    assert.match(slides, /<a:t>3<\/a:t>/, "total do ciclo");
    assert.match(slides, /<a:t>1<\/a:t>/, "hot news");
    assert.match(slides, /<a:t>9\.9<\/a:t>/, "CVSS máximo");
    assert.match(slides, /Total de notas: 3/);
    assert.match(slides, /RCE \/ Corrupção de memória:/);
});

test("títulos longos são condensados no card e preservados nas notas", async () => {
    const long = "A".repeat(160);
    const { slides, notes } = await buildXml({
        ...sample,
        notes: [{ ...sample.notes[0], title: long, cves: ["CVE-2026-1001", "CVE-2026-1002"], isUpdate: true }],
        summary: { ...sample.summary, total: 1, cveCount: 2 },
    });
    assert.doesNotMatch(slides, new RegExp("A{160}"), "o card não recebe o título inteiro");
    assert.match(slides, new RegExp("A{129}…"), "condensado no card de highlight");
    assert.match(notes, new RegExp("Título completo: A{160}"), "íntegro nas notas do apresentador");
    assert.match(slides, /CVE-2026-1001, CVE-2026-1002/, "todas as CVEs da nota");
    assert.match(slides, /atualizada/);
});

// Six cards is what the grid holds; the rest of the cycle ships in the workbook,
// and every note still reaches the presenter through the speaker notes.
test("o grid leva 6 notas e as demais vão para as notas do apresentador e o anexo", async () => {
    const { slides, notes } = await buildXml(withNoteCount(30));
    const onSlides = new Set(slides.match(/SAP Note 2000\d\d/g) ?? []);
    // Top 3 e highlights partem da mesma lista ordenada, então os três primeiros
    // cards do consolidado repetem os três primeiros highlights — 6 notas ao todo.
    assert.equal(onSlides.size, 6, "as 6 notas de maior severidade");
    assert.match(notes, /SAP Note 200029/, "a última nota chega ao apresentador pelas notas");
    assert.equal(new Set(notes.match(/SAP Note 2000\d\d/g) ?? []).size, 30, "todas as notas do ciclo");
    assert.match(slides, /A Listagem de Vulnerabilidades encontra-se no arquivo anexado ao e-mail\./);
});

test("as referências deduplicadas cabem no canvas e não colidem com o rodapé", () => {
    const summary = withNoteCount(30);
    summary.notes[29].noteUrl = summary.notes[0].noteUrl;
    const pptx = buildSapPatchPresentation(summary, loadPptx()) as unknown as {
        slides: { _slideObjects: { text?: unknown; options?: { x?: number; y?: number; w?: number; h?: number; hyperlink?: { url: string } } }[] }[];
    };
    const objects = pptx.slides[5]._slideObjects;
    const links = objects.filter((o) => o.options?.hyperlink);
    const expected = new Set([summary.url, ...summary.notes.map((note) => note.noteUrl)]);

    assert.equal(links.length, expected.size);
    assert.ok(new Set(links.map((o) => o.options!.x)).size >= 2, "distribuídas em colunas");
    for (const link of links) {
        assert.ok(link.options!.y! + link.options!.h! < 4.7, "acima da linha de geração");
        assert.ok(link.options!.x! + link.options!.w! <= 10.001);
    }
});

test("a planilha SAP sai no padrão de folha, em PT-BR, com os termos da SAP intactos", async () => {
    const workbook = buildSapPatchWorkbook(sample, loadExcel());

    assert.deepEqual(workbook.worksheets.map((sheet) => sheet.name), ["Visão executiva", "Notas de segurança"]);

    const notes = workbook.getWorksheet("Notas de segurança")!;
    const header = notes.getRow(1);
    assert.deepEqual(
        (notes.columns ?? []).map((column) => column.header),
        ["Nota", "CVE", "NVD", "Título", "CVSS", "Prioridade", "Categoria", "Produto/Componente", "Atualização", "Vetor CVSS", "URL da SAP Note"]
    );

    // Black band, yellow bold Calibri 14, bordered, frozen, filterable.
    const style = header.getCell(1);
    assert.deepEqual(style.font, { name: "Calibri", bold: true, size: 14, color: { argb: "FFFFE600" } });
    assert.equal((style.fill as { fgColor: { argb: string } }).fgColor.argb, "FF000000");
    assert.ok(style.border?.bottom);
    assert.deepEqual(notes.views, [{ state: "frozen", ySplit: 1 }]);
    assert.deepEqual(notes.autoFilter, { from: { row: 1, column: 1 }, to: { row: 1, column: 11 } });
    assert.equal(notes.properties.tabColor?.argb, "FFFFE600", "abas amarelas");

    // The note links to SAP, and every CVE carries its NVD reference.
    const first = notes.getRow(2);
    assert.deepEqual(first.getCell(1).value, { text: "100001", hyperlink: "https://me.sap.example/notes/100001" });
    assert.deepEqual(first.getCell(3).value, { text: "NVD", hyperlink: "https://nvd.nist.gov/vuln/detail/CVE-2026-1001" });
    assert.deepEqual(first.getCell(3).font, { name: "Calibri", color: { argb: "FF0563C1" }, underline: true });

    // Values: our labels in PT-BR, fallbacks where SAP published nothing.
    assert.equal(first.getCell(2).value, "CVE-2026-1001");
    assert.equal(first.getCell(6).value, "Crítica (Hot News)");
    assert.equal(first.getCell(7).value, "RCE / Corrupção de memória");
    assert.equal(first.getCell(8).value, "SAP NetWeaver AS Java");
    assert.equal(first.getCell(9).value, "Não", "booleano em PT-BR");
    assert.equal(first.getCell(10).value, "Não informado");

    // No colour on data rows — the reader filters by column instead.
    assert.equal(first.getCell(4).fill, undefined);
    assert.equal(first.getCell(4).font, undefined);

    assert.equal(sapPatchBaseFilename(sample), "SAP-Security-Patch-Day-2026-07");
    assert.equal(sapPatchExcelFilename(sample), "SAP-Security-Patch-Day-2026-07.xlsx");
    assert.equal(sapPatchBaseFilename({ ...sample, releaseDate: null }), "SAP-Security-Patch-Day-mais-recente");
});

test("a visão executiva mantém indicadores, blocos e cabeçalhos no padrão", () => {
    const executive = buildSapPatchWorkbook(sample, loadExcel()).getWorksheet("Visão executiva")!;

    assert.equal(executive.getCell("A2").value, "Data do ciclo");
    assert.equal(executive.getCell("B2").value, sample.releaseDate);
    assert.deepEqual(executive.getCell("B3").value, { text: "Fonte oficial SAP", hyperlink: sample.url });
    assert.equal(executive.getRow(5).getCell(1).value, "Indicador");
    assert.equal(executive.getRow(6).getCell(1).value, "Total de notas");
    assert.equal(executive.getRow(12).getCell(1).value, "Distribuição por prioridade");
    assert.equal(executive.getRow(17).getCell(1).value, "Distribuição por categoria");
    assert.equal(executive.getRow(22).getCell(1).value, "Top 3");
    assert.equal(executive.getRow(23).getCell(3).value, "Crítica (Hot News)");
    assert.deepEqual(executive.views, [{ state: "frozen", ySplit: 5 }]);
    assert.equal(executive.properties.tabColor?.argb, "FFFFE600");

    // Every block header wears the black band, not just the first one.
    for (const row of [5, 12, 17, 22]) {
        assert.equal(
            (executive.getRow(row).getCell(1).fill as { fgColor: { argb: string } }).fgColor.argb,
            "FF000000",
            `linha ${row}`
        );
    }
});

test("os fallbacks não criam link sem destino", () => {
    const edge: SapPatchSummary = {
        ...sample,
        notes: [{ ...sample.notes[0], note: "200001", noteUrl: "", title: "Issue in unnamed component", cves: [], cvss: null, cvssVector: null, isUpdate: true }],
        summary: { total: 1, byPriority: { High: 1 }, hotNews: 0, high: 1, maxCvss: 0, cveCount: 0 },
    };
    const row = buildSapPatchWorkbook(edge, loadExcel()).getWorksheet("Notas de segurança")!.getRow(2);
    assert.equal(row.getCell(1).value, "200001");
    assert.equal(row.getCell(2).value, "Não informada");
    assert.equal(row.getCell(3).value, "Não informada");
    assert.equal(row.getCell(3).font, undefined, "sem estilo de link onde não há link");
    assert.equal(row.getCell(5).value, "Não informado");
    assert.equal(row.getCell(8).value, "Componente SAP não especificado");
    assert.equal(row.getCell(9).value, "Sim");
    assert.equal(row.getCell(10).value, "Não informado");
    assert.equal(row.getCell(11).value, "Não informada");
});

test("os artefatos SAP não identificam a consultoria em nenhum metadado", async () => {
    const workbook = buildSapPatchWorkbook(sample, loadExcel());
    const xlsxZip = await loadZip().loadAsync((await workbook.xlsx.writeBuffer()) as ArrayBuffer);
    const files = Object.values(xlsxZip.files).filter((f) => !f.dir && /\.xml$/.test(f.name));
    const xml = (await Promise.all(files.map((f) => f.async("string")))).join("\n");

    assert.match(xml, /ThreatSumm4ry/);
    assert.match(xml, /Fonte oficial SAP/);
    assert.equal(workbook.company, "");
    assert.equal(workbook.subject, "Relatório automático do SAP Security Patch Day");
    assert.match(workbook.title, /julho de 2026/);
    for (const identifier of [/\bEY\b/i, /Ernst\s*&\s*Young/i, /\bcliente\b/i, /\bconsultoria\b/i]) {
        assert.doesNotMatch(xml, identifier, String(identifier));
    }
});

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/;

// SAP note titles are free text we do not control, and PowerPoint is far stricter
// than LibreOffice: a dangling rId, a part with no content type, or a stray `&`
// all produce the "needs repair" dialog instead of a slide.
test("o pacote SAP abre no PowerPoint: rIds resolvem, partes declaradas, texto escapado", async () => {
    const hostile = 'SAP <NetWeaver> \u0026 "AS Java" \u0007 Remote Code Execution';
    const fuzzed: SapPatchSummary = {
        ...sample,
        url: sample.url,
        notes: sample.notes.map((note) => ({ ...note, title: hostile })),
    };
    const zip = await loadZip().loadAsync(
        (await buildSapPatchPresentation(fuzzed, loadPptx()).write({ outputType: "nodebuffer" })) as ArrayBuffer
    );
    const part = (name: string) => zip.file(name)?.async("string") ?? Promise.resolve("");

    const types = await part("[Content_Types].xml");
    const parts = Object.keys(zip.files).filter((n) => !zip.files[n].dir && n.endsWith(".xml") && !n.includes("/_rels/"));
    assert.ok(parts.some((n) => /^ppt\/slides\/slide\d+\.xml$/.test(n)), "o pacote tem slides");

    const xlsx = await loadZip().loadAsync(
        (await buildSapPatchWorkbook(fuzzed, loadExcel()).xlsx.writeBuffer()) as ArrayBuffer
    );
    for (const file of Object.values(xlsx.files).filter((f) => !f.dir && /\.xml$/.test(f.name))) {
        assert.doesNotMatch(await file.async("string"), CONTROL_CHARS, `${file.name}: controle inválido no xlsx`);
    }

    for (const name of parts) {
        const xml = await part(name);
        // Every relationship the part points at has to exist in its own .rels.
        const rels = await part(name.replace(/([^/]+)$/, "_rels/$1.rels"));
        const declared = new Set([...rels.matchAll(/\bId="([^"]+)"/g)].map((m) => m[1]));
        for (const [, id] of xml.matchAll(/r:(?:id|embed|link|pict)="([^"]+)"/g)) {
            assert.ok(declared.has(id), `${name}: ${id} não existe em _rels`);
        }
        // Slides, notes and charts need an explicit content type; the generic
        // Default Extension="xml" is not enough for PowerPoint to render them.
        if (/^ppt\/(slides|notesSlides|charts)\//.test(name)) {
            assert.ok(types.includes(`PartName="/${name}"`), `${name}: sem Override em [Content_Types].xml`);
        }
        assert.doesNotMatch(xml, /&(?!amp;|lt;|gt;|quot;|apos;|#\d+;|#x[0-9a-fA-F]+;)/, `${name}: & solto quebra o XML`);
        assert.doesNotMatch(xml, CONTROL_CHARS, `${name}: caractere de controle inválido em XML 1.0`);
    }
});
