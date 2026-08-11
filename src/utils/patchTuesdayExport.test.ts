import assert from "node:assert/strict";
import test from "node:test";
import { createRequire } from "node:module";
import type { PatchTuesdaySummary, PatchVulnerability } from "@/services/msrcApi";
import { buildPatchTuesdayPresentation, buildPatchTuesdayWorkbook } from "./patchTuesdayExport";

const cve = (over: Partial<PatchVulnerability> = {}): PatchVulnerability => ({
    cve: "CVE-2026-68820",
    title: "Windows Common Log File System Driver Elevation of Privilege Vulnerability",
    description: "",
    cwe: "CWE-416",
    severity: "Important",
    impact: "Elevation of Privilege",
    cvss: 7.8,
    vector: "",
    exploited: true,
    publiclyDisclosed: false,
    exploitability: "Exploitation Detected",
    upstream: false,
    family: "Windows",
    productCount: 12,
    kbs: [{ kb: "5065426", url: "https://catalog.update.microsoft.com/" }],
    releaseDate: null,
    ...over,
});

// Shaped after August 2026: 422 Microsoft CVEs, 329 upstream republications.
const sample: PatchTuesdaySummary = {
    id: "2026-Aug",
    title: "August 2026 Security Updates",
    initialReleaseDate: "2026-08-11T07:00:00",
    currentReleaseDate: "2026-08-11T07:00:00",
    totals: {
        total: 422, critical: 62, important: 357, moderate: 1, low: 0, unknown: 2,
        exploited: 1, disclosed: 2, exploitMoreLikely: 34, upstream: 329,
    },
    byImpact: [
        { name: "Elevation of Privilege", count: 180 },
        { name: "Remote Code Execution", count: 120 },
        { name: "Information Disclosure", count: 62 },
    ],
    byFamily: [
        { name: "Windows", count: 225 },
        { name: "Microsoft Office", count: 98 },
        { name: "Other Microsoft Products", count: 13 },
    ],
    topCves: [cve(), cve({ cve: "CVE-2026-63508", severity: "Critical", exploited: false, publiclyDisclosed: true, cvss: 9.8 })],
    vulnerabilities: [],
};

// Slides and speaker notes are separate parts of the package. Keeping them apart
// is what lets a test say "this text is on the slide but not in the notes".
const buildXml = async (summary: PatchTuesdaySummary) => {
    const runtimeRequire = createRequire(`${process.cwd()}/package.json`);
    const JSZip = runtimeRequire("jszip") as typeof import("jszip");
    const PptxGenJS = runtimeRequire("pptxgenjs") as typeof import("pptxgenjs").default;
    const bytes = await buildPatchTuesdayPresentation(summary, PptxGenJS).write({ outputType: "nodebuffer" });
    const zip = await JSZip.loadAsync(bytes as ArrayBuffer);
    const read = async (pattern: RegExp) => {
        const files = Object.values(zip.files).filter((file) => !file.dir && pattern.test(file.name));
        return (await Promise.all(files.map((file) => file.async("string")))).join("\n");
    };
    return { all: await read(/\.xml$/), slides: await read(/^ppt\/slides\/.+\.xml$/), notes: await read(/^ppt\/notesSlides\/.+\.xml$/) };
};

test("o deck sai em PT-BR, no padrão executivo, sem identificar a consultoria", async () => {
    const { all: xml } = await buildXml(sample);

    assert.match(xml, /Avaliação de riscos de vulnerabilidades/);
    assert.match(xml, /Sumário executivo/);
    assert.match(xml, /Conclusão e recomendações/);
    assert.match(xml, /agosto de 2026/);
    // Severity and impact are the terms people search for; they stay as MSRC
    // publishes them even though the surrounding deck is PT-BR.
    assert.match(xml, /Remote Code Execution/, "impacto do MSRC preservado");
    assert.match(xml, /Critical/, "severidade do MSRC preservada");
    assert.doesNotMatch(xml, /Execução remota de código/, "termo técnico não traduzido");

    // Whoever presents this puts their own name on it.
    for (const identifier of [/\bEY\b/i, /Ernst\s*&\s*Young/i, /\bcliente\b/i, /\bconsultoria\b/i]) {
        assert.doesNotMatch(xml, identifier, String(identifier));
    }
});

test("o número da capa é o da Microsoft e o deck explica o que ficou de fora", async () => {
    const { all: xml } = await buildXml(sample);

    // The gap between 422 and the document's 751 is the question the room asks;
    // the deck answers it before it is asked.
    assert.match(xml, /422 CVEs · 62 críticas · 1 sob exploração ativa/);
    assert.match(xml, /329 CVEs de código upstream/);
    assert.match(xml, /Chromium\/Edge e pacotes do Azure Linux/);
    assert.doesNotMatch(xml, /751/, "a contagem bruta do documento não aparece em lugar nenhum");
});

test("severidades zeradas somem da rosca em vez de virarem fatia vazia", async () => {
    const { all: xml } = await buildXml(sample);
    assert.match(xml, /Moderate/, "moderate=1 aparece");
    assert.doesNotMatch(xml, /<a:t>Low<\/a:t>/, "low=0 é omitida");
});

// The only geometry that moves with the data: the executive summary drops a
// bullet per condition met, and the bold closing line sits below the last one.
test("o sumário executivo cabe na página mesmo com todos os marcadores", () => {
    const runtimeRequire = createRequire(`${process.cwd()}/package.json`);
    const PptxGenJS = runtimeRequire("pptxgenjs") as typeof import("pptxgenjs").default;
    const pptx = buildPatchTuesdayPresentation(sample, PptxGenJS) as unknown as {
        slides: { _slideObjects: { options?: { x?: number; y?: number; w?: number; h?: number } }[] }[];
    };
    const slide = pptx.slides[1];

    const placed = slide._slideObjects.map((o) => o.options).filter((o): o is { x: number; y: number; w: number; h: number } => o?.y != null);
    assert.equal(placed.length, 8, "título + frase de abertura + 5 marcadores + linha de fecho");
    for (const o of placed) {
        assert.ok(o.y + o.h <= 7.05, `elemento em y=${o.y} invade o rodapé`);
        assert.ok(o.x + o.w <= 13.333, `elemento em x=${o.x} passa da margem direita`);
    }
});

test("a planilha sai no padrão de folha, em PT-BR, com os termos do MSRC intactos", async () => {
    const runtimeRequire = createRequire(`${process.cwd()}/package.json`);
    const ExcelJS = runtimeRequire("exceljs") as typeof import("exceljs");
    const wb = buildPatchTuesdayWorkbook(
        { ...sample, vulnerabilities: [cve(), cve({ cve: "CVE-2026-64572", upstream: true, family: "Other Microsoft Products" })] },
        ExcelJS
    );

    assert.deepEqual(wb.worksheets.map((ws) => ws.name), ["Resumo", "Por Severidade", "Por Impacto", "Por Família de Produto", "Base de dados"]);

    const base = wb.getWorksheet("Base de dados")!;
    const header = base.getRow(1);
    assert.equal(header.getCell(1).value, "CVE");
    assert.equal(header.getCell(5).value, "Família de Produto", "rótulos em PT-BR");
    assert.equal(header.getCell(2).value, "Severity", "termo do MSRC preservado");
    assert.equal(header.getCell(4).value, "Impact");

    // Dark red band, white bold Calibri 14, bordered, frozen, filterable.
    const style = header.getCell(1);
    assert.deepEqual(style.font, { name: "Calibri", bold: true, size: 14, color: { argb: "FFFFFFFF" } });
    assert.equal((style.fill as { fgColor: { argb: string } }).fgColor.argb, "FFC00000");
    assert.ok(style.border?.bottom);
    assert.deepEqual(base.views, [{ state: "frozen", ySplit: 1 }]);
    assert.ok(base.autoFilter);

    // Values: MSRC terms untouched, our own labels in PT-BR.
    assert.equal(base.getRow(2).getCell(2).value, "Important");
    assert.equal(base.getRow(2).getCell(4).value, "Elevation of Privilege");
    assert.equal(base.getRow(2).getCell(6).value, "Microsoft");
    assert.equal(base.getRow(2).getCell(7).value, "Sim", "booleano em PT-BR");
    assert.equal(base.getRow(3).getCell(6).value, "Upstream republicado", "linhas upstream vão marcadas, não sumidas");

    // No colour on data rows — the reader filters by column instead.
    assert.equal(base.getRow(2).getCell(2).fill, undefined);
    assert.equal(base.getRow(2).getCell(2).font, undefined);
});

test("a planilha não identifica a consultoria em nenhum metadado", async () => {
    const runtimeRequire = createRequire(`${process.cwd()}/package.json`);
    const JSZip = runtimeRequire("jszip") as typeof import("jszip");
    const ExcelJS = runtimeRequire("exceljs") as typeof import("exceljs");
    const bytes = await buildPatchTuesdayWorkbook(sample, ExcelJS).xlsx.writeBuffer();
    const zip = await JSZip.loadAsync(bytes as ArrayBuffer);
    const files = Object.values(zip.files).filter((f) => !f.dir && /\.xml$/.test(f.name));
    const xml = (await Promise.all(files.map((f) => f.async("string")))).join("\n");

    assert.match(xml, /Fonte oficial Microsoft/);
    for (const identifier of [/\bEY\b/i, /Ernst\s*&\s*Young/i, /\bcliente\b/i, /\bconsultoria\b/i]) {
        assert.doesNotMatch(xml, identifier, String(identifier));
    }
});

test("títulos longos são condensados no slide e preservados nas notas", async () => {
    const long = "A".repeat(140);
    const { slides, notes } = await buildXml({ ...sample, topCves: [cve({ title: long })] });
    assert.doesNotMatch(slides, new RegExp("A{140}"), "a tabela não recebe o título inteiro");
    assert.match(slides, new RegExp("A{77}…"), "condensado na tabela");
    assert.match(notes, new RegExp("Título completo: A{140}"), "íntegro nas notas do apresentador");
});
