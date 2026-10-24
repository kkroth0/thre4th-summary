import { publisherNamePatterns } from './exportPublisher.testSupport';
import assert from "node:assert/strict";
import test from "node:test";
import { createRequire } from "node:module";
import type { PatchTuesdaySummary, PatchVulnerability } from "@/services/msrcApi";
import { DECK_FONTS } from "./deckTemplate";
import { buildPatchTuesdayPresentation, buildPatchTuesdayWorkbook, patchTuesdayExcelFilename } from "./patchTuesdayExport";

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

    assert.match(xml, /Cyber Threat Intelligence and Hunting/);
    assert.match(xml, /Sumário Executivo/);
    assert.match(xml, /Consolidado de Vulnerabilidades/);
    assert.match(xml, /Highlights: Vulnerabilidades Críticas/);
    assert.match(xml, /agosto de 2026/);
    // Severity and impact are the terms people search for; they stay as MSRC
    // publishes them even though the surrounding deck is PT-BR.
    assert.match(xml, /Remote Code Execution/, "impacto do MSRC preservado");
    assert.match(xml, /Critical/, "severidade do MSRC preservada");
    assert.doesNotMatch(xml, /Execução remota de código/, "termo técnico não traduzido");

    // Whoever presents this puts their own name on it.
    for (const identifier of [...publisherNamePatterns, /\bcliente\b/i, /\bconsultoria\b/i]) {
        assert.doesNotMatch(xml, identifier, String(identifier));
    }
});

test("o número da capa é o da Microsoft e o deck explica o que ficou de fora", async () => {
    const { all: xml } = await buildXml(sample);

    // The gap between 422 and the document's 751 is the question the room asks;
    // the deck answers it before it is asked.
    assert.match(xml, /422 vulnerabilidades/);
    assert.match(xml, /62 críticas e 2 zero-days/);
    assert.match(xml, /329 CVEs de código upstream/);
    assert.match(xml, /Chromium\/Edge e pacotes do Azure Linux/);
    // Text nodes only: 751 also shows up as an EMU coordinate, which says nothing.
    assert.doesNotMatch(xml, /<a:t>[^<]*751[^<]*<\/a:t>/, "a contagem bruta do documento não aparece em lugar nenhum");
});


// The dark panel is the drawing area of every content slide; the footer strip and
// the logo plate are the only things allowed below it. An element outside those
// bounds is the "deck opened broken" report, so both reports assert it.
const PANEL = { x: 0.264, y: 0.234, w: 9.472, h: 5.151 };
type Positioned = { options?: { x?: number; y?: number; w?: number; h?: number } };
const assertInsideTemplate = (pptx: { slides: { _slideObjects: Positioned[] }[] }) => {
    for (const [index, slide] of pptx.slides.entries()) {
        for (const o of slide._slideObjects.map((obj) => obj.options)) {
            if (o?.x == null || o?.y == null || o.w == null || o.h == null) continue;
            const right = o.x + o.w;
            const bottom = o.y + o.h;
            assert.ok(right <= 10.001, `slide ${index + 1}: elemento em x=${o.x} passa da margem direita`);
            assert.ok(bottom <= 5.626, `slide ${index + 1}: elemento em y=${o.y} passa do rodapé`);
            if (index === 0 || o.y >= 4.99) continue; // capa e faixa de rodapé
            assert.ok(o.x >= PANEL.x - 0.001 && right <= PANEL.x + PANEL.w + 0.001, `slide ${index + 1}: x=${o.x} sai do painel`);
            assert.ok(bottom <= PANEL.y + PANEL.h + 0.001, `slide ${index + 1}: y=${o.y} sai do painel`);
        }
    }
};

// The deck is a transcription of the reference template: four slides on the
// 10 × 5.625in canvas, Office fonts throughout, nothing hanging off the artboard.
test("o deck reproduz o gabarito: 4 slides, canvas 16:9 e fonte do Office", async () => {
    const runtimeRequire = createRequire(`${process.cwd()}/package.json`);
    const PptxGenJS = runtimeRequire("pptxgenjs") as typeof import("pptxgenjs").default;
    const pptx = buildPatchTuesdayPresentation(sample, PptxGenJS) as unknown as { slides: { _slideObjects: Positioned[] }[] };

    assert.equal(pptx.slides.length, 4, "capa + sumário + consolidado + highlights");
    assertInsideTemplate(pptx);
    // And it holds with a crowded cycle of long names, not just the tidy sample.
    const crowded = {
        ...sample,
        byImpact: Array.from({ length: 7 }, (_, i) => ({ name: `Impacto com nome bem longo ${i}`, count: 100 - i * 9 })),
        byFamily: Array.from({ length: 8 }, (_, i) => ({ name: `Família de produto bem longa ${i}`, count: 90 - i * 8 })),
        topCves: Array.from({ length: 8 }, (_, i) => cve({ cve: `CVE-2026-${6000 + i}`, title: "y".repeat(140), publiclyDisclosed: true })),
        vulnerabilities: Array.from({ length: 8 }, (_, i) => cve({ cve: `CVE-2026-${6000 + i}`, title: "y".repeat(140), publiclyDisclosed: true })),
    };
    assertInsideTemplate(buildPatchTuesdayPresentation(crowded, PptxGenJS) as never);

    const { all: xml, slides } = await buildXml(sample);
    assert.match(xml, new RegExp(`typeface="${DECK_FONTS[0]}"`));

    // A font PowerPoint does not have is substituted, and the substitute's metrics
    // move every box on the slide. Only Office-resident fonts may be named.
    // Só os slides: o tema traz a tabela de fallback por script do próprio OOXML.
    const typefaces = new Set([...slides.matchAll(/typeface="([^"]*)"/g)].map((m) => m[1]));
    assert.deepEqual([...typefaces].filter((f) => f && !DECK_FONTS.includes(f)), [], "fonte fora do Office");

    // And a fixed box only holds if it also tells PowerPoint to shrink on overflow.
    const bodies = slides.match(/<a:bodyPr[^>]*(?:\/>|>)/g) ?? [];
    const withText = slides.split("<p:txBody>").slice(1);
    assert.ok(withText.length > 0, "o deck tem caixas de texto");
    for (const body of withText) {
        assert.match(body.slice(0, 400), /<a:normAutofit/, "caixa de texto sem autofit vaza no PowerPoint");
    }
    assert.ok(bodies.length >= withText.length);
});

test("os indicadores do consolidado saem do sumário, não de contagem própria", async () => {
    const { slides } = await buildXml(sample);
    for (const label of ["VULNERABILIDADES", "VULNERABILIDADES ZERO DAY", "VULNERABILIDADES CRÍTICAS"]) {
        assert.match(slides, new RegExp(`<a:t>${label}</a:t>`));
    }
    assert.match(slides, /<a:t>422<\/a:t>/, "total do ciclo");
    assert.match(slides, /<a:t>62<\/a:t>/, "críticas");
    assert.match(slides, /<a:t>2<\/a:t>/, "zero-days: explorada + divulgada");
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
    assert.equal(header.getCell(2).value, "Microsoft");
    assert.equal(header.getCell(3).value, "NVD");
    assert.equal(header.getCell(7).value, "Família de Produto", "rótulos em PT-BR");
    assert.equal(header.getCell(4).value, "Severity", "termo do MSRC preservado");
    assert.equal(header.getCell(6).value, "Impact");

    // Black band, yellow bold Calibri 14, bordered, frozen, filterable.
    const style = header.getCell(1);
    assert.deepEqual(style.font, { name: "Calibri", bold: true, size: 14, color: { argb: "FFFFE600" } });
    assert.equal((style.fill as { fgColor: { argb: string } }).fgColor.argb, "FF000000");
    assert.ok(style.border?.bottom);
    assert.deepEqual(base.views, [{ state: "frozen", ySplit: 1 }]);
    assert.ok(base.autoFilter);
    assert.equal(base.properties.tabColor?.argb, "FFFFE600", "abas amarelas");

    // Every CVE carries its two canonical references, styled like Excel links.
    assert.deepEqual(base.getRow(2).getCell(2).value, {
        text: "Microsoft",
        hyperlink: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68820",
    });
    assert.deepEqual(base.getRow(2).getCell(3).value, {
        text: "NVD",
        hyperlink: "https://nvd.nist.gov/vuln/detail/CVE-2026-68820",
    });
    assert.deepEqual(base.getRow(2).getCell(2).font, { name: "Calibri", color: { argb: "FF0563C1" }, underline: true });

    // Values: MSRC terms untouched, our own labels in PT-BR.
    assert.equal(base.getRow(2).getCell(4).value, "Important");
    assert.equal(base.getRow(2).getCell(6).value, "Elevation of Privilege");
    assert.equal(base.getRow(2).getCell(8).value, "Microsoft");
    assert.equal(base.getRow(2).getCell(9).value, "Sim", "booleano em PT-BR");
    assert.equal(base.getRow(3).getCell(8).value, "Upstream republicado", "linhas upstream vão marcadas, não sumidas");

    // No colour on data rows — the reader filters by column instead.
    assert.equal(base.getRow(2).getCell(4).fill, undefined);
    assert.equal(base.getRow(2).getCell(4).font, undefined);

    assert.equal(patchTuesdayExcelFilename(sample), "Patch-Tuesday-Microsoft-2026-Aug.xlsx");
    assert.equal(patchTuesdayExcelFilename({ ...sample, id: "" }), "Patch-Tuesday-Microsoft-report.xlsx");
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
    for (const identifier of [...publisherNamePatterns, /\bcliente\b/i, /\bconsultoria\b/i]) {
        assert.doesNotMatch(xml, identifier, String(identifier));
    }
});

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/;

// The deck is opened in Microsoft PowerPoint, which is far stricter than
// LibreOffice: a dangling rId, a part with no content type, or a stray `&`
// coming from an MSRC title all produce the "needs repair" dialog instead of a
// slide. MSRC titles are attacker-influenced free text, so they get fuzzed here.
test("o pacote abre no PowerPoint: rIds resolvem, partes declaradas, texto escapado", async () => {
    const runtimeRequire = createRequire(`${process.cwd()}/package.json`);
    const JSZip = runtimeRequire("jszip") as typeof import("jszip");
    const PptxGenJS = runtimeRequire("pptxgenjs") as typeof import("pptxgenjs").default;
    const ExcelJS = runtimeRequire("exceljs") as typeof import("exceljs");
    const hostile = 'Windows <Shell> & "Print" Spooler \u0007 Elevation of Privilege';
    const fuzzed = {
        ...sample,
        title: hostile,
        topCves: [cve({ title: hostile })],
        byFamily: [{ name: hostile, count: 3 }],
        vulnerabilities: [cve({ title: hostile, family: hostile })],
    };
    const bytes = await buildPatchTuesdayPresentation(fuzzed, PptxGenJS).write({ outputType: "nodebuffer" });
    const zip = await JSZip.loadAsync(bytes as ArrayBuffer);
    const part = (name: string) => zip.file(name)?.async("string") ?? Promise.resolve("");

    const types = await part("[Content_Types].xml");
    const parts = Object.keys(zip.files).filter((n) => !zip.files[n].dir && n.endsWith(".xml") && !n.includes("/_rels/"));
    assert.ok(parts.some((n) => /^ppt\/slides\/slide\d+\.xml$/.test(n)), "o pacote tem slides");

    // The workbook is the attachment that ships with the deck; Excel is just as
    // strict about the package, and it reads the same MSRC free text.
    const xlsx = await JSZip.loadAsync(
        (await buildPatchTuesdayWorkbook(fuzzed, ExcelJS).xlsx.writeBuffer()) as ArrayBuffer
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

test("títulos longos são condensados no slide e preservados nas notas", async () => {
    const long = "A".repeat(140);
    const { slides, notes } = await buildXml({ ...sample, topCves: [cve({ title: long })] });
    assert.doesNotMatch(slides, new RegExp("A{140}"), "o card não recebe o título inteiro");
    assert.match(slides, new RegExp("A{129}…"), "condensado no card de highlight");
    assert.match(notes, new RegExp("Título completo: A{140}"), "íntegro nas notas do apresentador");
});
