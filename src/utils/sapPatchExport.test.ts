import assert from "node:assert/strict";
import test from "node:test";
import type { SapPatchSummary } from "@/services/sapApi";
import { buildSapPatchPresentation } from "./sapPatchExport";

class FakeSlide {
    texts: string[] = [];
    tables: unknown[][][] = [];
    background: unknown;
    addText(text: string | Array<{ text: string }>) {
        this.texts.push(typeof text === "string" ? text : text.map((run) => run.text).join(""));
    }
    addTable(rows: unknown[][]) { this.tables.push(rows); }
    addShape() {}
    addChart() {}
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
    assert.match(allText, /Não informado|9\.9/);
    assert.match(allText, /Não informada/);
    assert.match(allText, /Fonte oficial SAP/);
    assert.doesNotMatch(allText, /cliente|consultoria/i);
    assert.equal(pptx.slides[3].tables.length, 1);
    assert.equal(pptx.slides[3].tables[0].length, sample.notes.length + 1);
});
