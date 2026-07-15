import test from "node:test";
import assert from "node:assert/strict";
import {
    buildSapReportAnalysis,
    classifySapNote,
    identifySapProduct,
} from "./sapPatchAnalysis.ts";
import type { SapNote, SapPatchSummary } from "@/services/sapApi";

const note = (title: string): SapNote => ({
    note: "1000000",
    noteUrl: "https://me.sap.com/notes/1000000",
    title,
    cves: [],
    priority: "Medium",
    cvss: null,
    cvssVector: null,
    isUpdate: false,
});

const noteWith = (overrides: Partial<SapNote>): SapNote => ({
    ...note("Security issue in SAP component"),
    ...overrides,
});

const summary = (notes: SapNote[]): SapPatchSummary => {
    const byPriority = notes.reduce<Record<string, number>>((counts, item) => {
        counts[item.priority] = (counts[item.priority] ?? 0) + 1;
        return counts;
    }, {});

    return {
        url: "https://support.sap.com/security-notes.html",
        releaseDate: "2026-07-14",
        notes,
        summary: {
            total: notes.length,
            byPriority,
            hotNews: notes.filter((item) => /hot news|critical/i.test(item.priority)).length,
            high: notes.filter((item) => /high/i.test(item.priority)).length,
            maxCvss: Math.max(0, ...notes.map((item) => item.cvss ?? 0)),
            cveCount: new Set(notes.flatMap((item) => item.cves)).size,
        },
    };
};

test("classifica títulos SAP com precedência determinística", () => {
    assert.equal(classifySapNote(note("Remote Code Execution and SQL Injection")), "RCE / Corrupção de memória");
    assert.equal(classifySapNote(note("Sample credentials in Commerce Cloud")), "Configuração / Credenciais");
    assert.equal(classifySapNote(note("Missing Authorization check")), "Ausência de autorização");
    assert.equal(classifySapNote(note("Cross-Site Scripting (XSS)")), "Injeção");
    assert.equal(classifySapNote(note("Directory Traversal and Information Disclosure")), "Traversal / Divulgação");
    assert.equal(classifySapNote(note("HTTP Request Smuggling")), "Falsificação / Redirecionamento");
    assert.equal(classifySapNote(note("Improper error handling")), "Outras");
});

test("reconhece todos os termos de classificação especificados", () => {
    const cases: Array<[string, string[]]> = [
        ["RCE / Corrupção de memória", ["Remote Code Execution", "RCE", "Memory corruption", "Code execution"]],
        ["Configuração / Credenciais", ["Credential leak", "Password issue", "Configuration issue", "Misconfiguration", "Authentication issue"]],
        ["Ausência de autorização", ["Missing authorization", "Authorization check", "Privilege issue"]],
        ["Injeção", ["Command injection", "XSS", "Cross-site scripting", "SQL issue", "CSS issue"]],
        ["Traversal / Divulgação", ["Directory traversal", "Information disclosure", "Information exposure", "Path issue"]],
        ["Falsificação / Redirecionamento", ["Request spoofing", "Request smuggling", "Open redirect"]],
    ];

    for (const [category, titles] of cases) {
        for (const title of titles) assert.equal(classifySapNote(note(title)), category, title);
    }
});

test("identifica produtos conhecidos e usa fallback neutro", () => {
    const cases: Array<[string, string]> = [
        ["Issue in SAP NetWeaver AS ABAP", "SAP NetWeaver AS ABAP"],
        ["Issue in SAP NetWeaver AS Java", "SAP NetWeaver AS Java"],
        ["HTTP Request Smuggling in SAP Approuter", "SAP Approuter"],
        ["Issue in SAP Commerce Cloud", "SAP Commerce Cloud"],
        ["Issue in Edge Integration Cell", "SAP Integration Suite"],
        ["Issue in SAProuter", "SAProuter"],
        ["Issue in SAP S/4HANA", "SAP S/4HANA"],
        ["Issue in SAP Fiori", "SAP Fiori"],
        ["Issue in SAP CRM", "SAP CRM"],
        ["Issue in SAP WebComponents", "SAP UI5"],
        ["Issue in SAP HANA", "SAP HANA"],
    ];

    for (const [title, product] of cases) assert.equal(identifySapProduct(note(title)), product, title);
    assert.equal(identifySapProduct(note("Security issue in an unnamed component")), "Componente SAP não especificado");
});

test("ordena Top 3 por CVSS, prioridade e número da nota", () => {
    const analysis = buildSapReportAnalysis(summary([
        noteWith({ note: "4", cvss: 8.0, priority: "High" }),
        noteWith({ note: "5", cvss: 9.0, priority: "High" }),
        noteWith({ note: "3", cvss: 9.0, priority: "High" }),
        noteWith({ note: "2", cvss: 9.0, priority: "Critical" }),
        noteWith({ note: "1", cvss: null, priority: "Critical", cves: [] }),
    ]));

    assert.deepEqual(analysis.topThree.map((item) => item.note), ["2", "3", "5"]);
    assert.equal(analysis.notes.at(-1)?.primaryCve, "Não informada");
});

test("agrega produtos e categorias em ordem determinística", () => {
    const analysis = buildSapReportAnalysis(summary([
        noteWith({ title: "Remote Code Execution in SAP HANA", cves: ["CVE-2026-1"] }),
        noteWith({ title: "XSS in SAP HANA", cves: ["CVE-2026-2"] }),
        noteWith({ title: "XSS in SAP Commerce Cloud", cves: ["CVE-2026-3"] }),
    ]));

    assert.deepEqual(analysis.products, ["SAP HANA", "SAP Commerce Cloud"]);
    assert.deepEqual(analysis.categoryCounts, [
        { category: "RCE / Corrupção de memória", count: 1 },
        { category: "Injeção", count: 2 },
    ]);
    assert.equal(analysis.notes[0].primaryCve, "CVE-2026-1");
});

test("produz resumo, prioridades e seis recomendações neutras mesmo sem notas", () => {
    const analysis = buildSapReportAnalysis(summary([]));

    assert.match(analysis.executiveSummary, /0 notas/);
    assert.ok(analysis.immediatePriorities.length > 0);
    assert.deepEqual(analysis.recommendations.map((item) => item.title), [
        "Correção emergencial",
        "Proteção de integração e borda",
        "Higiene de credenciais e configuração",
        "Componentes descontinuados ou sem correção indicada",
        "Aplicações de negócio ABAP/Java",
        "Implantação e governança",
    ]);
    for (const recommendation of analysis.recommendations) {
        assert.ok(recommendation.body.length > 0);
        assert.doesNotMatch(recommendation.body, /foi identificad[ao]|há falha|vulnerabilidade presente/i);
    }
    assert.doesNotMatch(
        [...analysis.immediatePriorities, ...analysis.recommendations.map((item) => item.body)].join(" "),
        /0 notas/,
    );
});

test("usa concordância singular nos textos para uma nota", () => {
    const analysis = buildSapReportAnalysis(summary([
        noteWith({ title: "Credential issue in SAP HANA", priority: "High" }),
    ]));
    const text = [
        analysis.executiveSummary,
        ...analysis.immediatePriorities,
        ...analysis.recommendations.map((item) => item.body),
    ].join(" ");

    assert.match(analysis.executiveSummary, /1 nota analisada/);
    assert.match(text, /Priorizar a 1 nota de severidade/);
    assert.match(text, /a 1 nota classificada nessa categoria/);
    assert.doesNotMatch(text, /1 notas|as 1 nota/);
});
