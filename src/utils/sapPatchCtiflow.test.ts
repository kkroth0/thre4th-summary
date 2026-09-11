import assert from "node:assert/strict";
import test from "node:test";
import type { SapNote, SapPatchSummary } from "@/services/sapApi";
import {
    buildSapPatchCtiflowDeck,
    sapPatchCtiflowFilename,
    SAP_CTIFLOW_SCHEMA,
} from "./sapPatchCtiflow";

const note = (over: Partial<SapNote> = {}): SapNote => ({
    note: "3747367",
    noteUrl: "https://me.sap.com/notes/3747367",
    title: "Remote Code Execution vulnerability in SAP NetWeaver AS Java",
    cves: ["CVE-2026-12345"],
    priority: "Hot News",
    cvss: 9.9,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    isUpdate: false,
    ...over,
});

const sample: SapPatchSummary = {
    url: "https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html",
    releaseDate: "2026-08-11",
    notes: [
        note(),
        note({ note: "3747999", title: "Missing Authorization check in SAP Fiori", priority: "High", cvss: 7.5, cves: [], cvssVector: null }),
        note({ note: "3748001", title: "Hardcoded credential in SAP HANA configuration", priority: "Medium", cvss: 5.3, cves: ["CVE-2026-54321"], isUpdate: true, noteUrl: "https://me.sap.com/notes/3748001" }),
    ],
    summary: {
        total: 3,
        byPriority: { "Hot News": 1, High: 1, Medium: 1 },
        hotNews: 1,
        high: 1,
        maxCvss: 9.9,
        cveCount: 2,
    },
};

test("o deck do CTIFLOW carrega o esquema, o ciclo e as métricas do sumário", () => {
    const deck = buildSapPatchCtiflowDeck(sample);

    assert.equal(deck.schema, SAP_CTIFLOW_SCHEMA);
    assert.equal(deck.source.vendor, "SAP");
    assert.equal(deck.source.url, sample.url);

    assert.equal(deck.metrics.total, 3);
    assert.equal(deck.metrics.hotNews, 1);
    assert.equal(deck.metrics.maxCvss, 9.9);
    assert.equal(deck.metrics.cveCount, 2);

    assert.equal(deck.cycle.label, "Agosto/2026");
    assert.equal(deck.cycle.shortDatePt, "11/08/2026");

    for (const key of ["cover", "executiveSummary", "consolidated", "highlights", "recommendations", "references"] as const) {
        assert.ok(deck.slides[key], `tela ${key} presente`);
    }
});

test("o texto pré-renderizado do sumário bate com os números do ciclo", () => {
    const { executiveSummary } = buildSapPatchCtiflowDeck(sample).slides;

    assert.match(executiveSummary.paragraph, /O ciclo de agosto de 2026 publica 3 notas de segurança/);
    assert.match(executiveSummary.paragraph, /1 críticas e 1 altas/);
    assert.match(executiveSummary.paragraph, /CVSS máximo de 9\.9/);
    assert.match(executiveSummary.paragraph, /2 CVE\(s\) referenciada\(s\)/);
    // The dynamic analysis sentence rides along, not just the numeric prefix.
    assert.match(executiveSummary.paragraph, /notas? analisadas?/);

    assert.equal(executiveSummary.immediatePriorities.length, 3);
});

test("consolidado e highlights trazem os cartões prontos para o template", () => {
    const { consolidated, highlights } = buildSapPatchCtiflowDeck(sample).slides;

    assert.deepEqual(consolidated.kpis, [
        { value: "3", label: "NOTAS DE SEGURANÇA" },
        { value: "1", label: "NOTAS CRÍTICAS (HOT NEWS)" },
        { value: "9.9", label: "CVSS MÁXIMO DO CICLO" },
    ]);
    assert.ok(consolidated.topThreeCards.length <= 3);
    assert.equal(consolidated.topThreeCards[0].note, "SAP Note 3747367");
    assert.equal(consolidated.categoryGlossary.length > 0, true);

    assert.ok(highlights.cards.length <= 6);
    assert.equal(highlights.cards[0].note, "SAP Note 3747367");
    assert.match(highlights.cards[0].tag, /CVE-2026-12345/);
    assert.match(highlights.speakerNotes, /Título completo:/);

    // The updated note carries its own marker through to the card.
    const updated = highlights.cards.find((c) => c.note.includes("3748001"));
    assert.ok(updated?.note.includes("atualizada"));
});

test("recomendações e referências saem prontas, sem duplicar links", () => {
    const { recommendations, references } = buildSapPatchCtiflowDeck(sample).slides;

    assert.equal(recommendations.blocks.length, 6);
    assert.equal(recommendations.blocks[0].title, "Correção emergencial");
    assert.deepEqual(recommendations.blocks.map((b) => b.index), [1, 2, 3, 4, 5, 6]);

    assert.ok(references.links.includes(sample.url));
    assert.ok(references.links.includes("https://me.sap.com/notes/3747367"));
    // Unique — the SAP url and a note url never collide, but repeats among
    // notes must still collapse to one entry.
    assert.equal(references.links.length, new Set(references.links).size);
});

test("o JSON não identifica a consultoria nem o cliente", () => {
    const json = JSON.stringify(buildSapPatchCtiflowDeck(sample));
    for (const identifier of [/\bEY\b/i, /Ernst\s*&\s*Young/i, /Votorantim/i, /\bcliente\b/i, /\bconsultoria\b/i]) {
        assert.doesNotMatch(json, identifier, String(identifier));
    }
    assert.equal(buildSapPatchCtiflowDeck(sample).slides.cover.audienceLine, "");
});

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/;

test("títulos hostis da SAP são higienizados antes de virar JSON", () => {
    const hostile = `SAP <Shell> & "Note" Title ${String.fromCharCode(7)} Vulnerability`;
    const deck = buildSapPatchCtiflowDeck({
        ...sample,
        notes: [note({ title: hostile })],
    });
    assert.doesNotMatch(JSON.stringify(deck), CONTROL_CHARS);
});

test("o nome do arquivo carrega o mês do ciclo", () => {
    assert.equal(sapPatchCtiflowFilename(sample), "SAP-Security-Patch-Day-2026-08-ctiflow.json");
    assert.equal(sapPatchCtiflowFilename({ ...sample, releaseDate: null }), "SAP-Security-Patch-Day-mais-recente-ctiflow.json");
});
