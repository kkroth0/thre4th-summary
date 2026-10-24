import { publisherNamePatterns } from './exportPublisher.testSupport';
import assert from "node:assert/strict";
import test from "node:test";
import type { PatchTuesdaySummary, PatchVulnerability } from "@/services/msrcApi";
import {
    buildPatchTuesdayCtiflowDeck,
    patchTuesdayCtiflowFilename,
    CTIFLOW_SCHEMA,
} from "./patchTuesdayCtiflow";

const cve = (over: Partial<PatchVulnerability> = {}): PatchVulnerability => ({
    cve: "CVE-2026-68820",
    title: "Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability",
    description: "",
    cwe: "CWE-416",
    severity: "Important",
    impact: "Elevation of Privilege",
    cvss: 7.8,
    vector: "",
    exploited: false,
    publiclyDisclosed: false,
    exploitability: "Exploitation More Likely",
    upstream: false,
    family: "Windows",
    productCount: 12,
    kbs: [{ kb: "5065426", url: "https://catalog.update.microsoft.com/" }],
    releaseDate: null,
    ...over,
});

const sample: PatchTuesdaySummary = {
    id: "2026-Aug",
    title: "August 2026 Security Updates",
    initialReleaseDate: "2026-08-12T07:00:00",
    currentReleaseDate: "2026-08-12T07:00:00",
    totals: {
        total: 420, critical: 62, important: 355, moderate: 1, low: 0, unknown: 2,
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
        { name: "Developer Tools & .NET", count: 40 },
        { name: "Other Microsoft Products", count: 13 },
    ],
    topCves: [],
    vulnerabilities: [
        cve({ cve: "CVE-2026-68820", exploited: true, severity: "Important", exploitability: "Exploitation Detected" }),
        cve({ cve: "CVE-2026-62832", publiclyDisclosed: true, family: "Windows", title: "Windows User Profile Service Elevation of Privilege Vulnerability" }),
        cve({ cve: "CVE-2026-72971", publiclyDisclosed: true, impact: "Tampering", title: "Windows Container Isolation FS Filter Driver Tampering Vulnerability" }),
        cve({ cve: "CVE-2026-63508", severity: "Critical", impact: "Remote Code Execution", family: "Other Microsoft Products", title: "Microsoft Planetary Computer Pro RCE" }),
        cve({ cve: "CVE-2026-56162", severity: "Critical", impact: "Remote Code Execution", family: "Azure & Cloud", title: "Azure SQL Database RCE" }),
        cve({ cve: "CVE-2026-65667", severity: "Critical", impact: "Elevation of Privilege", family: "Other Microsoft Products", title: "Microsoft Teams Elevation of Privilege Vulnerability" }),
    ],
};

test("o deck do CTIFLOW carrega o esquema, as cinco telas e as métricas do sumário", () => {
    const deck = buildPatchTuesdayCtiflowDeck(sample);

    assert.equal(deck.schema, CTIFLOW_SCHEMA);
    assert.equal(deck.source.vendor, "Microsoft");
    assert.equal(deck.source.releaseId, "2026-Aug");

    // Numbers are the sumário's, not a recount.
    assert.equal(deck.metrics.total, 420);
    assert.equal(deck.metrics.critical, 62);
    assert.equal(deck.metrics.upstream, 329);
    // Zero-days = exploited OR publicly disclosed, de-duplicated across the catalog.
    assert.equal(deck.metrics.zeroDays, 3);

    for (const key of ["cover", "executiveSummary", "consolidated", "highlights", "recommendations"] as const) {
        assert.ok(deck.slides[key], `tela ${key} presente`);
    }
    assert.equal(deck.cycle.label, "Agosto/2026");
    assert.equal(deck.cycle.shortDatePt, "12/08/2026");
});

test("o texto pré-renderizado do sumário bate com os números do ciclo", () => {
    const { executiveSummary } = buildPatchTuesdayCtiflowDeck(sample).slides;

    assert.match(executiveSummary.paragraph, /O ciclo de agosto de 2026 corrige 420 vulnerabilidades/);
    assert.match(executiveSummary.paragraph, /62 críticas e 3 zero-days/);
    assert.match(executiveSummary.paragraph, /329 CVEs de código upstream/);
    assert.match(executiveSummary.paragraph, /Chromium\/Edge e pacotes do Azure Linux/);

    // Four bullets: exploited, disclosed, families to accelerate, deployment hygiene.
    assert.equal(executiveSummary.immediatePriorities.length, 4);
    assert.match(executiveSummary.immediatePriorities[0], /Priorizar imediatamente Windows/);
    // Family chart names are the PT-BR forms.
    assert.deepEqual(
        executiveSummary.affectedProductsChart.map((r) => r.name),
        ["Windows", "Microsoft Office", "Ferramentas de desenvolvimento e .NET", "Outros produtos Microsoft"]
    );
});

test("consolidado e highlights trazem os cartões prontos para o template", () => {
    const { consolidated, highlights } = buildPatchTuesdayCtiflowDeck(sample).slides;

    assert.deepEqual(consolidated.kpis, [
        { value: 420, label: "VULNERABILIDADES" },
        { value: 3, label: "VULNERABILIDADES ZERO DAY" },
        { value: 62, label: "VULNERABILIDADES CRÍTICAS" },
    ]);
    assert.equal(consolidated.zeroDayCards.length, 3);
    assert.equal(consolidated.zeroDayCards[0].cve, "CVE-2026-68820");
    assert.equal(consolidated.zeroDayCards[0].status, "Exploração ativa");
    assert.equal(consolidated.impactGlossary.length, 7);

    // Highlights: zero-days lead, at most six, tag is "Impacto curto | Status".
    assert.ok(highlights.cards.length <= 6);
    assert.equal(highlights.cards[0].cve, "CVE-2026-68820");
    assert.equal(highlights.cards[0].tag, "EoP | Explor. ativa");
    assert.match(highlights.speakerNotes, /Título completo:/);
});

test("a tela de conclusão traz seis recomendações, a primeira orientada pelo dado", () => {
    const { recommendations } = buildPatchTuesdayCtiflowDeck(sample).slides;

    assert.equal(recommendations.blocks.length, 6);
    assert.deepEqual(
        recommendations.blocks.map((b) => b.title),
        [
            "Correção Prioritária",
            "Infraestrutura Crítica",
            "Segurança dos Endpoints",
            "Proteção da Identidade",
            "Aplicações Corporativas",
            "Implantação e Governança",
        ]
    );
    // Block 1 names the actively exploited CVE.
    assert.match(recommendations.blocks[0].body, /CVE-2026-68820/);
    assert.match(recommendations.blocks[0].body, /exploração ativa/);

    // With nothing exploited or disclosed, block 1 falls back to the critical count.
    const quiet = buildPatchTuesdayCtiflowDeck({
        ...sample,
        totals: { ...sample.totals, exploited: 0, disclosed: 0 },
        vulnerabilities: sample.vulnerabilities.map((v) => ({ ...v, exploited: false, publiclyDisclosed: false })),
    });
    assert.match(quiet.slides.recommendations.blocks[0].body, /62 correções de severidade crítica/);
});

test("o JSON não identifica a consultoria nem o cliente", () => {
    const json = JSON.stringify(buildPatchTuesdayCtiflowDeck(sample));
    for (const identifier of [...publisherNamePatterns, /Votorantim/i, /\bcliente\b/i, /\bconsultoria\b/i]) {
        assert.doesNotMatch(json, identifier, String(identifier));
    }
    // The audience line is a slot CTIFLOW fills, left blank by the app.
    assert.equal(buildPatchTuesdayCtiflowDeck(sample).slides.cover.audienceLine, "");
});

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/;

test("títulos hostis do MSRC são higienizados antes de virar JSON", () => {
    const hostile = `Windows <Shell> & "Print" Spooler ${String.fromCharCode(7)} Elevation of Privilege`;
    const deck = buildPatchTuesdayCtiflowDeck({
        ...sample,
        title: hostile,
        vulnerabilities: [cve({ title: hostile, family: hostile, exploited: true })],
    });
    assert.doesNotMatch(JSON.stringify(deck), CONTROL_CHARS);
});

test("o nome do arquivo carrega o id do ciclo", () => {
    assert.equal(patchTuesdayCtiflowFilename(sample), "Patch-Tuesday-2026-Aug-ctiflow.json");
    assert.equal(patchTuesdayCtiflowFilename({ ...sample, id: "" }), "Patch-Tuesday-report-ctiflow.json");
});
