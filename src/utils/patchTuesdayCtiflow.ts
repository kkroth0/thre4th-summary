// CTIFLOW export: the Patch Tuesday cycle as a JSON document shaped like the
// five-slide deck the CTI team hands over (capa → sumário executivo →
// consolidado → highlights → conclusão e recomendações). CTIFLOW reads this to
// fill a pre-built .pptx template, so every field it needs is here already
// rendered in PT-BR — the same sentences the native PowerPoint export writes,
// composed from patchTuesdayDeckContent so the two can never disagree.
import type { PatchTuesdaySummary, PatchVulnerability, NamedCount } from '@/services/msrcApi';
import {
    scrubXml, msrcCveUrl, nvdCveUrl, monthSlashYear, fmtMonthPt, fmtLongDatePt, fmtShortDatePt,
} from './deckTemplate';
import {
    familyPt, impactShort, severityPt, statusTagPt, statusLabelPt, condenseTitle,
    zeroDays, criticalImpactMix, criticalImpactLines, executiveParagraph, zeroDaysLine,
    upstreamNote, immediatePriorities, IMPACT_GLOSSARY, recommendationBlocks, highlightSpeakerNotes,
    type RecommendationBlock,
} from './patchTuesdayDeckContent';

export const CTIFLOW_SCHEMA = 'ctiflow.patch-tuesday/v1' as const;

// ---- Shapes ---------------------------------------------------------------

export interface CtiflowCve {
    cve: string;
    title: string;
    titleCondensed: string;
    description: string;
    cwe: string;
    severity: string; // MSRC term, kept in English
    severityPt: string;
    impact: string; // MSRC term, kept in English
    impactShort: string;
    cvss: number | null;
    vector: string;
    exploited: boolean;
    publiclyDisclosed: boolean;
    exploitability: string;
    zeroDay: boolean;
    upstream: boolean;
    family: string; // MSRC family
    familyPt: string;
    productCount: number;
    // Tag used on the highlight cards ("EoP | Explor. ativa") and the spelled-out
    // form used on the consolidated slide's mini cards.
    statusTag: string;
    statusLabel: string;
    kbs: { kb: string; url: string }[];
    links: { msrc: string; nvd: string };
}

export interface CtiflowDeck {
    schema: typeof CTIFLOW_SCHEMA;
    generatedAt: string;
    source: {
        vendor: 'Microsoft';
        feed: 'MSRC CVRF v3.0';
        releaseId: string;
        releaseNotesUrl: string;
        apiUrl: string;
    };
    cycle: {
        id: string;
        title: string;
        label: string; // "Agosto/2026"
        monthYear: string; // "agosto de 2026"
        initialReleaseDate: string | null;
        currentReleaseDate: string | null;
        longDatePt: string; // "12 de Agosto de 2026"
        shortDatePt: string; // "12/08/2026"
    };
    metrics: {
        total: number;
        critical: number;
        important: number;
        moderate: number;
        low: number;
        unrated: number;
        exploited: number;
        disclosed: number;
        exploitMoreLikely: number;
        zeroDays: number;
        upstream: number;
    };
    distributions: {
        bySeverity: NamedCount[];
        byImpact: NamedCount[];
        byFamily: NamedCount[];
        criticalByImpact: NamedCount[];
    };
    zeroDays: CtiflowCve[];
    highlights: CtiflowCve[];
    catalog: CtiflowCve[];
    slides: {
        cover: {
            title: string;
            subtitle: string;
            consolidatedLabel: string;
            dateText: string;
            // CTIFLOW injects the audience line ("Equipe de inteligência para a organização destinatária…").
            // The app never emits a client or consultancy name of its own.
            audienceLine: string;
        };
        executiveSummary: {
            heading: string;
            bandTitle: string;
            paragraph: string;
            zeroDaysLine: string;
            upstreamNote: string;
            affectedProductsChart: NamedCount[];
            immediatePriorities: string[];
        };
        consolidated: {
            heading: string;
            kpis: { value: number; label: string }[];
            impactChart: NamedCount[];
            impactGlossary: string[];
            zeroDayCards: {
                cve: string;
                familyPt: string;
                status: string;
                titleCondensed: string;
                url: string;
            }[];
            criticalImpactMix: string[];
            attachmentNote: string;
        };
        highlights: {
            heading: string;
            intro: string;
            cards: {
                cve: string;
                familyPt: string;
                tag: string;
                titleCondensed: string;
                severity: string;
                cvss: number | null;
                url: string;
            }[];
            attachmentNote: string;
            speakerNotes: string;
        };
        recommendations: {
            heading: string;
            blocks: RecommendationBlock[];
        };
    };
}

const ATTACHMENT_NOTE = 'A Listagem de Vulnerabilidades encontra-se no arquivo anexado ao e-mail.';

const toCtiflowCve = (v: PatchVulnerability): CtiflowCve => ({
    cve: v.cve,
    title: v.title,
    titleCondensed: condenseTitle(v.title, 130),
    description: v.description,
    cwe: v.cwe,
    severity: v.severity,
    severityPt: severityPt(v.severity),
    impact: v.impact,
    impactShort: impactShort(v.impact),
    cvss: v.cvss,
    vector: v.vector,
    exploited: v.exploited,
    publiclyDisclosed: v.publiclyDisclosed,
    exploitability: v.exploitability,
    zeroDay: v.exploited || v.publiclyDisclosed,
    upstream: v.upstream,
    family: v.family,
    familyPt: familyPt(v.family),
    productCount: v.productCount,
    statusTag: statusTagPt(v),
    statusLabel: statusLabelPt(v),
    kbs: v.kbs,
    links: { msrc: msrcCveUrl(v.cve), nvd: nvdCveUrl(v.cve) },
});

// Highlights lead with the zero-days, then the top CVEs, de-duplicated — the
// same selection the PowerPoint highlights slide makes, at the same length.
const highlightSet = (s: PatchTuesdaySummary): PatchVulnerability[] => {
    const zds = zeroDays(s);
    const listed = new Set(zds.map((v) => v.cve));
    return [...zds, ...s.topCves.filter((v) => !listed.has(v.cve))].slice(0, 6);
};

export function buildPatchTuesdayCtiflowDeck(rawSummary: PatchTuesdaySummary): CtiflowDeck {
    const s = scrubXml(rawSummary);
    const t = s.totals;
    const zds = zeroDays(s);
    const highlights = highlightSet(s);
    const date = s.initialReleaseDate;

    const bySeverity: NamedCount[] = [
        { name: 'Critical', count: t.critical },
        { name: 'Important', count: t.important },
        { name: 'Moderate', count: t.moderate },
        { name: 'Low', count: t.low },
        { name: 'Sem classificação', count: t.unknown },
    ];

    const deck: CtiflowDeck = {
        schema: CTIFLOW_SCHEMA,
        generatedAt: new Date().toISOString(),
        source: {
            vendor: 'Microsoft',
            feed: 'MSRC CVRF v3.0',
            releaseId: s.id,
            releaseNotesUrl: `https://msrc.microsoft.com/update-guide/releaseNote/${s.id}`,
            apiUrl: `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/${s.id}`,
        },
        cycle: {
            id: s.id,
            title: s.title,
            label: monthSlashYear(date),
            monthYear: fmtMonthPt(date),
            initialReleaseDate: s.initialReleaseDate,
            currentReleaseDate: s.currentReleaseDate,
            longDatePt: fmtLongDatePt(date),
            shortDatePt: fmtShortDatePt(date),
        },
        metrics: {
            total: t.total,
            critical: t.critical,
            important: t.important,
            moderate: t.moderate,
            low: t.low,
            unrated: t.unknown,
            exploited: t.exploited,
            disclosed: t.disclosed,
            exploitMoreLikely: t.exploitMoreLikely,
            zeroDays: zds.length,
            upstream: t.upstream,
        },
        distributions: {
            bySeverity,
            byImpact: s.byImpact,
            byFamily: s.byFamily,
            criticalByImpact: criticalImpactMix(s),
        },
        zeroDays: zds.map(toCtiflowCve),
        highlights: highlights.map(toCtiflowCve),
        catalog: s.vulnerabilities.map(toCtiflowCve),
        slides: {
            cover: {
                title: 'Microsoft Patch Tuesday',
                subtitle: 'Cyber Threat Intelligence and Hunting',
                consolidatedLabel: `Consolidado - ${monthSlashYear(date)}`,
                dateText: fmtLongDatePt(date),
                audienceLine: '',
            },
            executiveSummary: {
                heading: 'Sumário Executivo',
                bandTitle: `Microsoft Patch Tuesday (${monthSlashYear(date)})`,
                paragraph: executiveParagraph(s),
                zeroDaysLine: zeroDaysLine(s),
                upstreamNote: upstreamNote(s),
                affectedProductsChart: s.byFamily.slice(0, 8).map((f) => ({ name: familyPt(f.name), count: f.count })),
                immediatePriorities: immediatePriorities(s),
            },
            consolidated: {
                heading: 'Consolidado de Vulnerabilidades',
                kpis: [
                    { value: t.total, label: 'VULNERABILIDADES' },
                    { value: zds.length, label: 'VULNERABILIDADES ZERO DAY' },
                    { value: t.critical, label: 'VULNERABILIDADES CRÍTICAS' },
                ],
                impactChart: s.byImpact.slice(0, 7),
                impactGlossary: IMPACT_GLOSSARY,
                zeroDayCards: zds.slice(0, 3).map((v) => ({
                    cve: v.cve,
                    familyPt: familyPt(v.family),
                    status: statusLabelPt(v),
                    titleCondensed: condenseTitle(v.title, 120),
                    url: msrcCveUrl(v.cve),
                })),
                criticalImpactMix: criticalImpactLines(s),
                attachmentNote: ATTACHMENT_NOTE,
            },
            highlights: {
                heading: 'Highlights: Vulnerabilidades Críticas',
                intro: 'Seleção orientada ao risco corporativo e à exploração observada:',
                cards: highlights.map((v) => ({
                    cve: v.cve,
                    familyPt: familyPt(v.family),
                    tag: `${impactShort(v.impact)} | ${statusTagPt(v)}`,
                    titleCondensed: condenseTitle(v.title, 130),
                    severity: v.severity,
                    cvss: v.cvss,
                    url: msrcCveUrl(v.cve),
                })),
                attachmentNote: ATTACHMENT_NOTE,
                speakerNotes: highlightSpeakerNotes(highlights),
            },
            recommendations: {
                heading: 'Conclusão e Recomendações',
                blocks: recommendationBlocks(s),
            },
        },
    };

    return scrubXml(deck);
}

export const patchTuesdayCtiflowFilename = (s: PatchTuesdaySummary) =>
    `Patch-Tuesday-${s.id || 'report'}-ctiflow.json`;

const triggerDownload = (content: string, filename: string) => {
    const blob = new Blob([content], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
};

export function exportPatchTuesdayCtiflowJSON(summary: PatchTuesdaySummary): void {
    const deck = buildPatchTuesdayCtiflowDeck(summary);
    triggerDownload(JSON.stringify(deck, null, 2), patchTuesdayCtiflowFilename(summary));
}
