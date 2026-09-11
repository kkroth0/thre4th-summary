// CTIFLOW export: the SAP Security Patch Day cycle as a JSON document shaped
// like the six-slide deck the CTI team hands over (capa → sumário executivo →
// consolidado → highlights → conclusão e recomendações → referências).
// CTIFLOW reads this to fill a pre-built .pptx template, so every field it
// needs is here already rendered in PT-BR — the same labels and sentences the
// native PowerPoint export writes, both composed from sapPatchAnalysis and
// sapPatchDeckContent so the two can never disagree.
import type { SapPatchSummary } from '@/services/sapApi';
import { buildSapReportAnalysis, type AnalyzedSapNote, type SapReportAnalysis } from './sapPatchAnalysis';
import { scrubXml, nvdCveUrl, monthSlashYear, fmtMonthPt, fmtLongDatePt, fmtShortDatePt, condenseTitle } from './deckTemplate';
import {
    SAP_REPORT, allCves, priorityLabel, cvssLabel, categoryGlossaryLines, categoryMixLines, noteSpeakerNotes,
} from './sapPatchDeckContent';

export const SAP_CTIFLOW_SCHEMA = 'ctiflow.sap-patch-day/v1' as const;

// ---- Shapes ---------------------------------------------------------------

export interface SapCtiflowNote {
    note: string;
    noteUrl: string;
    title: string;
    titleCondensed: string;
    cves: string[];
    cveList: string;
    priority: string; // SAP term, kept as published
    priorityPt: string;
    cvss: number | null;
    cvssLabel: string;
    cvssVector: string | null;
    category: string;
    product: string;
    isUpdate: boolean;
    links: { note: string | null; nvd: string | null };
}

export interface SapCtiflowDeck {
    schema: typeof SAP_CTIFLOW_SCHEMA;
    generatedAt: string;
    source: {
        vendor: 'SAP';
        feed: 'SAP Security Notes';
        url: string;
    };
    cycle: {
        releaseDate: string | null;
        label: string; // "Agosto/2026"
        monthYear: string; // "agosto de 2026"
        longDatePt: string;
        shortDatePt: string;
    };
    metrics: {
        total: number;
        hotNews: number;
        high: number;
        maxCvss: number;
        cveCount: number;
        byPriority: { name: string; count: number }[];
    };
    distributions: {
        byCategory: { name: string; count: number }[];
    };
    topThree: SapCtiflowNote[];
    highlights: SapCtiflowNote[];
    catalog: SapCtiflowNote[];
    slides: {
        cover: {
            title: string;
            subtitle: string;
            consolidatedLabel: string;
            dateText: string;
            // CTIFLOW injects the audience line. The app never emits a client
            // or consultancy name of its own.
            audienceLine: string;
        };
        executiveSummary: {
            heading: string;
            bandTitle: string;
            paragraph: string;
            categoryChart: { name: string; count: number }[];
            immediatePriorities: string[];
        };
        consolidated: {
            heading: string;
            kpis: { value: string; label: string }[];
            categoryChart: { name: string; count: number }[];
            categoryGlossary: string[];
            topThreeCards: {
                note: string;
                product: string;
                meta: string;
                titleCondensed: string;
                url: string | null;
            }[];
            categoryMix: string[];
            attachmentNote: string;
        };
        highlights: {
            heading: string;
            intro: string;
            cards: {
                note: string;
                product: string;
                tag: string;
                titleCondensed: string;
                url: string | null;
                isUpdate: boolean;
            }[];
            attachmentNote: string;
            speakerNotes: string;
        };
        recommendations: {
            heading: string;
            blocks: { index: number; title: string; body: string }[];
        };
        references: {
            heading: string;
            links: string[];
        };
    };
}

const ATTACHMENT_NOTE = 'A Listagem de Vulnerabilidades encontra-se no arquivo anexado ao e-mail.';

const toSapCtiflowNote = (note: AnalyzedSapNote): SapCtiflowNote => ({
    note: note.note,
    noteUrl: note.noteUrl,
    title: note.title,
    titleCondensed: condenseTitle(note.title, 130),
    cves: note.cves,
    cveList: allCves(note),
    priority: note.priority,
    priorityPt: priorityLabel(note.priority),
    cvss: note.cvss,
    cvssLabel: cvssLabel(note.cvss),
    cvssVector: note.cvssVector,
    category: note.category,
    product: note.product,
    isUpdate: note.isUpdate,
    links: {
        note: note.noteUrl || null,
        nvd: note.cves.length > 0 ? nvdCveUrl(note.cves[0]) : null,
    },
});

export function buildSapPatchCtiflowDeck(rawSummary: SapPatchSummary): SapCtiflowDeck {
    const summary = scrubXml(rawSummary);
    const analysis: SapReportAnalysis = buildSapReportAnalysis(summary);
    const date = summary.releaseDate;
    const highlights = analysis.notes.slice(0, 6);
    const categoryChart = analysis.categoryCounts.slice(0, 7).map(({ category, count }) => ({ name: category, count }));
    const links = [...new Set([summary.url, ...analysis.notes.map((note) => note.noteUrl)].filter(Boolean))];

    const deck: SapCtiflowDeck = {
        schema: SAP_CTIFLOW_SCHEMA,
        generatedAt: new Date().toISOString(),
        source: {
            vendor: 'SAP',
            feed: 'SAP Security Notes',
            url: summary.url,
        },
        cycle: {
            releaseDate: summary.releaseDate,
            label: monthSlashYear(date),
            monthYear: fmtMonthPt(date),
            longDatePt: fmtLongDatePt(date),
            shortDatePt: fmtShortDatePt(date),
        },
        metrics: {
            total: summary.summary.total,
            hotNews: summary.summary.hotNews,
            high: summary.summary.high,
            maxCvss: summary.summary.maxCvss,
            cveCount: summary.summary.cveCount,
            byPriority: Object.entries(summary.summary.byPriority).map(([priority, count]) => ({
                name: priorityLabel(priority),
                count,
            })),
        },
        distributions: {
            byCategory: analysis.categoryCounts.map(({ category, count }) => ({ name: category, count })),
        },
        topThree: analysis.topThree.map(toSapCtiflowNote),
        highlights: highlights.map(toSapCtiflowNote),
        catalog: analysis.notes.map(toSapCtiflowNote),
        slides: {
            cover: {
                title: SAP_REPORT,
                subtitle: 'Avaliação de riscos de vulnerabilidades',
                consolidatedLabel: `Consolidado - ${monthSlashYear(date)}`,
                dateText: fmtLongDatePt(date),
                audienceLine: '',
            },
            executiveSummary: {
                heading: 'Sumário executivo',
                bandTitle: `${SAP_REPORT} (${monthSlashYear(date)})`,
                paragraph:
                    `O ciclo de ${fmtMonthPt(date)} publica ${summary.summary.total} notas de segurança, ` +
                    `incluindo ${summary.summary.hotNews} críticas e ${summary.summary.high} altas, ` +
                    `com CVSS máximo de ${summary.summary.maxCvss.toFixed(1)} e ${summary.summary.cveCount} CVE(s) referenciada(s). ` +
                    analysis.executiveSummary,
                categoryChart,
                immediatePriorities: analysis.immediatePriorities,
            },
            consolidated: {
                heading: 'Consolidado de vulnerabilidades',
                kpis: [
                    { value: String(summary.summary.total), label: 'NOTAS DE SEGURANÇA' },
                    { value: String(summary.summary.hotNews), label: 'NOTAS CRÍTICAS (HOT NEWS)' },
                    { value: summary.summary.maxCvss.toFixed(1), label: 'CVSS MÁXIMO DO CICLO' },
                ],
                categoryChart,
                categoryGlossary: categoryGlossaryLines(analysis),
                topThreeCards: analysis.topThree.map((note) => ({
                    note: `SAP Note ${note.note}`,
                    product: note.product,
                    meta: `${priorityLabel(note.priority)} · CVSS ${cvssLabel(note.cvss)}`,
                    titleCondensed: condenseTitle(note.title, 120),
                    url: note.noteUrl || null,
                })),
                categoryMix: categoryMixLines(analysis),
                attachmentNote: ATTACHMENT_NOTE,
            },
            highlights: {
                heading: 'Highlights de vulnerabilidades',
                intro: 'Seleção orientada ao risco corporativo e à severidade publicada pela SAP:',
                cards: highlights.map((note) => ({
                    note: `SAP Note ${note.note}${note.isUpdate ? ' · atualizada' : ''}`,
                    product: note.product,
                    tag: `${allCves(note)} | ${priorityLabel(note.priority)} | CVSS ${cvssLabel(note.cvss)}`,
                    titleCondensed: condenseTitle(note.title, 130),
                    url: note.noteUrl || null,
                    isUpdate: note.isUpdate,
                })),
                attachmentNote: ATTACHMENT_NOTE,
                speakerNotes: noteSpeakerNotes(analysis.notes),
            },
            recommendations: {
                heading: 'Conclusão e recomendações',
                blocks: analysis.recommendations.map((item, index) => ({ index: index + 1, ...item })),
            },
            references: {
                heading: 'Referências',
                links,
            },
        },
    };

    return scrubXml(deck);
}

export const sapPatchCtiflowFilename = (s: SapPatchSummary) => {
    const month = s.releaseDate?.match(/^(\d{4})-(\d{2})/)?.slice(1).join('-');
    return `SAP-Security-Patch-Day-${month || 'mais-recente'}-ctiflow.json`;
};

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

export function exportSapPatchCtiflowJSON(summary: SapPatchSummary): void {
    const deck = buildSapPatchCtiflowDeck(summary);
    triggerDownload(JSON.stringify(deck, null, 2), sapPatchCtiflowFilename(summary));
}
