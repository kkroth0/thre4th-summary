// Document generators for the SAP Security Patch Day summary (PDF / PPTX / Excel).
// The deck and the workbook follow the team template in `deckTemplate`, the same
// one the Patch Tuesday report uses; only the PDF keeps its own plain layout.
// Heavy libs (jspdf, jspdf-autotable, pptxgenjs, exceljs) are typed-only here and
// imported lazily inside each exporter, so the page route stays light.
import type { jsPDF } from 'jspdf';
import type PptxGenJS from 'pptxgenjs';
import type ExcelJS from 'exceljs';
import type { SapPatchSummary } from '@/services/sapApi';
import { buildSapReportAnalysis, type AnalyzedSapNote, type SapReportAnalysis } from './sapPatchAnalysis';
import {
    DECK, FONT, FONT_LIGHT, LINK_FONT, SHEET_HEADER, SHEET_TAB,
    attachmentNote, condenseTitle, deckText, contentSlide, coverSlide, darkBarChart, deckMetadata, gradientBar,
    highlightCard, kpiPill, nvdCveUrl, scrubXml, styleHeaderRow, workbookMetadata,
    fmtMonthPt, monthSlashYear, type PptxFactory,
} from './deckTemplate';

const BRAND = '2563EB';

// Priority → fill color (Hot News/Critical red, High orange, Medium amber, Low green).
const PRIORITY_RANK: Record<string, number> = { 'Hot News': 4, Critical: 4, High: 3, Medium: 2, Low: 1 };
const priorityHex = (p: string) => {
    const r = PRIORITY_RANK[p] || 0;
    return r >= 4 ? 'DC2626' : r === 3 ? 'EA580C' : r === 2 ? 'CA8A04' : '64748B';
};

const fmtDate = (iso: string | null): string => {
    if (!iso) return 'N/A';
    const d = new Date(`${iso}T00:00:00Z`);
    return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString('en-US', { day: '2-digit', month: 'long', year: 'numeric', timeZone: 'UTC' });
};

export const sapPatchBaseFilename = (s: SapPatchSummary) => {
    const month = s.releaseDate?.match(/^(\d{4})-(\d{2})/)?.slice(1).join('-');
    return `SAP-Security-Patch-Day-${month || 'mais-recente'}`;
};
const rgb = (h: string): [number, number, number] => [0, 2, 4].map((o) => parseInt(h.substr(o, 2), 16)) as [number, number, number];

const kpiList = (s: SapPatchSummary) => [
    { label: 'Notes', value: s.summary.total, color: BRAND },
    { label: 'Hot News', value: s.summary.hotNews, color: 'DC2626' },
    { label: 'High', value: s.summary.high, color: 'EA580C' },
    { label: 'Max CVSS', value: s.summary.maxCvss.toFixed(1), color: 'B91C1C' },
    { label: 'CVEs', value: s.summary.cveCount, color: '7C3AED' },
];

const triggerDownload = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
};

// ---- PDF -----------------------------------------------------------------------
export async function exportSapPatchPDF(s: SapPatchSummary): Promise<void> {
    const [{ jsPDF }, { default: autoTable }] = await Promise.all([import('jspdf'), import('jspdf-autotable')]);
    const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
    const pageW = doc.internal.pageSize.getWidth();
    const margin = 14;

    doc.setFillColor(15, 23, 42);
    doc.rect(0, 0, pageW, 52, 'F');
    doc.setFillColor(37, 99, 235);
    doc.rect(0, 52, pageW, 2, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.text('SAP SECURITY PATCH DAY', margin, 18);
    doc.setFontSize(22);
    doc.text(fmtDate(s.releaseDate), margin, 30);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    doc.setTextColor(203, 213, 225);
    doc.text(`${s.summary.total} security notes`, margin, 40);
    doc.text('Source: support.sap.com', pageW - margin, 40, { align: 'right' });

    let y = 64;
    const kpis = kpiList(s);
    const gap = 4;
    const cardW = (pageW - margin * 2 - gap * (kpis.length - 1)) / kpis.length;
    kpis.forEach((k, i) => {
        const x = margin + i * (cardW + gap);
        doc.setDrawColor(226, 232, 240);
        doc.setFillColor(248, 250, 252);
        doc.roundedRect(x, y, cardW, 22, 2, 2, 'FD');
        const [r, g, b] = rgb(k.color);
        doc.setTextColor(r, g, b);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(16);
        doc.text(String(k.value), x + cardW / 2, y + 11, { align: 'center' });
        doc.setTextColor(100, 116, 139);
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(8);
        doc.text(k.label, x + cardW / 2, y + 17, { align: 'center' });
    });
    y += 32;

    autoTable(doc, {
        startY: y,
        head: [['Note#', 'Title', 'CVE', 'Priority', 'CVSS']],
        body: s.notes.map((n) => [n.note, n.title, n.cves.join(', '), n.priority, n.cvss ?? '—']),
        styles: { fontSize: 7, cellPadding: 1.5, overflow: 'linebreak' },
        headStyles: { fillColor: [15, 23, 42], textColor: 255 },
        columnStyles: { 0: { cellWidth: 18 }, 1: { cellWidth: 90 }, 2: { cellWidth: 30 }, 3: { cellWidth: 18 }, 4: { cellWidth: 12, halign: 'right' } },
        didParseCell: (d) => {
            if (d.section === 'body' && d.column.index === 3) {
                const [r, g, b] = rgb(priorityHex(String(d.cell.raw)));
                d.cell.styles.textColor = [r, g, b];
                d.cell.styles.fontStyle = 'bold';
            }
        },
        margin: { left: margin, right: margin },
    });

    doc.save(`${sapPatchBaseFilename(s)}.pdf`);
}

// ---- PPTX ----------------------------------------------------------------------
// Six slides on the template canvas: capa → sumário executivo → consolidado →
// highlights → conclusão → referências. The full note list lives in the attached
// workbook, exactly as the Patch Tuesday deck does it; the slides carry the
// selection a room can actually read.

const REPORT = 'SAP Security Patch Day';

const allCves = (note: { cves: string[] }): string => (note.cves.length > 0 ? note.cves.join(', ') : 'Não informada');

const priorityLabel = (priority: string): string => {
    if (/hot news/i.test(priority)) return 'Crítica (Hot News)';
    if (/critical/i.test(priority)) return 'Crítica';
    if (/high/i.test(priority)) return 'Alta';
    if (/medium/i.test(priority)) return 'Média';
    if (/low/i.test(priority)) return 'Baixa';
    return priority;
};

const cvssLabel = (cvss: number | null): string => (cvss == null ? 'Não informado' : cvss.toFixed(1));

const CATEGORY_EXPLANATIONS: Record<string, string> = {
    'RCE / Corrupção de memória': 'Execução de código ou comprometimento de memória.',
    'Configuração / Credenciais': 'Riscos associados a autenticação, senhas ou configuração.',
    'Ausência de autorização': 'Validações insuficientes de acesso ou privilégio.',
    'Injeção': 'Entrada não confiável interpretada por aplicações.',
    'Traversal / Divulgação': 'Acesso indevido a caminhos ou exposição de informações.',
    'Falsificação / Redirecionamento': 'Manipulação de identidade, tráfego ou destino.',
    'Outras': 'Demais tipos de vulnerabilidade publicados no ciclo.',
};

const addCoverSlide = (pptx: PptxGenJS, summary: SapPatchSummary): void => {
    const slide = coverSlide(pptx, REPORT, summary.releaseDate);
    deckText(slide, 'Avaliação de riscos de vulnerabilidades', {
        x: 0.67, y: 4.53, w: 4.654, h: 0.202,
        fontFace: FONT_LIGHT, fontSize: 11, color: DECK.white,
    });
};

const addExecutiveSummarySlide = (pptx: PptxGenJS, summary: SapPatchSummary, analysis: SapReportAnalysis): void => {
    const slide = contentSlide(pptx, 'Sumário executivo', 2, summary.releaseDate);

    // Header band, gradient like the rule but tall enough to carry the cycle name.
    gradientBar(pptx, slide, 0.469, 0.871, 8.968, 0.295);
    deckText(slide, `${REPORT} (${monthSlashYear(summary.releaseDate)})`, {
        x: 0.539, y: 0.871, w: 8.828, h: 0.295,
        fontFace: FONT, fontSize: 12, bold: true, color: DECK.ink, valign: 'middle',
    });

    const light = { fontFace: FONT_LIGHT, fontSize: 9, color: DECK.white };
    const strong = { fontFace: FONT, fontSize: 9, color: DECK.white, bold: true };
    deckText(slide, 
        [
            { text: `O ciclo de ${fmtMonthPt(summary.releaseDate)} publica `, options: light },
            { text: `${summary.summary.total} notas de segurança`, options: strong },
            { text: ', incluindo ', options: light },
            { text: `${summary.summary.hotNews} críticas e ${summary.summary.high} altas`, options: strong },
            { text: `, com CVSS máximo de ${summary.summary.maxCvss.toFixed(1)} e ${summary.summary.cveCount} CVE(s) referenciada(s). `, options: { ...light, breakLine: true } },
            { text: analysis.executiveSummary, options: light },
        ],
        { x: 0.477, y: 1.242, w: 8.968, h: 0.984, lineSpacingMultiple: 1.25, valign: 'middle' }
    );

    slide.addShape(pptx.ShapeType.roundRect, {
        x: 0.469, y: 2.46, w: 4.211, h: 2.332,
        rectRadius: 0.048, fill: { color: DECK.cardAlt }, line: { color: DECK.cardLine, width: 0.8 },
    });
    slide.addShape(pptx.ShapeType.roundRect, {
        x: 5.0, y: 2.46, w: 4.369, h: 2.353,
        rectRadius: 0.048, fill: { color: DECK.cardAlt }, line: { color: DECK.cardLine, width: 0.8 },
    });
    const cardLabel = { fontFace: FONT_LIGHT, fontSize: 12, bold: true, color: DECK.accent, valign: 'middle' as const };
    deckText(slide, 'Categorias x Número de Notas:', { x: 0.574, y: 2.572, w: 3.82, h: 0.25, ...cardLabel });
    deckText(slide, 'Prioridades imediatas', { x: 5.187, y: 2.581, w: 2.1, h: 0.225, ...cardLabel });

    darkBarChart(
        pptx, slide,
        analysis.categoryCounts.slice(0, 7).map(({ category, count }) => ({ name: category, count })),
        { x: 0.5, y: 2.86, w: 4.1, h: 1.86 },
        DECK.cardAlt
    );

    deckText(slide, 
        analysis.immediatePriorities.map((text) => ({ text, options: { breakLine: true, paraSpaceAfter: 6 } })),
        { x: 5.187, y: 2.822, w: 4.047, h: 1.95, fontFace: FONT_LIGHT, fontSize: 8, color: DECK.white, lineSpacingMultiple: 1.15 }
    );

    attachmentNote(slide);
};

const addConsolidatedSlide = (pptx: PptxGenJS, summary: SapPatchSummary, analysis: SapReportAnalysis): void => {
    const slide = contentSlide(pptx, 'Consolidado de vulnerabilidades', 3, summary.releaseDate);

    kpiPill(pptx, slide, String(summary.summary.total), 'NOTAS DE SEGURANÇA', { x: 0.477, y: 0.822, vw: 0.641, lw: 2.665, h: 0.354, valueSize: 15 });
    kpiPill(pptx, slide, String(summary.summary.hotNews), 'NOTAS CRÍTICAS (HOT NEWS)', { x: 5.254, y: 0.841, vw: 0.806, lw: 2.819, h: 0.371, valueSize: 15 });
    kpiPill(pptx, slide, summary.summary.maxCvss.toFixed(1), 'CVSS MÁXIMO DO CICLO', { x: 5.254, y: 2.776, vw: 0.836, lw: 2.781, h: 0.354, valueSize: 18 });

    gradientBar(pptx, slide, 4.742, 0.806, 0.038, 4.304, true);

    const sectionLabel = { fontFace: FONT, fontSize: 9, bold: true, color: DECK.accent, valign: 'middle' as const };
    deckText(slide, `Total de notas: ${summary.summary.total}`, { x: 0.481, y: 1.288, w: 2.849, h: 0.225, ...sectionLabel });
    darkBarChart(
        pptx, slide,
        analysis.categoryCounts.slice(0, 7).map(({ category, count }) => ({ name: category, count })),
        { x: 0.55, y: 1.474, w: 3.943, h: 1.691 },
        DECK.panel
    );

    deckText(slide, 'Descrição Executiva da Vulnerabilidade:', { x: 0.481, y: 3.13, w: 2.849, h: 0.225, ...sectionLabel });
    deckText(slide, 
        analysis.categoryCounts.map(({ category }) => ({
            text: `${category}: ${CATEGORY_EXPLANATIONS[category] ?? ''}`.trim(),
            options: { breakLine: true, bullet: true },
        })),
        { x: 0.469, y: 3.32, w: 4.441, h: 1.826, fontFace: FONT_LIGHT, fontSize: 8, color: DECK.white }
    );

    // Top-3 mini cards, right of the divider.
    analysis.topThree.forEach((note, index) => {
        const x = [5.268, 6.556, 7.812][index];
        const y = 1.381;
        slide.addShape(pptx.ShapeType.roundRect, {
            x, y, w: 1.096, h: 1.167,
            rectRadius: 0.024, fill: { color: DECK.card }, line: { color: DECK.red, width: 0.8 },
            shadow: { type: 'outer', color: '000000', opacity: 0.18, blur: 3, offset: 0.5, angle: 45 },
        });
        slide.addShape(pptx.ShapeType.rect, { x, y, w: 1.096, h: 0.062, fill: { color: DECK.red }, line: { type: 'none' } });
        slide.addShape(pptx.ShapeType.rect, { x: x + 0.006, y: 1.728, w: 1.09, h: 0.05, fill: { color: DECK.red }, line: { type: 'none' } });
        deckText(slide, `SAP Note ${note.note}`, {
            x: x + 0.057, y: 1.511, w: 0.981, h: 0.145,
            fontFace: FONT_LIGHT, fontSize: 8, bold: true, color: DECK.accent, valign: 'middle', fit: 'shrink',
            ...(note.noteUrl ? { hyperlink: { url: note.noteUrl } } : {}),
        });
        deckText(slide, note.product, {
            x: x + 0.057, y: 1.837, w: 0.981, h: 0.121,
            fontFace: FONT_LIGHT, fontSize: 8, bold: true, color: DECK.white, valign: 'middle', fit: 'shrink',
        });
        deckText(slide, `${priorityLabel(note.priority)} · CVSS ${cvssLabel(note.cvss)}`, {
            x: x + 0.057, y: 1.94, w: 0.981, h: 0.106,
            fontFace: FONT_LIGHT, fontSize: 5, bold: true, italic: true, color: DECK.muted, valign: 'middle',
        });
        deckText(slide, condenseTitle(note.title, 120), {
            x: x + 0.057, y: 2.109, w: 0.981, h: 0.347,
            fontFace: FONT_LIGHT, fontSize: 5, color: DECK.white, valign: 'middle', fit: 'shrink',
        });
    });

    deckText(slide, 
        [
            ...analysis.categoryCounts.slice(0, 4).map(({ category, count }) => ({
                text: `${count} ${category}`,
                options: { fontFace: FONT, fontSize: 9, color: DECK.white, breakLine: true },
            })),
            { text: '', options: { fontFace: FONT, fontSize: 9, breakLine: true } },
            {
                text: 'A Listagem de Vulnerabilidades encontra-se no arquivo anexado ao e-mail.',
                options: { fontFace: FONT, fontSize: 8, bold: true, italic: true, color: DECK.white },
            },
        ],
        { x: 5.234, y: 3.165, w: 4.135, h: 0.968 }
    );
};

const addHighlightsSlide = (pptx: PptxGenJS, summary: SapPatchSummary, analysis: SapReportAnalysis): void => {
    const slide = contentSlide(pptx, 'Highlights de vulnerabilidades', 4, summary.releaseDate);
    deckText(slide, 'Seleção orientada ao risco corporativo e à severidade publicada pela SAP:', {
        x: 0.413, y: 0.715, w: 8.807, h: 0.379,
        fontFace: FONT_LIGHT, fontSize: 9, bold: true, color: DECK.white,
    });

    // The notes come pre-sorted by severity, so the grid's six cards are the six
    // that matter; the rest ships in the attached workbook.
    const highlights = analysis.notes.slice(0, 6);
    const cols = [0.469, 3.476, 6.566];
    const cardW = 2.85;

    highlights.forEach((note, index) => {
        const x = cols[index % 3];
        const y = index < 3 ? 1.065 : 3.09;
        highlightCard(pptx, slide, { x, y, w: cardW, h: 1.815 });
        deckText(slide, `SAP Note ${note.note}${note.isUpdate ? ' · atualizada' : ''}`, {
            x: x + 0.109, y: y + 0.21, w: cardW - 0.22, h: 0.225,
            fontFace: FONT_LIGHT, fontSize: 11, bold: true, color: DECK.red, fit: 'shrink',
            ...(note.noteUrl ? { hyperlink: { url: note.noteUrl } } : {}),
        });
        deckText(slide, note.product, {
            x: x + 0.109, y: y + 0.51, w: cardW - 0.22, h: 0.187,
            fontFace: FONT_LIGHT, fontSize: 9, bold: true, color: DECK.white, fit: 'shrink',
        });
        deckText(slide, `${allCves(note)} | ${priorityLabel(note.priority)} | CVSS ${cvssLabel(note.cvss)}`, {
            x: x + 0.137, y: y + 0.741, w: cardW - 0.27, h: 0.165,
            fontFace: FONT_LIGHT, fontSize: 7, bold: true, color: DECK.muted, fit: 'shrink',
        });
        deckText(slide, condenseTitle(note.title, 130), {
            x: x + 0.137, y: y + 1.012, w: cardW - 0.27, h: 0.54,
            fontFace: FONT_LIGHT, fontSize: 8, color: DECK.white, fit: 'shrink',
        });
    });

    // Every note reaches the presenter, including the ones the grid could not hold.
    slide.addNotes(
        analysis.notes
            .map((note) =>
                [
                    `SAP Note ${note.note}`,
                    `Título completo: ${note.title}`,
                    `CVE: ${allCves(note)}`,
                    `Severidade: ${priorityLabel(note.priority)} · CVSS ${cvssLabel(note.cvss)}`,
                    `Categoria: ${note.category} · Produto: ${note.product}`,
                    note.isUpdate ? 'Nota atualizada' : 'Nota nova neste ciclo',
                ].join('\n')
            )
            .join('\n\n')
    );

    attachmentNote(slide);
};

const addRecommendationsSlide = (pptx: PptxGenJS, summary: SapPatchSummary, analysis: SapReportAnalysis): void => {
    const slide = contentSlide(pptx, 'Conclusão e recomendações', 5, summary.releaseDate);
    analysis.recommendations.slice(0, 6).forEach((item, index) => {
        const column = index % 2;
        const row = Math.floor(index / 2);
        const x = 0.469 + column * 4.531;
        const y = 1.12 + row * 1.32;
        slide.addShape(pptx.ShapeType.roundRect, {
            x, y, w: 4.3, h: 1.2,
            rectRadius: 0.048, fill: { color: DECK.cardAlt }, line: { color: DECK.cardLine, width: 0.8 },
        });
        deckText(slide, item.title, {
            x: x + 0.13, y: y + 0.11, w: 4.04, h: 0.24,
            fontFace: FONT, fontSize: 10, bold: true, color: DECK.accent, fit: 'shrink',
        });
        deckText(slide, item.body, {
            x: x + 0.13, y: y + 0.4, w: 4.04, h: 0.7,
            fontFace: FONT_LIGHT, fontSize: 8, color: DECK.white, fit: 'shrink',
        });
    });
};

const addReferencesSlide = (pptx: PptxGenJS, summary: SapPatchSummary, analysis: SapReportAnalysis): void => {
    const slide = contentSlide(pptx, 'Referências', 6, summary.releaseDate);
    deckText(slide, 'Fonte oficial SAP', {
        x: 0.469, y: 0.715, w: 8.807, h: 0.3,
        fontFace: FONT, fontSize: 11, bold: true, color: DECK.accent,
    });

    const links = [...new Set([summary.url, ...analysis.notes.map((note) => note.noteUrl)].filter(Boolean))];
    const maxRows = 12;
    const columns = Math.max(1, Math.ceil(links.length / maxRows));
    const rows = Math.ceil(links.length / columns);
    const gap = 0.16;
    const columnW = (8.807 - gap * (columns - 1)) / columns;
    const fontSize = Math.max(5, 8 - (columns - 1));
    const step = rows <= 1 ? 0 : Math.min(0.28, 3.3 / (rows - 1));
    const textH = Math.min(0.2, step || 0.2);

    links.forEach((link, index) => {
        const column = Math.floor(index / rows);
        const row = index % rows;
        deckText(slide, link, {
            x: 0.469 + column * (columnW + gap), y: 1.1 + row * step, w: columnW, h: textH,
            fontFace: FONT_LIGHT, fontSize, color: DECK.white, fit: 'shrink', breakLine: false,
            hyperlink: { url: link },
        });
    });

    deckText(slide, `Gerado em ${new Date().toLocaleString('pt-BR')}`, {
        x: 0.469, y: 4.7, w: 8.807, h: 0.2,
        fontFace: FONT_LIGHT, fontSize: 8, color: DECK.muted,
    });
};

export function buildSapPatchPresentation(rawSummary: SapPatchSummary, PptxLib: PptxFactory): PptxGenJS {
    const summary = scrubXml(rawSummary);
    const pptx = new PptxLib();
    deckMetadata(pptx, REPORT, summary.releaseDate);

    const analysis = buildSapReportAnalysis(summary);
    addCoverSlide(pptx, summary);
    addExecutiveSummarySlide(pptx, summary, analysis);
    addConsolidatedSlide(pptx, summary, analysis);
    addHighlightsSlide(pptx, summary, analysis);
    addRecommendationsSlide(pptx, summary, analysis);
    addReferencesSlide(pptx, summary, analysis);
    return pptx;
}

export async function exportSapPatchPPTX(summary: SapPatchSummary): Promise<void> {
    const { default: PptxGenLib } = await import('pptxgenjs');
    const pptx = buildSapPatchPresentation(summary, PptxGenLib);
    await pptx.writeFile({ fileName: `${sapPatchBaseFilename(summary)}.pptx` });
}

// ---- Excel ---------------------------------------------------------------------
export interface ExcelWorkbookFactory {
    Workbook: new () => ExcelJS.Workbook;
}

export const sapPatchExcelFilename = (s: SapPatchSummary) => `${sapPatchBaseFilename(s)}.xlsx`;

// A note can reference several CVEs; the sheet links the first one, which is the
// one the analysis already treats as primary.
const nvdCell = (note: AnalyzedSapNote) =>
    note.cves.length > 0 ? { text: 'NVD', hyperlink: nvdCveUrl(note.cves[0]) } : 'Não informada';

export function buildSapPatchWorkbook(rawSummary: SapPatchSummary, ExcelLib: ExcelWorkbookFactory): ExcelJS.Workbook {
    const summary = scrubXml(rawSummary);
    const workbook = new ExcelLib.Workbook();
    workbookMetadata(workbook, REPORT, summary.releaseDate, 'SAP Security Patch Day, vulnerabilidades, CVSS, CVE');
    workbook.description = 'Avaliação automática de riscos de vulnerabilidades SAP.';
    const analysis = buildSapReportAnalysis(summary);

    // ---- Visão executiva ----
    const executive = workbook.addWorksheet('Visão executiva', { views: [{ state: 'frozen', ySplit: 5 }], properties: SHEET_TAB });
    executive.mergeCells('A1:D1');
    executive.getCell('A1').value = `${REPORT} — ${fmtMonthPt(summary.releaseDate)}`;
    executive.getCell('A1').font = { name: 'Calibri', bold: true, size: 12, color: { argb: `FF${SHEET_HEADER}` } };
    executive.getCell('A2').value = 'Data do ciclo';
    executive.getCell('B2').value = summary.releaseDate || 'Ciclo mais recente';
    executive.getCell('A3').value = 'Fonte';
    executive.getCell('B3').value = summary.url ? { text: 'Fonte oficial SAP', hyperlink: summary.url } : 'Fonte oficial SAP';
    if (summary.url) executive.getCell('B3').font = { ...LINK_FONT };

    executive.getRow(5).values = ['Indicador', 'Valor'];
    styleHeaderRow(executive, 5, 2);
    ([
        ['Total de notas', summary.summary.total],
        ['Críticas (Hot News/Critical)', summary.summary.hotNews],
        ['Altas (High)', summary.summary.high],
        ['CVSS máximo', summary.summary.maxCvss.toFixed(1)],
        ['CVEs', summary.summary.cveCount],
    ] as [string, string | number][]).forEach((row) => executive.addRow(row));

    let cursor = 10; // last row of the indicator block above
    const block = (header: (string | number)[], body: (string | number)[][]) => {
        executive.addRow([]);
        executive.addRow(header);
        cursor += 2;
        styleHeaderRow(executive, cursor, header.length);
        body.forEach((row) => executive.addRow(row));
        cursor += body.length;
    };
    block(['Distribuição por prioridade', 'Quantidade'], Object.entries(summary.summary.byPriority).map(([priority, count]) => [priorityLabel(priority), count]));
    block(['Distribuição por categoria', 'Quantidade'], analysis.categoryCounts.map(({ category, count }) => [category, count]));
    block(['Top 3', 'CVSS', 'Prioridade', 'Produto/Componente'], analysis.topThree.map((note) => [note.note, cvssLabel(note.cvss), priorityLabel(note.priority), note.product]));

    executive.autoFilter = { from: { row: 5, column: 1 }, to: { row: 10, column: 2 } };
    executive.getColumn(1).width = 40;
    executive.getColumn(2).width = 22;
    executive.getColumn(3).width = 22;
    executive.getColumn(4).width = 38;

    // ---- Notas de segurança ----
    const notes = workbook.addWorksheet('Notas de segurança', { views: [{ state: 'frozen', ySplit: 1 }], properties: SHEET_TAB });
    notes.columns = [
        { header: 'Nota', key: 'note', width: 14 },
        { header: 'CVE', key: 'cve', width: 22 },
        { header: 'NVD', key: 'nvd', width: 10 },
        { header: 'Título', key: 'title', width: 65 },
        { header: 'CVSS', key: 'cvss', width: 12 },
        { header: 'Prioridade', key: 'priority', width: 22 },
        { header: 'Categoria', key: 'category', width: 30 },
        { header: 'Produto/Componente', key: 'product', width: 32 },
        { header: 'Atualização', key: 'update', width: 13 },
        { header: 'Vetor CVSS', key: 'vector', width: 42 },
        { header: 'URL da SAP Note', key: 'url', width: 45 },
    ];
    styleHeaderRow(notes, 1, notes.columns.length);

    analysis.notes.forEach((note) => {
        const row = notes.addRow({
            note: note.noteUrl ? { text: note.note, hyperlink: note.noteUrl } : note.note,
            cve: allCves(note),
            nvd: nvdCell(note),
            title: note.title,
            cvss: note.cvss == null ? 'Não informado' : note.cvss,
            priority: priorityLabel(note.priority),
            category: note.category,
            product: note.product,
            update: note.isUpdate ? 'Sim' : 'Não',
            vector: note.cvssVector || 'Não informado',
            url: note.noteUrl ? { text: note.noteUrl, hyperlink: note.noteUrl } : 'Não informada',
        });
        // Only the links get colour; the reader filters by column instead.
        if (note.noteUrl) {
            row.getCell(1).font = { ...LINK_FONT };
            row.getCell(11).font = { ...LINK_FONT };
        }
        if (note.cves.length > 0) row.getCell(3).font = { ...LINK_FONT };
    });

    notes.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: notes.columns.length } };
    return workbook;
}

export async function exportSapPatchExcel(summary: SapPatchSummary): Promise<void> {
    const { default: ExcelLib } = await import('exceljs');
    const workbook = buildSapPatchWorkbook(summary, ExcelLib);
    const buffer = await workbook.xlsx.writeBuffer();
    triggerDownload(new Blob([buffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }), sapPatchExcelFilename(summary));
}
