// Professional document generators for the Microsoft Patch Tuesday summary.
// Produces consolidated PDF, PPTX and Excel artifacts from a normalized summary.
// Heavy document libs (jspdf, jspdf-autotable, pptxgenjs, exceljs) are imported as
// TYPES only and loaded lazily inside each exporter, so visiting the Patch Tuesday
// page no longer pulls ~1.3MB of export toolchain into the route chunk — it is
// fetched on demand when the user actually exports.
import type { jsPDF } from 'jspdf';
import type { CellHookData } from 'jspdf-autotable';
import type PptxGenJS from 'pptxgenjs';
import type ExcelJS from 'exceljs';
import type { PatchTuesdaySummary, PatchVulnerability, PatchTuesdayTotals, NamedCount } from '@/services/msrcApi';

// ---- Shared palette / helpers -------------------------------------------------

const BRAND = '2563EB'; // app primary blue
const INK = '0F172A'; // slate-900
const MUTED = '64748B'; // slate-500

const SEVERITY_HEX: Record<string, string> = {
    Critical: 'DC2626',
    Important: 'EA580C',
    Moderate: 'CA8A04',
    Low: '16A34A',
    Unknown: '64748B',
};

const hex = (h: string) => `#${h}`;

// jspdf-autotable augments the jsPDF instance with this at runtime
type AutoTableDoc = jsPDF & { lastAutoTable: { finalY: number } };
const finalY = (doc: jsPDF) => (doc as AutoTableDoc).lastAutoTable.finalY;

const rgb = (h: string): [number, number, number] => [
    parseInt(h.substr(0, 2), 16),
    parseInt(h.substr(2, 2), 16),
    parseInt(h.substr(4, 2), 16),
];

// 100% stacked horizontal severity bar with legend underneath; returns next y
function drawSeverityBar(doc: jsPDF, x: number, y: number, w: number, totals: PatchTuesdayTotals): number {
    const segs = [
        { label: 'Critical', value: totals.critical, hex: SEVERITY_HEX.Critical },
        { label: 'Important', value: totals.important, hex: SEVERITY_HEX.Important },
        { label: 'Moderate', value: totals.moderate, hex: SEVERITY_HEX.Moderate },
        { label: 'Low', value: totals.low, hex: SEVERITY_HEX.Low },
        // Genuinely just Microsoft CVEs that MSRC left unrated — upstream
        // republications are excluded from totals before they get here.
        { label: 'Unrated', value: totals.unknown, hex: SEVERITY_HEX.Unknown },
    ];
    const total = totals.total || 1;
    const h = 8;
    let cx = x;
    segs.forEach((s) => {
        const segW = (s.value / total) * w;
        if (segW <= 0) return;
        const [r, g, b] = rgb(s.hex);
        doc.setFillColor(r, g, b);
        doc.rect(cx, y, segW, h, 'F');
        cx += segW;
    });
    // Legend chips
    const ly = y + h + 5;
    let lx = x;
    doc.setFontSize(7.5);
    segs.forEach((s) => {
        const [r, g, b] = rgb(s.hex);
        doc.setFillColor(r, g, b);
        doc.roundedRect(lx, ly - 2.6, 3, 3, 0.5, 0.5, 'F');
        doc.setTextColor(71, 85, 105);
        doc.setFont('helvetica', 'normal');
        const text = `${s.label} (${s.value})`;
        doc.text(text, lx + 4.2, ly);
        lx += 4.2 + doc.getTextWidth(text) + 6;
    });
    return ly + 4;
}

// Horizontal bar chart with labels + values; returns next y
function drawHBars(doc: jsPDF, x: number, y: number, w: number, rows: NamedCount[], colorHex: string): number {
    const max = Math.max(1, ...rows.map((r) => r.count));
    const labelW = 46;
    const valW = 12;
    const trackX = x + labelW;
    const trackW = w - labelW - valW;
    const rowH = 6;
    const [cr, cg, cb] = rgb(colorHex);
    doc.setFontSize(7.5);
    rows.forEach((r) => {
        doc.setTextColor(51, 65, 85);
        doc.setFont('helvetica', 'normal');
        const label = r.name.length > 28 ? `${r.name.slice(0, 27)}…` : r.name;
        doc.text(label, x, y + 3.3);
        doc.setFillColor(241, 245, 249);
        doc.roundedRect(trackX, y, trackW, 4, 1, 1, 'F');
        const bw = Math.max(0.8, (r.count / max) * trackW);
        doc.setFillColor(cr, cg, cb);
        doc.roundedRect(trackX, y, bw, 4, 1, 1, 'F');
        doc.setTextColor(15, 23, 42);
        doc.setFont('helvetica', 'bold');
        doc.text(String(r.count), trackX + trackW + 2, y + 3.3);
        y += rowH;
    });
    return y;
}

const fmtDate = (iso: string | null): string => {
    if (!iso) return 'N/A';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return 'N/A';
    return d.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
};

const baseFilename = (s: PatchTuesdaySummary) => `Patch-Tuesday-${s.id || 'report'}`;

const exploitTag = (v: PatchVulnerability): string => {
    const tags: string[] = [];
    if (v.exploited) tags.push('Exploited');
    if (v.publiclyDisclosed) tags.push('Disclosed');
    return tags.length ? tags.join(' / ') : '-';
};

// =============================================================================
//  PDF  (jsPDF + autotable)
// =============================================================================

export async function exportPatchTuesdayPDF(summary: PatchTuesdaySummary): Promise<void> {
    const [{ jsPDF }, { default: autoTable }] = await Promise.all([
        import('jspdf'),
        import('jspdf-autotable'),
    ]);
    const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
    const pageW = doc.internal.pageSize.getWidth();
    const pageH = doc.internal.pageSize.getHeight();
    const margin = 14;
    const generated = new Date().toLocaleString('en-US');

    // ---- Cover banner ----
    doc.setFillColor(15, 23, 42); // INK
    doc.rect(0, 0, pageW, 52, 'F');
    doc.setFillColor(37, 99, 235); // BRAND
    doc.rect(0, 52, pageW, 2, 'F');

    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.text('MICROSOFT PATCH TUESDAY', margin, 18);
    doc.setFontSize(22);
    doc.text(summary.title || 'Security Updates', margin, 30);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    doc.setTextColor(203, 213, 225);
    doc.text(`Release date: ${fmtDate(summary.initialReleaseDate)}`, margin, 40);
    doc.text(`Last revised: ${fmtDate(summary.currentReleaseDate)}`, margin, 46);
    doc.text(`${summary.totals.total} CVEs`, pageW - margin, 40, { align: 'right' });
    doc.text('Source: MSRC CVRF v3.0', pageW - margin, 46, { align: 'right' });

    let y = 64;

    // ---- KPI cards ----
    const kpis = [
        { label: 'Total CVEs', value: summary.totals.total, color: BRAND },
        { label: 'Critical', value: summary.totals.critical, color: SEVERITY_HEX.Critical },
        { label: 'Important', value: summary.totals.important, color: SEVERITY_HEX.Important },
        { label: 'Exploited', value: summary.totals.exploited, color: 'B91C1C' },
        { label: 'Disclosed', value: summary.totals.disclosed, color: '7C3AED' },
    ];
    const gap = 4;
    const cardW = (pageW - margin * 2 - gap * (kpis.length - 1)) / kpis.length;
    kpis.forEach((k, i) => {
        const x = margin + i * (cardW + gap);
        doc.setDrawColor(226, 232, 240);
        doc.setFillColor(248, 250, 252);
        doc.roundedRect(x, y, cardW, 22, 2, 2, 'FD');
        const [r, g, b] = [0, 2, 4].map((o) => parseInt(k.color.substr(o, 2), 16));
        doc.setTextColor(r, g, b);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(17);
        doc.text(String(k.value), x + cardW / 2, y + 11, { align: 'center' });
        doc.setTextColor(100, 116, 139);
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7.5);
        doc.text(k.label.toUpperCase(), x + cardW / 2, y + 17, { align: 'center' });
    });
    y += 30;

    const sectionTitle = (text: string) => {
        doc.setTextColor(15, 23, 42);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(12);
        doc.text(text, margin, y);
        doc.setDrawColor(37, 99, 235);
        doc.setLineWidth(0.5);
        doc.line(margin, y + 1.5, margin + 28, y + 1.5);
        y += 5;
    };

    // ---- Severity distribution (stacked bar chart) ----
    sectionTitle('Severity Distribution');
    y = drawSeverityBar(doc, margin, y + 2, pageW - margin * 2, summary.totals) + 5;

    // ---- By Impact (horizontal bar chart) ----
    sectionTitle('Vulnerabilities by Impact');
    y = drawHBars(doc, margin, y + 2, pageW - margin * 2, summary.byImpact, BRAND) + 6;

    if (y > pageH - 70) {
        doc.addPage();
        y = 20;
    }
    // ---- Affected product families (horizontal bar chart) ----
    sectionTitle('Affected Product Families');
    y = drawHBars(doc, margin, y + 2, pageW - margin * 2, summary.byFamily, '1E3A8A') + 6;

    // ---- References ----
    if (y > pageH - 50) {
        doc.addPage();
        y = 20;
    }
    sectionTitle('References & Sources');
    const refs = [
        { label: 'Microsoft Security Update Guide', url: `https://msrc.microsoft.com/update-guide/releaseNote/${summary.id}` },
        { label: 'MSRC CVRF v3.0 API (source document)', url: `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/${summary.id}` },
        { label: 'Microsoft Update Catalog', url: 'https://catalog.update.microsoft.com/' },
    ];
    refs.forEach((r) => {
        doc.setFontSize(8.5);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(15, 23, 42);
        doc.text(`• ${r.label}:`, margin, y);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(37, 99, 235);
        doc.textWithLink(r.url, margin + 4, y + 4.5, { url: r.url });
        y += 11;
    });
    doc.setFontSize(7.5);
    doc.setFont('helvetica', 'italic');
    doc.setTextColor(100, 116, 139);
    doc.text(
        `Data retrieved from the official Microsoft Security Response Center (MSRC) on ${generated}. Each CVE can be reviewed at https://msrc.microsoft.com/update-guide/vulnerability/<CVE-ID>.`,
        margin,
        y + 1,
        { maxWidth: pageW - margin * 2 }
    );

    // ---- Priority CVEs ----
    doc.addPage();
    y = 20;
    sectionTitle('Priority CVEs (exploited, disclosed & highest CVSS)');
    autoTable(doc, {
        startY: y,
        head: [['CVE', 'Severity', 'CVSS', 'Impact', 'Status', 'Title']],
        body: summary.topCves.map((v) => [
            v.cve,
            v.severity,
            v.cvss ?? '-',
            v.impact,
            exploitTag(v),
            v.title,
        ]),
        theme: 'grid',
        headStyles: { fillColor: [15, 23, 42], fontSize: 8 },
        bodyStyles: { fontSize: 7.5 },
        columnStyles: { 0: { fontStyle: 'bold' }, 5: { cellWidth: 60 } },
        margin: { left: margin, right: margin },
        didParseCell: (data) => severityCellColor(data, 1),
    });

    // ---- Full CVE catalog ----
    doc.addPage();
    y = 20;
    sectionTitle(`Complete CVE Catalog (${summary.vulnerabilities.length})`);
    autoTable(doc, {
        startY: y,
        head: [['CVE', 'Severity', 'CVSS', 'Impact', 'Family', 'Exploitability', 'Status']],
        body: summary.vulnerabilities.map((v) => [
            v.cve,
            v.severity,
            v.cvss ?? '-',
            v.impact,
            v.family,
            v.exploitability,
            exploitTag(v),
        ]),
        theme: 'striped',
        headStyles: { fillColor: [15, 23, 42], fontSize: 7.5 },
        bodyStyles: { fontSize: 6.8 },
        columnStyles: { 0: { fontStyle: 'bold' } },
        margin: { left: margin, right: margin },
        didParseCell: (data) => severityCellColor(data, 1),
    });

    // ---- Footer on every page ----
    const pages = doc.getNumberOfPages();
    for (let p = 1; p <= pages; p++) {
        doc.setPage(p);
        doc.setDrawColor(226, 232, 240);
        doc.line(margin, pageH - 12, pageW - margin, pageH - 12);
        doc.setFontSize(7);
        doc.setTextColor(148, 163, 184);
        doc.setFont('helvetica', 'normal');
        doc.text(`ThreatSumm4ry · Patch Tuesday Report · Generated ${generated}`, margin, pageH - 7);
        doc.text(`Page ${p} of ${pages}`, pageW - margin, pageH - 7, { align: 'right' });
    }

    doc.save(`${baseFilename(summary)}.pdf`);
}

const severityCellColor = (data: CellHookData, col: number) => {
    if (data.section !== 'body' || data.column.index !== col) return;
    const sev = String(data.cell.raw);
    const h = SEVERITY_HEX[sev];
    if (!h) return;
    data.cell.styles.textColor = [parseInt(h.substr(0, 2), 16), parseInt(h.substr(2, 2), 16), parseInt(h.substr(4, 2), 16)];
    data.cell.styles.fontStyle = 'bold';
};

// =============================================================================
//  PPTX  (pptxgenjs)
// =============================================================================
// Executive deck standard, the same one the SAP Security Patch Day deck follows:
// PT-BR, navy cover, thin blue rule, numbered slides, capa → sumário executivo →
// consolidado → famílias → highlights → recomendações → referências. Metadata
// carries no company name (pptx.company stays blank) — the deck is handed over
// and presented under the reader's own name.
// The palette is duplicated rather than imported from sapPatchExport: that module
// pulls its analysis dependency along, and this file exists to keep the export
// toolchain out of the Patch Tuesday route chunk.

const DECK = { blue: '1565C0', navy: '172033', slate: '526274', pale: 'F3F6FA', border: 'DCE3EE', white: 'FFFFFF' } as const;

export type PptxFactory = new () => PptxGenJS;

const FAMILY_PT: Record<string, string> = {
    'Azure & Cloud': 'Azure e nuvem',
    'Developer Tools & .NET': 'Ferramentas de desenvolvimento e .NET',
    'Other Microsoft Products': 'Outros produtos Microsoft',
};

const pt = (map: Record<string, string>, value: string) => map[value] || value;

const fmtMonthPt = (iso: string | null): string => {
    if (!iso) return 'Ciclo mais recente';
    const d = new Date(iso);
    return isNaN(d.getTime()) ? 'Ciclo mais recente' : d.toLocaleDateString('pt-BR', { month: 'long', year: 'numeric' });
};

const fmtDatePt = (iso: string | null): string => {
    if (!iso) return 'Ciclo mais recente';
    const d = new Date(iso);
    return isNaN(d.getTime()) ? 'Ciclo mais recente' : d.toLocaleDateString('pt-BR', { day: '2-digit', month: 'long', year: 'numeric' });
};

const statusPt = (v: PatchVulnerability): string => {
    const tags: string[] = [];
    if (v.exploited) tags.push('Explorada');
    if (v.publiclyDisclosed) tags.push('Divulgada');
    return tags.length ? tags.join(' / ') : '—';
};

const deckTitle = (slide: PptxGenJS.Slide, text: string) =>
    slide.addText(text, { x: 0.55, y: 0.35, w: 12.2, h: 0.45, fontSize: 23, bold: true, color: DECK.navy });

const addCoverSlide = (pptx: PptxGenJS, s: PatchTuesdaySummary): void => {
    const t = s.totals;
    const slide = pptx.addSlide();
    slide.background = { color: DECK.navy };
    slide.addText('Microsoft Patch Tuesday', { x: 0.7, y: 2.15, w: 12, h: 0.65, fontSize: 32, bold: true, color: DECK.white });
    slide.addText('Avaliação de riscos de vulnerabilidades', { x: 0.7, y: 2.9, w: 12, h: 0.45, fontSize: 20, color: DECK.white });
    slide.addText(`${fmtMonthPt(s.initialReleaseDate)} · ${fmtDatePt(s.initialReleaseDate)}`, { x: 0.7, y: 3.42, w: 12, h: 0.4, fontSize: 16, color: DECK.blue });
    slide.addText(`${t.total} CVEs · ${t.critical} críticas · ${t.exploited} sob exploração ativa`, { x: 0.7, y: 3.95, w: 12, h: 0.45, fontSize: 15, color: DECK.border });
    slide.addText('Fonte oficial Microsoft (MSRC)', { x: 0.7, y: 6.45, w: 12, h: 0.3, fontSize: 10, color: DECK.slate });
};

const addExecutiveSummarySlide = (pptx: PptxGenJS, s: PatchTuesdaySummary): void => {
    const t = s.totals;
    const slide = pptx.addSlide({ masterName: 'EXECUTIVO' });
    deckTitle(slide, 'Sumário executivo');
    slide.addText(
        `A Microsoft corrigiu ${t.total} vulnerabilidades em ${fmtMonthPt(s.initialReleaseDate)}, sendo ${t.critical} críticas e ${t.important} importantes.`,
        { x: 0.7, y: 1.15, w: 11.9, h: 0.8, fontSize: 18, color: DECK.navy }
    );

    const priorities: string[] = [];
    if (t.exploited > 0) priorities.push(`${t.exploited} CVE(s) já sob exploração ativa — correção emergencial em 24 a 48 horas.`);
    if (t.disclosed > 0) priorities.push(`${t.disclosed} CVE(s) divulgadas publicamente — detalhes de exploração podem já estar circulando.`);
    if (t.exploitMoreLikely > 0) priorities.push(`${t.exploitMoreLikely} CVE(s) classificadas pela Microsoft como de exploração mais provável.`);
    const topFamily = s.byFamily[0];
    if (topFamily) priorities.push(`${pt(FAMILY_PT, topFamily.name)} concentra o maior volume do ciclo, com ${topFamily.count} CVE(s).`);
    // The number the audience will compare against the press coverage. Saying why
    // it differs on the slide is cheaper than answering it live.
    if (t.upstream > 0) {
        priorities.push(
            `${t.upstream} CVEs de código upstream (Chromium/Edge e pacotes do Azure Linux) ficaram fora da contagem: são republicações da Microsoft, não correções em produtos próprios.`
        );
    }
    priorities.forEach((item, index) =>
        slide.addText(`• ${item}`, { x: 0.9, y: 2.25 + index * 0.55, w: 11.4, h: 0.45, fontSize: 14, color: DECK.slate })
    );
    slide.addText(
        `Critical: ${t.critical} · Important: ${t.important} · Sob exploração ativa: ${t.exploited}`,
        { x: 0.9, y: 2.5 + priorities.length * 0.55, w: 11.4, h: 0.4, fontSize: 16, bold: true, color: SEVERITY_HEX.Critical }
    );
};

const addConsolidatedSlide = (pptx: PptxGenJS, s: PatchTuesdaySummary): void => {
    const t = s.totals;
    const slide = pptx.addSlide({ masterName: 'EXECUTIVO' });
    deckTitle(slide, 'Consolidado de vulnerabilidades');
    slide.addText(`Total de CVEs: ${t.total}`, { x: 0.6, y: 0.88, w: 3, h: 0.3, fontSize: 12, bold: true, color: DECK.blue });

    // Empty severities are dropped: an unused legend entry reads as a data gap.
    // MSRC's own rating names, kept in English like everywhere else in the deck.
    const severities = ([
        ['Critical', t.critical, SEVERITY_HEX.Critical],
        ['Important', t.important, SEVERITY_HEX.Important],
        ['Moderate', t.moderate, SEVERITY_HEX.Moderate],
        ['Low', t.low, SEVERITY_HEX.Low],
        ['Sem classificação', t.unknown, SEVERITY_HEX.Unknown],
    ] as [string, number, string][]).filter(([, value]) => value > 0);
    slide.addChart(
        pptx.ChartType.doughnut,
        [{ name: 'Severidade', labels: severities.map((x) => x[0]), values: severities.map((x) => x[1]) }],
        {
            x: 0.6, y: 1.25, w: 5.7, h: 4.9,
            chartColors: severities.map((x) => x[2]),
            showLegend: true, legendPos: 'b', showTitle: true, title: 'Por severidade', titleFontSize: 13,
            showValue: true, dataLabelFontSize: 9, holeSize: 55,
        }
    );

    const impacts = s.byImpact.slice(0, 7);
    slide.addChart(
        pptx.ChartType.bar,
        [{ name: 'CVEs', labels: impacts.map((i) => i.name), values: impacts.map((i) => i.count) }],
        {
            x: 6.7, y: 1.25, w: 6, h: 4.9,
            barDir: 'bar', chartColors: [DECK.blue],
            showTitle: true, title: 'Por tipo de impacto', titleFontSize: 13,
            showValue: true, dataLabelFontSize: 9, catAxisLabelFontSize: 9, valAxisHidden: true,
        }
    );
};

const addFamiliesSlide = (pptx: PptxGenJS, s: PatchTuesdaySummary): void => {
    const slide = pptx.addSlide({ masterName: 'EXECUTIVO' });
    deckTitle(slide, 'Famílias de produtos afetadas');
    const fams = s.byFamily.slice(0, 10);
    slide.addChart(
        pptx.ChartType.bar,
        [{ name: 'CVEs', labels: fams.map((f) => pt(FAMILY_PT, f.name)), values: fams.map((f) => f.count) }],
        {
            x: 0.6, y: 1.1, w: 12.2, h: 5.3,
            barDir: 'bar', chartColors: [DECK.navy],
            showValue: true, dataLabelFontSize: 10, catAxisLabelFontSize: 11, valAxisHidden: true,
        }
    );
};

// A title long enough to wrap breaks the fixed row height, so it is condensed and
// the untruncated text goes to the speaker notes.
const condenseTitle = (title: string, max = 78) => (title.length > max ? `${title.slice(0, max - 1)}…` : title);

const addHighlightsSlide = (pptx: PptxGenJS, s: PatchTuesdaySummary): void => {
    const slide = pptx.addSlide({ masterName: 'EXECUTIVO' });
    deckTitle(slide, 'Highlights de vulnerabilidades');
    const highlights = s.topCves.slice(0, 12);
    const cell = (text: string, options: PptxGenJS.TableCell['options'] = {}): PptxGenJS.TableCell => ({ text, options });
    const rows: PptxGenJS.TableRow[] = [
        ['CVE', 'Severidade', 'CVSS', 'Impacto', 'Situação', 'Título'].map((text) =>
            cell(text, { bold: true, color: DECK.white, fill: { color: DECK.blue } })
        ),
        ...highlights.map((v) => [
            cell(v.cve, { bold: true }),
            cell(v.severity, { bold: true, color: SEVERITY_HEX[v.severity] || DECK.slate }),
            cell(v.cvss == null ? '—' : v.cvss.toFixed(1), { bold: true }),
            cell(v.impact),
            cell(statusPt(v), { color: v.exploited ? SEVERITY_HEX.Critical : DECK.slate }),
            cell(condenseTitle(v.title)),
        ]),
    ];
    slide.addTable(rows, {
        x: 0.45, y: 1.05, w: 12.45, colW: [1.65, 1.35, 0.7, 2.4, 1.5, 4.85],
        fontSize: highlights.length <= 10 ? 8.5 : 7.5, margin: 0.02,
        autoPage: false, breakLine: false, valign: 'middle',
        border: { type: 'solid', color: DECK.border, pt: 0.5 },
        fill: { color: DECK.white }, color: DECK.navy, bold: false,
    });
    slide.addNotes(
        highlights
            .map((v) =>
                [
                    v.cve,
                    `Título completo: ${v.title}`,
                    `Severidade: ${v.severity}${v.cvss == null ? '' : ` · CVSS ${v.cvss.toFixed(1)}`}`,
                    `Impacto: ${v.impact} · Família: ${pt(FAMILY_PT, v.family)}`,
                    `Avaliação de exploração: ${v.exploitability}`,
                    v.kbs.length ? `KBs: ${v.kbs.map((k) => `KB${k.kb}`).join(', ')}` : 'Sem KB associada',
                ].join('\n')
            )
            .join('\n\n')
    );
};

const addRecommendationsSlide = (pptx: PptxGenJS, s: PatchTuesdaySummary): void => {
    const t = s.totals;
    const slide = pptx.addSlide({ masterName: 'EXECUTIVO' });
    deckTitle(slide, 'Conclusão e recomendações');
    const recommendations: { title: string; body: string }[] = [];
    if (t.exploited > 0) {
        recommendations.push({
            title: 'Corrigir o que já está sendo explorado',
            body: `${t.exploited} CVE(s) com exploração confirmada pela Microsoft. Tratar como incidente: janela emergencial de 24 a 48 horas, fora do ciclo normal de mudanças.`,
        });
    }
    if (t.disclosed > 0) {
        recommendations.push({
            title: 'Revisar as divulgadas publicamente',
            body: `${t.disclosed} CVE(s) tiveram detalhes publicados antes da correção. Assumir que prova de conceito já circula e antecipar a aplicação.`,
        });
    }
    recommendations.push({
        title: 'Planejar o ciclo regular',
        body: `Distribuir ${t.critical} correções críticas e ${t.important} importantes pelo parque afetado, respeitando as janelas de controle de mudanças.`,
    });
    if (t.exploitMoreLikely > 0) {
        recommendations.push({
            title: 'Acompanhar as de exploração provável',
            body: `${t.exploitMoreLikely} CVE(s) marcadas como de exploração mais provável. Priorizar acima do restante do ciclo, mesmo sem exploração observada.`,
        });
    }
    recommendations.push({
        title: 'Validar cobertura por KB',
        body: 'Conferir a aplicabilidade de cada KB por família de produto usando a planilha anexa, que traz os links do Catálogo de Atualizações da Microsoft.',
    });
    recommendations.push({
        title: 'Comunicar escopo e prazos',
        body: 'Alinhar com as áreas responsáveis o alcance das correções e as datas de aplicação, usando este consolidado como referência única do ciclo.',
    });
    recommendations.forEach((item, index) => {
        const col = index % 2;
        const row = Math.floor(index / 2);
        const x = 0.65 + col * 6.15;
        const y = 1.15 + row * 1.75;
        slide.addText(item.title, { x, y, w: 5.75, h: 0.3, fontSize: 13, bold: true, color: DECK.blue });
        slide.addText(item.body, { x, y: y + 0.38, w: 5.75, h: 0.95, fontSize: 10, color: DECK.slate, breakLine: false });
    });
};

const addReferencesSlide = (pptx: PptxGenJS, s: PatchTuesdaySummary): void => {
    const slide = pptx.addSlide({ masterName: 'EXECUTIVO' });
    deckTitle(slide, 'Referências');
    slide.addText('Fonte oficial Microsoft (MSRC)', { x: 0.7, y: 1.15, w: 11.8, h: 0.35, fontSize: 15, bold: true, color: DECK.blue });
    const links = [
        `https://msrc.microsoft.com/update-guide/releaseNote/${s.id}`,
        `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/${s.id}`,
        'https://catalog.update.microsoft.com/',
        ...s.topCves.slice(0, 12).map((v) => `https://msrc.microsoft.com/update-guide/vulnerability/${v.cve}`),
    ];
    const maxRows = 12;
    const columns = Math.max(1, Math.ceil(links.length / maxRows));
    const rows = Math.ceil(links.length / columns);
    const gap = 0.22;
    const columnW = (11.8 - gap * (columns - 1)) / columns;
    const fontSize = Math.max(5.5, 10 - (columns - 1) * 1.25);
    const step = rows <= 1 ? 0 : Math.min(0.38, 4.35 / (rows - 1));
    const textH = Math.min(0.28, step || 0.28);
    links.forEach((link, index) => {
        const column = Math.floor(index / rows);
        const row = index % rows;
        slide.addText(link, {
            x: 0.7 + column * (columnW + gap), y: 1.7 + row * step, w: columnW, h: textH,
            fontSize, color: DECK.slate, fit: 'shrink', breakLine: false, hyperlink: { url: link },
        });
    });
    slide.addText(`Gerado em ${new Date().toLocaleString('pt-BR')}`, { x: 0.7, y: 6.35, w: 11.8, h: 0.3, fontSize: 9, color: DECK.slate });
};

export function buildPatchTuesdayPresentation(summary: PatchTuesdaySummary, PptxLib: PptxFactory): PptxGenJS {
    const pptx = new PptxLib();
    pptx.defineLayout({ name: 'PT_EXECUTIVO', width: 13.333, height: 7.5 });
    pptx.layout = 'PT_EXECUTIVO';
    pptx.author = 'ThreatSumm4ry';
    pptx.company = '';
    (pptx as PptxGenJS & { lang: string }).lang = 'pt-BR';
    pptx.subject = 'Relatório automático do Microsoft Patch Tuesday';
    pptx.title = `Microsoft Patch Tuesday — ${fmtMonthPt(summary.initialReleaseDate)}`;
    pptx.defineSlideMaster({
        title: 'EXECUTIVO',
        background: { color: DECK.white },
        objects: [
            { rect: { x: 0, y: 0, w: 13.333, h: 0.08, fill: { color: DECK.blue }, line: { color: DECK.blue } } },
            { text: { text: 'Microsoft Patch Tuesday', options: { x: 0.45, y: 7.08, w: 4, h: 0.25, fontSize: 8, color: DECK.slate } } },
            { text: { text: fmtMonthPt(summary.initialReleaseDate), options: { x: 5, y: 7.08, w: 3.3, h: 0.25, fontSize: 8, color: DECK.slate, align: 'center' } } },
        ],
        slideNumber: { x: 12.35, y: 7.08, w: 0.5, h: 0.25, fontSize: 8, color: DECK.slate },
    });

    addCoverSlide(pptx, summary);
    addExecutiveSummarySlide(pptx, summary);
    addConsolidatedSlide(pptx, summary);
    addFamiliesSlide(pptx, summary);
    addHighlightsSlide(pptx, summary);
    addRecommendationsSlide(pptx, summary);
    addReferencesSlide(pptx, summary);
    return pptx;
}

export async function exportPatchTuesdayPPTX(summary: PatchTuesdaySummary): Promise<void> {
    const { default: PptxGenLib } = await import('pptxgenjs');
    const pptx = buildPatchTuesdayPresentation(summary, PptxGenLib);
    await pptx.writeFile({ fileName: `${baseFilename(summary)}.pptx` });
}

// =============================================================================
//  Excel  (exceljs)
// =============================================================================

// Same sheet standard as the attack-surface export: dark red header band, white
// bold Calibri 14, thin border, frozen header row, autofilter, and no colour on
// the data rows — whoever reads it filters by column instead.
// Labels are PT-BR; the values MSRC publishes (severity, impact, exploitability)
// stay in English, since those are the canonical terms people search for.
const SHEET_HEADER = 'C00000';
const SHEET_BORDER = { style: 'thin' as const };

export interface ExcelWorkbookFactory {
    Workbook: new () => ExcelJS.Workbook;
}

const styleHeaderRow = (ws: ExcelJS.Worksheet, row: number, lastCol: number) => {
    const r = ws.getRow(row);
    for (let c = 1; c <= lastCol; c++) {
        const cell = r.getCell(c);
        cell.font = { name: 'Calibri', bold: true, size: 14, color: { argb: 'FFFFFFFF' } };
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: `FF${SHEET_HEADER}` } };
        cell.alignment = { horizontal: 'left', vertical: 'top' };
        cell.border = { top: SHEET_BORDER, left: SHEET_BORDER, bottom: SHEET_BORDER, right: SHEET_BORDER };
    }
    r.height = 18.5;
};

export function buildPatchTuesdayWorkbook(summary: PatchTuesdaySummary, ExcelLib: ExcelWorkbookFactory): ExcelJS.Workbook {
    const wb = new ExcelLib.Workbook();
    wb.creator = 'ThreatSumm4ry';
    wb.company = '';
    wb.created = new Date();
    const t = summary.totals;

    // ---- Resumo ----
    const resumo = wb.addWorksheet('Resumo', { properties: { tabColor: { argb: `FF${SHEET_HEADER}` } } });
    resumo.mergeCells('A1:B1');
    resumo.getCell('A1').value = `Microsoft Patch Tuesday — ${fmtMonthPt(summary.initialReleaseDate)}`;
    resumo.getCell('A1').font = { name: 'Calibri', bold: true, size: 12, color: { argb: `FF${SHEET_HEADER}` } };
    resumo.mergeCells('A2:B2');
    resumo.getCell('A2').value = `Publicado em ${fmtDatePt(summary.initialReleaseDate)} · Fonte oficial Microsoft (MSRC) · Gerado em ${new Date().toLocaleString('pt-BR')}`;
    resumo.getCell('A2').font = { name: 'Calibri', size: 10 };
    resumo.addRow([]);

    resumo.getRow(4).values = ['Indicador', 'Quantidade'];
    styleHeaderRow(resumo, 4, 2);
    ([
        ['Total de CVEs', t.total],
        ['Critical', t.critical],
        ['Important', t.important],
        ['Moderate', t.moderate],
        ['Low', t.low],
        ['Sem classificação', t.unknown],
        ['Sob exploração ativa', t.exploited],
        ['Divulgadas publicamente', t.disclosed],
        ['Exploitation More Likely', t.exploitMoreLikely],
        ['Código upstream (Chromium/Edge e pacotes do Azure Linux, fora da contagem)', t.upstream],
    ] as [string, number][]).forEach((row) => resumo.addRow(row));
    resumo.getColumn(1).width = 62;
    resumo.getColumn(2).width = 14;

    // ---- Abas de distribuição ----
    const distribuicao = (sheetName: string, label: string, rows: NamedCount[]) => {
        const ws = wb.addWorksheet(sheetName, { views: [{ state: 'frozen', ySplit: 1 }] });
        ws.getRow(1).values = [label, 'CVEs', 'Participação'];
        styleHeaderRow(ws, 1, 3);
        rows.forEach((r) => ws.addRow([r.name, r.count, t.total ? r.count / t.total : 0]));
        ws.getColumn(1).width = 38;
        ws.getColumn(2).width = 12;
        ws.getColumn(3).width = 16;
        ws.getColumn(3).numFmt = '0.0%';
        ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: 3 } };
    };
    distribuicao('Por Severidade', 'Severity', [
        { name: 'Critical', count: t.critical },
        { name: 'Important', count: t.important },
        { name: 'Moderate', count: t.moderate },
        { name: 'Low', count: t.low },
        { name: 'Sem classificação', count: t.unknown },
    ]);
    distribuicao('Por Impacto', 'Impact', summary.byImpact);
    distribuicao('Por Família de Produto', 'Família de produto', summary.byFamily);

    // ---- Base de dados ----
    const cols = [
        { header: 'CVE', key: 'cve', width: 20 },
        { header: 'Severity', key: 'severity', width: 14 },
        { header: 'CVSS', key: 'cvss', width: 9 },
        { header: 'Impact', key: 'impact', width: 26 },
        { header: 'Família de Produto', key: 'family', width: 26 },
        { header: 'Origem', key: 'origem', width: 20 },
        { header: 'Sob Exploração Ativa', key: 'exploited', width: 20 },
        { header: 'Divulgada Publicamente', key: 'disclosed', width: 22 },
        { header: 'Exploitability', key: 'exploitability', width: 26 },
        { header: 'CWE', key: 'cwe', width: 36 },
        { header: 'Produtos Afetados', key: 'productCount', width: 18 },
        { header: 'Artigos KB', key: 'kbs', width: 32 },
        { header: 'Título', key: 'title', width: 54 },
        { header: 'Descrição', key: 'description', width: 70 },
        { header: 'Vetor CVSS', key: 'vector', width: 42 },
    ];
    const base = wb.addWorksheet('Base de dados', {
        properties: { tabColor: { argb: `FF${SHEET_HEADER}` } },
        views: [{ state: 'frozen', ySplit: 1 }],
    });
    base.columns = cols;
    styleHeaderRow(base, 1, cols.length);
    summary.vulnerabilities.forEach((v) => {
        base.addRow({
            cve: v.cve,
            severity: v.severity,
            cvss: v.cvss ?? '',
            impact: v.impact,
            family: v.family,
            // The one column that explains why the sheet has more rows than the
            // headline count: upstream entries are shipped, but marked.
            origem: v.upstream ? 'Upstream republicado' : 'Microsoft',
            exploited: v.exploited ? 'Sim' : 'Não',
            disclosed: v.publiclyDisclosed ? 'Sim' : 'Não',
            exploitability: v.exploitability,
            cwe: v.cwe,
            productCount: v.productCount,
            kbs: v.kbs.map((k) => `KB${k.kb}`).join(', '),
            title: v.title,
            description: v.description,
            vector: v.vector,
        });
    });
    base.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: cols.length } };

    return wb;
}

export async function exportPatchTuesdayExcel(summary: PatchTuesdaySummary): Promise<void> {
    const { default: ExcelLib } = await import('exceljs');
    const wb = buildPatchTuesdayWorkbook(summary, ExcelLib);
    const buf = await wb.xlsx.writeBuffer();
    triggerDownload(new Blob([buf], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }), `${baseFilename(summary)}.xlsx`);
}

const triggerDownload = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
};

// Keep hex helper referenced (used by callers that build inline styles)
export const severityColor = (sev: string) => hex(SEVERITY_HEX[sev] || MUTED);
