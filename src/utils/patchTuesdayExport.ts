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
import { DECK_COVER_BG, DECK_PANEL_BG } from './patchTuesdayDeckArt';

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
// Reproduces the four-slide Patch Tuesday deck the team already hands over:
// capa → sumário executivo → consolidado → highlights críticos. Dark panel on a
// blurred colour field, yellow section titles over a yellow→magenta→cyan rule,
// Overpass throughout. Geometry is transcribed from the reference file in EMU
// converted to inches, so the generated deck drops into the same template.
// Metadata carries no company name (pptx.company stays blank) — the deck is
// handed over and presented under the reader's own name.

const DECK = {
    panel: '1A1A24', // dark panel that covers all but a thin frame of the artwork
    card: '242731', // highlight cards
    cardAlt: '222530', // the two wide cards on the executive summary
    cardLine: '454957',
    accent: 'FFE600', // section titles
    amber: 'FFC000', // KPI pills
    red: 'E53935', // card rules and CVE identifiers
    muted: 'B7BAC5',
    white: 'FFFFFF',
    ink: '1A1A24', // text on the amber pills
    logo: '2E2E38', // the reserved logo plate, bottom right
    green: '2DB757', // chart bars
} as const;

const FONT = 'Overpass';
const FONT_LIGHT = 'Overpass Light';

export type PptxFactory = new () => PptxGenJS;

const FAMILY_PT: Record<string, string> = {
    'Azure & Cloud': 'Azure e nuvem',
    'Developer Tools & .NET': 'Ferramentas de desenvolvimento e .NET',
    'Other Microsoft Products': 'Outros produtos Microsoft',
};

// Short forms used on the highlight card tags, where a full impact name would wrap.
const IMPACT_SHORT: Record<string, string> = {
    'Remote Code Execution': 'RCE',
    'Elevation of Privilege': 'EoP',
    'Security Feature Bypass': 'Bypass',
    'Information Disclosure': 'Info. Disc.',
    'Denial of Service': 'DoS',
};

const pt = (map: Record<string, string>, value: string) => map[value] || value;

const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

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

// "12 de agosto de 2026" → "12 de Agosto de 2026", the cover's own capitalisation.
const fmtLongDatePt = (iso: string | null): string =>
    fmtDatePt(iso).replace(/ de (\p{Ll})/u, (_, letter: string) => ` de ${letter.toUpperCase()}`);

// dd/mm/yyyy, the form the slide footer uses.
const fmtShortDatePt = (iso: string | null): string => {
    if (!iso) return '';
    const d = new Date(iso);
    return isNaN(d.getTime()) ? '' : d.toLocaleDateString('pt-BR');
};

// "agosto de 2026" → "Agosto/2026", the form the cover and the header band use.
const monthSlashYear = (iso: string | null): string => {
    if (!iso) return 'Ciclo mais recente';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return 'Ciclo mais recente';
    return `${capitalize(d.toLocaleDateString('pt-BR', { month: 'long' }))}/${d.getFullYear()}`;
};

const statusPt = (v: PatchVulnerability): string => {
    if (v.exploited) return 'Explor. ativa';
    if (v.publiclyDisclosed) return 'Pública';
    return v.severity === 'Critical' ? 'Crítica' : v.severity;
};

// ---- Template chrome ---------------------------------------------------------

// The accent rule runs yellow → magenta → cyan. pptxgenjs has no gradient fill,
// so it is painted as abutting slices of the interpolated colour; at 0.07in tall
// the seams are not resolvable.
const GRADIENT_STOPS: [number, string][] = [
    [0, 'FFE600'],
    [0.46, 'FFE600'],
    [0.66, 'FF32FF'],
    [1, '32FFFF'],
];

const mixHex = (from: string, to: string, t: number): string =>
    [0, 2, 4]
        .map((o) => {
            const a = parseInt(from.substr(o, 2), 16);
            const b = parseInt(to.substr(o, 2), 16);
            return Math.round(a + (b - a) * t)
                .toString(16)
                .padStart(2, '0');
        })
        .join('')
        .toUpperCase();

const gradientAt = (t: number): string => {
    for (let i = 1; i < GRADIENT_STOPS.length; i++) {
        const [p0, c0] = GRADIENT_STOPS[i - 1];
        const [p1, c1] = GRADIENT_STOPS[i];
        if (t <= p1) return p1 === p0 ? c1 : mixHex(c0, c1, (t - p0) / (p1 - p0));
    }
    return GRADIENT_STOPS[GRADIENT_STOPS.length - 1][1];
};

const GRADIENT_SLICES = 40;

const gradientBar = (
    pptx: PptxGenJS,
    slide: PptxGenJS.Slide,
    x: number,
    y: number,
    w: number,
    h: number,
    vertical = false
): void => {
    const span = (vertical ? h : w) / GRADIENT_SLICES;
    for (let i = 0; i < GRADIENT_SLICES; i++) {
        slide.addShape(pptx.ShapeType.rect, {
            x: vertical ? x : x + i * span,
            y: vertical ? y + i * span : y,
            w: vertical ? w : span + 0.005, // overlap so no hairline shows between slices
            h: vertical ? span + 0.005 : h,
            fill: { color: gradientAt(i / (GRADIENT_SLICES - 1)) },
            line: { type: 'none' },
        });
    }
};

const contentSlide = (pptx: PptxGenJS, s: PatchTuesdaySummary, title: string, pageNumber: number): PptxGenJS.Slide => {
    const slide = pptx.addSlide();
    slide.background = { data: DECK_PANEL_BG, path: 'preencoded.jpg' };
    slide.addShape(pptx.ShapeType.roundRect, {
        x: 0.264, y: 0.234, w: 9.472, h: 5.151,
        rectRadius: 0.106, fill: { color: DECK.panel }, line: { type: 'none' },
    });
    slide.addText(title, {
        x: 0.539, y: 0.483, w: 8.9, h: 0.471,
        fontFace: FONT, fontSize: 21, bold: true, color: DECK.accent,
    });
    gradientBar(pptx, slide, 0.55, 0.969, 7.07, 0.07);

    const footer = { h: 0.101, fontFace: FONT_LIGHT, fontSize: 6, color: DECK.white, align: 'center' as const, valign: 'middle' as const };
    slide.addText(fmtShortDatePt(s.initialReleaseDate), { x: 0.816, y: 5.405, w: 1.046, ...footer });
    slide.addText('Cyber Threat Intelligence & Cyber Threat Hunting', { x: 1.862, y: 5.405, w: 3.137, ...footer });
    slide.addText(String(pageNumber), { x: 0.398, y: 5.405, w: 0.418, ...footer });

    // Reserved plate, bottom right: the presenter drops their own mark in here.
    slide.addShape(pptx.ShapeType.rect, {
        x: 8.428, y: 4.997, w: 1.571, h: 0.628,
        fill: { color: DECK.logo }, line: { color: DECK.accent, width: 0.75 },
    });
    return slide;
};

const attachmentNote = (slide: PptxGenJS.Slide): void => {
    slide.addText('A Listagem de Vulnerabilidades encontra-se no arquivo anexado ao e-mail.', {
        x: 0.469, y: 4.96, w: 6.936, h: 0.227,
        fontFace: FONT, fontSize: 9, bold: true, italic: true, color: DECK.white,
    });
};

// A bar chart drawn straight onto a dark surface: the plot has to be painted the
// same colour as whatever sits behind it, or it shows up as a white block.
const darkBarChart = (
    pptx: PptxGenJS,
    slide: PptxGenJS.Slide,
    rows: NamedCount[],
    box: { x: number; y: number; w: number; h: number },
    surface: string
): void => {
    // Charted bottom-up, so the largest count reads at the top of the axis.
    const data = [...rows].reverse();
    slide.addChart(
        pptx.ChartType.bar,
        [{ name: 'CVEs', labels: data.map((r) => pt(FAMILY_PT, r.name)), values: data.map((r) => r.count) }],
        {
            ...box,
            barDir: 'bar', barGapWidthPct: 45, chartColors: [DECK.green],
            showLegend: false, showTitle: false,
            showValue: true, dataLabelColor: DECK.white, dataLabelFontFace: FONT, dataLabelFontSize: 7,
            catAxisLabelColor: DECK.white, catAxisLabelFontFace: FONT_LIGHT, catAxisLabelFontSize: 7,
            catAxisLineShow: false, valAxisHidden: true,
            catGridLine: { style: 'none' }, valGridLine: { style: 'none' },
            chartArea: { fill: { color: surface }, border: { pt: 0, color: surface } },
            plotArea: { fill: { color: surface }, border: { pt: 0, color: surface } },
        }
    );
};

// ---- Slides ------------------------------------------------------------------

const addCoverSlide = (pptx: PptxGenJS, s: PatchTuesdaySummary): void => {
    const slide = pptx.addSlide();
    slide.background = { data: DECK_COVER_BG, path: 'preencoded.jpg' };
    slide.addShape(pptx.ShapeType.rect, {
        x: 8.428, y: 0, w: 1.571, h: 5.625,
        fill: { color: DECK.logo }, line: { color: DECK.accent, width: 0.75 },
    });
    slide.addText(
        [
            { text: 'Microsoft Patch Tuesday', options: { breakLine: true } },
            { text: '', options: { breakLine: true } },
            { text: 'Cyber Threat Intelligence and Hunting' },
        ],
        { x: 0.67, y: 2.066, w: 4.654, h: 1.292, fontFace: FONT, fontSize: 24, color: DECK.white, lineSpacingMultiple: 0.85 }
    );
    slide.addText(`Consolidado - ${monthSlashYear(s.initialReleaseDate)}`, {
        x: 0.67, y: 3.529, w: 4.269, h: 0.588,
        fontFace: FONT, fontSize: 14, bold: true, italic: true, color: DECK.white,
    });
    slide.addText(fmtLongDatePt(s.initialReleaseDate), {
        x: 0.67, y: 4.288, w: 4.024, h: 0.202,
        fontFace: FONT, fontSize: 14, color: DECK.white,
    });
};

// Zero-days are the CVEs Microsoft flags as exploited or already public. The full
// catalog is the source of truth; topCves stands in when a caller hands over a
// summary without it.
const zeroDays = (s: PatchTuesdaySummary): PatchVulnerability[] => {
    const isZeroDay = (v: PatchVulnerability) => v.exploited || v.publiclyDisclosed;
    const fromCatalog = s.vulnerabilities.filter(isZeroDay);
    return fromCatalog.length ? fromCatalog : s.topCves.filter(isZeroDay);
};

const addExecutiveSummarySlide = (pptx: PptxGenJS, s: PatchTuesdaySummary): void => {
    const t = s.totals;
    const slide = contentSlide(pptx, s, 'Sumário Executivo', 2);
    const zds = zeroDays(s);

    // Header band, gradient like the rule but tall enough to carry the cycle name.
    gradientBar(pptx, slide, 0.469, 0.871, 8.968, 0.295);
    slide.addText(`Microsoft Patch Tuesday (${monthSlashYear(s.initialReleaseDate)})`, {
        x: 0.539, y: 0.871, w: 8.828, h: 0.295,
        fontFace: FONT, fontSize: 12, bold: true, color: DECK.ink, valign: 'middle',
    });

    const light = { fontFace: FONT_LIGHT, fontSize: 9, color: DECK.white };
    const strong = { fontFace: FONT, fontSize: 9, color: DECK.white, bold: true };
    const opening: PptxGenJS.TextProps[] = [
        { text: `O ciclo de ${fmtMonthPt(s.initialReleaseDate)} corrige `, options: light },
        { text: `${t.total} vulnerabilidades`, options: strong },
        { text: ', incluindo ', options: light },
        { text: `${t.critical} críticas e ${zds.length} zero-days`, options: strong },
        { text: '. ', options: { ...light, breakLine: true } },
    ];
    if (zds.length) {
        opening.push({ text: 'Zero-Days: ', options: strong });
        opening.push({
            text: `${zds.map((v) => `${v.family} (${v.cve})`).join(', ')}. `,
            options: light,
        });
    }
    // The number the audience will compare against the press coverage. Saying why
    // it differs on the slide is cheaper than answering it live.
    if (t.upstream > 0) {
        opening.push({
            text: `${t.upstream} CVEs de código upstream (Chromium/Edge e pacotes do Azure Linux) ficam fora da contagem: são republicações da Microsoft, não correções em produtos próprios.`,
            options: light,
        });
    }
    slide.addText(opening, { x: 0.477, y: 1.242, w: 8.968, h: 0.984, lineSpacingMultiple: 1.25, valign: 'middle' });

    slide.addShape(pptx.ShapeType.roundRect, {
        x: 0.469, y: 2.46, w: 4.211, h: 2.332,
        rectRadius: 0.048, fill: { color: DECK.cardAlt }, line: { color: DECK.cardLine, width: 0.8 },
    });
    slide.addShape(pptx.ShapeType.roundRect, {
        x: 5.0, y: 2.46, w: 4.369, h: 2.353,
        rectRadius: 0.048, fill: { color: DECK.cardAlt }, line: { color: DECK.cardLine, width: 0.8 },
    });
    const cardLabel = { fontFace: FONT_LIGHT, fontSize: 12, bold: true, color: DECK.accent, valign: 'middle' as const };
    slide.addText('Produtos Afetados x Número de CVEs:', { x: 0.574, y: 2.572, w: 3.82, h: 0.25, ...cardLabel });
    slide.addText('Prioridades imediatas', { x: 5.187, y: 2.581, w: 2.1, h: 0.225, ...cardLabel });

    darkBarChart(pptx, slide, s.byFamily.slice(0, 8), { x: 0.5, y: 2.86, w: 4.1, h: 1.86 }, DECK.cardAlt);

    const priorities: string[] = [];
    if (t.exploited > 0) {
        const targets = zds.filter((v) => v.exploited).map((v) => v.family);
        priorities.push(
            `Priorizar imediatamente ${targets.length ? targets.join(' e ') : 'os ativos expostos'}, considerando a existência de vulnerabilidades já exploradas em ataques.`
        );
    }
    if (t.disclosed > 0) {
        priorities.push(
            `Antecipar a correção das ${t.disclosed} CVE(s) divulgadas publicamente: detalhes de exploração podem já estar circulando.`
        );
    }
    priorities.push(
        `Acelerar a atualização de ${s.byFamily.slice(0, 4).map((f) => pt(FAMILY_PT, f.name)).join(', ')}, priorizando serviços de identidade, segurança e colaboração.`
    );
    priorities.push(
        'Validar a aplicação dos patches nos ativos afetados, acompanhar falhas de instalação e tratar rapidamente sistemas sem suporte, exceções ou atualizações pendentes.'
    );
    slide.addText(
        priorities.map((text) => ({ text, options: { breakLine: true, paraSpaceAfter: 6 } })),
        { x: 5.187, y: 2.822, w: 4.047, h: 1.95, fontFace: FONT_LIGHT, fontSize: 8, color: DECK.white, lineSpacingMultiple: 1.15 }
    );

    attachmentNote(slide);
};

// The impact mix of the critical set is what the right column of the consolidated
// slide lists. `vulnerabilities` is the full catalog; when a caller hands over a
// summary without it, the cycle-wide impact split is the honest stand-in.
const criticalImpactMix = (s: PatchTuesdaySummary): NamedCount[] => {
    const counts = new Map<string, number>();
    for (const v of s.vulnerabilities) {
        if (v.severity !== 'Critical') continue;
        counts.set(v.impact, (counts.get(v.impact) || 0) + 1);
    }
    const rows = [...counts.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
    return (rows.length ? rows : s.byImpact).slice(0, 4);
};

const IMPACT_GLOSSARY = [
    'Tampering: alteração não autorizada de dados, arquivos ou configurações.',
    'Security Feature Bypass: contorno de mecanismos e controles de segurança.',
    'DoS: interrupção ou indisponibilidade de sistemas e serviços.',
    'Spoofing: falsificação de identidade ou origem para enganar sistemas e usuários.',
    'Information Disclosure: exposição indevida de informações sensíveis ou confidenciais.',
    'Remote Code Execution (RCE): execução arbitrária de código no sistema afetado.',
    'Elevation of Privilege: obtenção de permissões superiores às originalmente concedidas.',
];

const kpiPill = (
    pptx: PptxGenJS,
    slide: PptxGenJS.Slide,
    value: string,
    label: string,
    box: { x: number; y: number; vw: number; lw: number; h: number; valueSize: number }
): void => {
    const pill = { fill: { color: DECK.amber }, line: { type: 'none' as const } };
    const text = { fontFace: FONT, bold: true, color: DECK.ink, align: 'center' as const, valign: 'middle' as const };
    slide.addShape(pptx.ShapeType.rect, { x: box.x, y: box.y, w: box.vw, h: box.h, ...pill });
    slide.addText(value, { x: box.x, y: box.y, w: box.vw, h: box.h, fontSize: box.valueSize, ...text });
    slide.addShape(pptx.ShapeType.rect, { x: box.x + box.vw + 0.031, y: box.y, w: box.lw, h: box.h, ...pill });
    slide.addText(label, { x: box.x + box.vw + 0.031, y: box.y, w: box.lw, h: box.h, fontSize: 12, ...text });
};

const addConsolidatedSlide = (pptx: PptxGenJS, s: PatchTuesdaySummary): void => {
    const t = s.totals;
    const slide = contentSlide(pptx, s, 'Consolidado de Vulnerabilidades', 3);
    const zds = zeroDays(s);

    kpiPill(pptx, slide, String(t.total), 'VULNERABILIDADES', { x: 0.477, y: 0.822, vw: 0.641, lw: 2.665, h: 0.354, valueSize: 15 });
    kpiPill(pptx, slide, String(zds.length), 'VULNERABILIDADES ZERO DAY', { x: 5.254, y: 0.841, vw: 0.806, lw: 2.819, h: 0.371, valueSize: 15 });
    kpiPill(pptx, slide, String(t.critical), 'VULNERABILIDADES CRÍTICAS', { x: 5.254, y: 2.776, vw: 0.836, lw: 2.781, h: 0.354, valueSize: 18 });

    gradientBar(pptx, slide, 4.742, 0.806, 0.038, 4.304, true);

    const sectionLabel = { fontFace: FONT, fontSize: 9, bold: true, color: DECK.accent, valign: 'middle' as const };
    slide.addText('Distribuição de CVEs:', { x: 0.481, y: 1.288, w: 2.849, h: 0.225, ...sectionLabel });
    darkBarChart(pptx, slide, s.byImpact.slice(0, 7), { x: 0.55, y: 1.474, w: 3.943, h: 1.691 }, DECK.panel);

    slide.addText('Descrição Executiva da Vulnerabilidade:', { x: 0.481, y: 3.13, w: 2.849, h: 0.225, ...sectionLabel });
    slide.addText(
        IMPACT_GLOSSARY.map((text) => ({ text, options: { breakLine: true, bullet: true } })),
        { x: 0.469, y: 3.32, w: 4.441, h: 1.826, fontFace: FONT_LIGHT, fontSize: 8, color: DECK.white }
    );

    // Zero-day mini cards, right of the divider.
    zds.slice(0, 3).forEach((v, i) => {
        const x = [5.268, 6.556, 7.812][i];
        const y = 1.381;
        slide.addShape(pptx.ShapeType.roundRect, {
            x, y, w: 1.096, h: 1.167,
            rectRadius: 0.024, fill: { color: DECK.card }, line: { color: DECK.red, width: 0.8 },
            shadow: { type: 'outer', color: '000000', opacity: 0.18, blur: 3, offset: 0.5, angle: 45 },
        });
        slide.addShape(pptx.ShapeType.rect, { x, y, w: 1.096, h: 0.062, fill: { color: DECK.red }, line: { type: 'none' } });
        slide.addShape(pptx.ShapeType.rect, { x: x + 0.006, y: 1.728, w: 1.09, h: 0.05, fill: { color: DECK.red }, line: { type: 'none' } });
        slide.addText(v.cve, {
            x: x + 0.057, y: 1.511, w: 0.981, h: 0.145,
            fontFace: FONT_LIGHT, fontSize: 8, bold: true, color: DECK.accent, valign: 'middle',
            hyperlink: { url: `https://msrc.microsoft.com/update-guide/vulnerability/${v.cve}` },
        });
        slide.addText(pt(FAMILY_PT, v.family), {
            x: x + 0.057, y: 1.837, w: 0.981, h: 0.121,
            fontFace: FONT_LIGHT, fontSize: 8, bold: true, color: DECK.white, valign: 'middle', fit: 'shrink',
        });
        slide.addText(v.exploited ? 'Exploração ativa' : 'Publicamente divulgada', {
            x: x + 0.057, y: 1.94, w: 0.981, h: 0.106,
            fontFace: FONT_LIGHT, fontSize: 5, bold: true, italic: true, color: DECK.muted, valign: 'middle',
        });
        slide.addText(condenseTitle(v.title, 120), {
            x: x + 0.057, y: 2.109, w: 0.981, h: 0.347,
            fontFace: FONT_LIGHT, fontSize: 5, color: DECK.white, valign: 'middle', fit: 'shrink',
        });
    });

    slide.addText(
        [
            ...criticalImpactMix(s).map((r) => ({
                text: `${r.count} ${r.name}`,
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

// A title long enough to wrap breaks the fixed card height, so it is condensed and
// the untruncated text goes to the speaker notes.
const condenseTitle = (title: string, max = 78) => (title.length > max ? `${title.slice(0, max - 1)}…` : title);

const addHighlightsSlide = (pptx: PptxGenJS, s: PatchTuesdaySummary): void => {
    const slide = contentSlide(pptx, s, 'Highlights: Vulnerabilidades Críticas', 4);
    slide.addText('Seleção orientada ao risco corporativo e à exploração observada:', {
        x: 0.413, y: 0.715, w: 8.807, h: 0.379,
        fontFace: FONT_LIGHT, fontSize: 9, bold: true, color: DECK.white,
    });

    // Zero-days lead, then the criticals; six cards is what the grid holds.
    const zds = zeroDays(s);
    const listed = new Set(zds.map((v) => v.cve));
    const highlights = [...zds, ...s.topCves.filter((v) => !listed.has(v.cve))].slice(0, 6);
    const cols = [0.469, 3.476, 6.566];
    const cardW = 2.85;

    highlights.forEach((v, i) => {
        const x = cols[i % 3];
        const y = i < 3 ? 1.065 : 3.09;
        slide.addShape(pptx.ShapeType.roundRect, {
            x, y, w: cardW, h: 1.815,
            rectRadius: 0.038, fill: { color: DECK.card }, line: { color: DECK.red, width: 0.8 },
            shadow: { type: 'outer', color: '000000', opacity: 0.18, blur: 3, offset: 0.5, angle: 45 },
        });
        slide.addShape(pptx.ShapeType.rect, { x, y, w: cardW, h: 0.096, fill: { color: DECK.red }, line: { type: 'none' } });
        slide.addText(v.cve, {
            x: x + 0.109, y: y + 0.21, w: cardW - 0.22, h: 0.225,
            fontFace: FONT_LIGHT, fontSize: 11, bold: true, color: DECK.red,
            hyperlink: { url: `https://msrc.microsoft.com/update-guide/vulnerability/${v.cve}` },
        });
        slide.addText(pt(FAMILY_PT, v.family), {
            x: x + 0.109, y: y + 0.51, w: cardW - 0.22, h: 0.187,
            fontFace: FONT_LIGHT, fontSize: 9, bold: true, color: DECK.white, fit: 'shrink',
        });
        slide.addText(`${pt(IMPACT_SHORT, v.impact)} | ${statusPt(v)}`, {
            x: x + 0.137, y: y + 0.741, w: cardW - 0.27, h: 0.165,
            fontFace: FONT_LIGHT, fontSize: 7, bold: true, color: DECK.muted,
        });
        slide.addText(condenseTitle(v.title, 130), {
            x: x + 0.137, y: y + 1.012, w: cardW - 0.27, h: 0.54,
            fontFace: FONT_LIGHT, fontSize: 8, color: DECK.white, fit: 'shrink',
        });
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

    attachmentNote(slide);
};

// MSRC titles and product names are free text we do not control. XML 1.0 has no
// legal representation for the C0 controls (not even `&#x7;`), so one of them in
// a title is enough for PowerPoint and Excel to declare the file corrupt and
// offer to repair it. Both builders scrub their input before writing anything.
// eslint-disable-next-line no-control-regex
const XML_ILLEGAL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g;
const scrubXml = <T>(v: T): T =>
    typeof v === 'string'
        ? (v.replace(XML_ILLEGAL, '') as T)
        : Array.isArray(v)
          ? (v.map(scrubXml) as T)
          : v && typeof v === 'object'
            ? (Object.fromEntries(Object.entries(v).map(([k, x]) => [k, scrubXml(x)])) as T)
            : v;

export function buildPatchTuesdayPresentation(rawSummary: PatchTuesdaySummary, PptxLib: PptxFactory): PptxGenJS {
    const summary = scrubXml(rawSummary);
    const pptx = new PptxLib();
    pptx.layout = 'LAYOUT_16x9'; // 10 × 5.625in, the reference deck's exact canvas
    pptx.author = 'ThreatSumm4ry';
    pptx.company = '';
    (pptx as PptxGenJS & { lang: string }).lang = 'pt-BR';
    pptx.subject = 'Relatório automático do Microsoft Patch Tuesday';
    pptx.title = `Microsoft Patch Tuesday — ${fmtMonthPt(summary.initialReleaseDate)}`;

    addCoverSlide(pptx, summary);
    addExecutiveSummarySlide(pptx, summary);
    addConsolidatedSlide(pptx, summary);
    addHighlightsSlide(pptx, summary);
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

// Sheet standard matching the deck: black header band, yellow bold Calibri 14,
// yellow tabs, thin border, frozen header row, autofilter, and no colour on the
// data rows — whoever reads it filters by column instead.
// Labels are PT-BR; the values MSRC publishes (severity, impact, exploitability)
// stay in English, since those are the canonical terms people search for.
const SHEET_HEADER = '000000';
const SHEET_HEADER_TEXT = 'FFE600';
const SHEET_BORDER = { style: 'thin' as const };

// Both URLs are deterministic from the CVE id, so the sheet builds them locally
// instead of asking MSRC for a link it already knows how to write.
export const msrcCveUrl = (cve: string) => `https://msrc.microsoft.com/update-guide/vulnerability/${cve}`;
export const nvdCveUrl = (cve: string) => `https://nvd.nist.gov/vuln/detail/${cve}`;

export const patchTuesdayExcelFilename = (s: PatchTuesdaySummary) => `Patch-Tuesday-Microsoft-${s.id || 'report'}.xlsx`;

const LINK_FONT = { name: 'Calibri', color: { argb: 'FF0563C1' }, underline: true } as const;

export interface ExcelWorkbookFactory {
    Workbook: new () => ExcelJS.Workbook;
}

const styleHeaderRow = (ws: ExcelJS.Worksheet, row: number, lastCol: number) => {
    const r = ws.getRow(row);
    for (let c = 1; c <= lastCol; c++) {
        const cell = r.getCell(c);
        cell.font = { name: 'Calibri', bold: true, size: 14, color: { argb: `FF${SHEET_HEADER_TEXT}` } };
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: `FF${SHEET_HEADER}` } };
        cell.alignment = { horizontal: 'left', vertical: 'top' };
        cell.border = { top: SHEET_BORDER, left: SHEET_BORDER, bottom: SHEET_BORDER, right: SHEET_BORDER };
    }
    r.height = 18.5;
};

export function buildPatchTuesdayWorkbook(rawSummary: PatchTuesdaySummary, ExcelLib: ExcelWorkbookFactory): ExcelJS.Workbook {
    const summary = scrubXml(rawSummary);
    const wb = new ExcelLib.Workbook();
    wb.creator = 'ThreatSumm4ry';
    wb.company = '';
    wb.created = new Date();
    const t = summary.totals;

    // ---- Resumo ----
    const resumo = wb.addWorksheet('Resumo', { properties: { tabColor: { argb: `FF${SHEET_HEADER_TEXT}` } } });
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
        { header: 'Microsoft', key: 'msrc', width: 14 },
        { header: 'NVD', key: 'nvd', width: 10 },
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
        properties: { tabColor: { argb: `FF${SHEET_HEADER_TEXT}` } },
        views: [{ state: 'frozen', ySplit: 1 }],
    });
    base.columns = cols;
    styleHeaderRow(base, 1, cols.length);
    summary.vulnerabilities.forEach((v) => {
        const row = base.addRow({
            cve: v.cve,
            msrc: { text: 'Microsoft', hyperlink: msrcCveUrl(v.cve) },
            nvd: { text: 'NVD', hyperlink: nvdCveUrl(v.cve) },
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
        row.getCell('msrc').font = LINK_FONT;
        row.getCell('nvd').font = LINK_FONT;
    });
    base.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: cols.length } };

    return wb;
}

export async function exportPatchTuesdayExcel(summary: PatchTuesdaySummary): Promise<void> {
    const { default: ExcelLib } = await import('exceljs');
    const wb = buildPatchTuesdayWorkbook(summary, ExcelLib);
    const buf = await wb.xlsx.writeBuffer();
    triggerDownload(new Blob([buf], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }), patchTuesdayExcelFilename(summary));
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
