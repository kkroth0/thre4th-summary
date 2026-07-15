// Document generators for the SAP Security Patch Day summary (PDF / PPTX / Excel).
// Heavy libs (jspdf, jspdf-autotable, pptxgenjs, exceljs) are typed-only here and
// imported lazily inside each exporter, so the page route stays light.
import type { jsPDF } from 'jspdf';
import type PptxGenJS from 'pptxgenjs';
import type ExcelJS from 'exceljs';
import type { SapPatchSummary, SapNote } from '@/services/sapApi';
import { buildSapReportAnalysis, type SapReportAnalysis } from './sapPatchAnalysis';

const BRAND = '2563EB';
const INK = '0F172A';
const MUTED = '64748B';

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

const baseFilename = (s: SapPatchSummary) => {
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

    doc.save(`${baseFilename(s)}.pdf`);
}

// ---- PPTX ----------------------------------------------------------------------
const COLORS = { blue: '1565C0', navy: '172033', slate: '526274', pale: 'F3F6FA', border: 'DCE3EE', white: 'FFFFFF', critical: 'C62828', high: 'E66A21', medium: 'C58A00', low: '2E7D32' } as const;
export type PptxFactory = new () => PptxGenJS;

const formatReportMonth = (date: string | null): string => {
    if (!date) return 'Ciclo mais recente';
    const value = new Date(`${date}T00:00:00Z`);
    return Number.isNaN(value.getTime()) ? date : value.toLocaleDateString('pt-BR', { month: 'long', year: 'numeric', timeZone: 'UTC' });
};
const slideTitle = (slide: PptxGenJS.Slide, title: string) => slide.addText(title, { x: .55, y: .35, w: 12.2, h: .45, fontSize: 23, bold: true, color: COLORS.navy });
const addCoverSlide = (pptx: PptxGenJS, summary: SapPatchSummary): void => {
    const slide = pptx.addSlide(); slide.background = { color: COLORS.navy };
    slide.addText('SAP Security Patch Day', { x: .7, y: 2.15, w: 12, h: .65, fontSize: 32, bold: true, color: COLORS.white });
    slide.addText(formatReportMonth(summary.releaseDate), { x: .7, y: 2.9, w: 12, h: .55, fontSize: 22, color: COLORS.blue });
    slide.addText(`${summary.summary.total} notas · CVSS máximo ${summary.summary.maxCvss.toFixed(1)}`, { x: .7, y: 3.65, w: 12, h: .45, fontSize: 15, color: 'DCE3EE' });
    slide.addText('Fonte oficial SAP', { x: .7, y: 6.45, w: 12, h: .3, fontSize: 10, color: COLORS.slate });
};
const addExecutiveSummarySlide = (pptx: PptxGenJS, summary: SapPatchSummary, analysis: SapReportAnalysis): void => {
    const slide = pptx.addSlide({ masterName: 'EXECUTIVO' }); slideTitle(slide, 'Sumário executivo');
    slide.addText(analysis.executiveSummary, { x: .7, y: 1.15, w: 11.9, h: .8, fontSize: 18, color: COLORS.navy });
    analysis.immediatePriorities.forEach((item, index) => slide.addText(`• ${item}`, { x: .9, y: 2.25 + index * .55, w: 11.4, h: .4, fontSize: 14, color: COLORS.slate }));
    slide.addText(`Hot News/Critical: ${summary.summary.hotNews} · High: ${summary.summary.high}`, { x: .9, y: 4.6, w: 11.4, h: .4, fontSize: 16, bold: true, color: COLORS.critical });
};
const addConsolidatedSlide = (pptx: PptxGenJS, _summary: SapPatchSummary, analysis: SapReportAnalysis): void => {
    const slide = pptx.addSlide({ masterName: 'EXECUTIVO' }); slideTitle(slide, 'Consolidado de vulnerabilidades');
    slide.addChart(pptx.ChartType.bar, [{ name: 'Notas', labels: analysis.categoryCounts.map(x => x.category), values: analysis.categoryCounts.map(x => x.count) }], { x: .6, y: 1.15, w: 6.1, h: 4.9, catAxisLabelFontSize: 9, showLegend: false, showValue: true });
    analysis.topThree.forEach((note, index) => {
        const y = 1.15 + index * 1.65;
        slide.addShape(pptx.ShapeType.roundRect, { x: 7, y, w: 5.7, h: 1.35, fill: { color: COLORS.pale }, line: { color: COLORS.border } });
        slide.addText(`${note.note} · ${note.cvss == null ? 'Não informado' : note.cvss.toFixed(1)}`, { x: 7.2, y: y + .12, w: 5.2, h: .3, fontSize: 13, bold: true, color: priorityHex(note.priority) });
        slide.addText(`${note.primaryCve || 'Não informada'} · ${note.product}`, { x: 7.2, y: y + .48, w: 5.2, h: .3, fontSize: 10, color: COLORS.slate });
        slide.addText(note.title, { x: 7.2, y: y + .8, w: 5.2, h: .35, fontSize: 10, color: COLORS.navy });
    });
};
const displayTitle = (title: string) => title.length > 100 ? `${title.slice(0, 99)}…` : title;
const addHighlightsSlide = (pptx: PptxGenJS, analysis: SapReportAnalysis): void => {
    const slide = pptx.addSlide({ masterName: 'EXECUTIVO' }); slideTitle(slide, 'Highlights de vulnerabilidades');
    const cell = (text: string): PptxGenJS.TableCell => ({ text, options: {} });
    const rows: PptxGenJS.TableRow[] = [
        ['CVE', 'Título', 'CVSS', 'Produto/Componente'].map(cell),
        ...analysis.notes.map(note => [note.primaryCve, displayTitle(note.title), note.cvss == null ? 'Não informado' : note.cvss.toFixed(1), note.product].map(cell)),
    ];
    slide.addTable(rows, { x: .45, y: 1.05, w: 12.45, colW: [2.05, 5.7, 1.05, 3.65], fontSize: analysis.notes.length <= 20 ? 8 : 7, border: { type: 'solid', color: COLORS.border, pt: .5 }, fill: { color: COLORS.white }, color: COLORS.navy, bold: false });
};
const addRecommendationsSlide = (pptx: PptxGenJS, analysis: SapReportAnalysis): void => {
    const slide = pptx.addSlide({ masterName: 'EXECUTIVO' }); slideTitle(slide, 'Conclusão e recomendações');
    analysis.recommendations.forEach((item, index) => {
        const col = index % 2, row = Math.floor(index / 2), x = .65 + col * 6.15, y = 1.15 + row * 1.75;
        slide.addText(item.title, { x, y, w: 5.75, h: .3, fontSize: 13, bold: true, color: COLORS.blue });
        slide.addText(item.body, { x, y: y + .38, w: 5.75, h: .85, fontSize: 10, color: COLORS.slate, breakLine: false });
    });
};
const addReferencesSlide = (pptx: PptxGenJS, summary: SapPatchSummary, analysis: SapReportAnalysis): void => {
    const slide = pptx.addSlide({ masterName: 'EXECUTIVO' }); slideTitle(slide, 'Referências');
    slide.addText('Fonte oficial SAP', { x: .7, y: 1.15, w: 11.8, h: .35, fontSize: 15, bold: true, color: COLORS.blue });
    const links = [...new Set([summary.url, ...analysis.notes.map(note => note.noteUrl)].filter(Boolean))];
    links.forEach((link, index) => slide.addText(link, { x: .85, y: 1.7 + index * .42, w: 11.6, h: .3, fontSize: 10, color: COLORS.slate, hyperlink: { url: link } }));
    slide.addText(`Gerado em ${new Date().toLocaleString('pt-BR')}`, { x: .7, y: 6.25, w: 11.8, h: .3, fontSize: 9, color: COLORS.slate });
};

export function buildSapPatchPresentation(summary: SapPatchSummary, PptxLib: PptxFactory): PptxGenJS {
    const pptx = new PptxLib();
    pptx.defineLayout({ name: 'SAP_EXECUTIVO', width: 13.333, height: 7.5 }); pptx.layout = 'SAP_EXECUTIVO';
    pptx.author = 'ThreatSumm4ry'; pptx.company = ''; (pptx as PptxGenJS & { lang: string }).lang = 'pt-BR';
    pptx.subject = 'Relatório automático do SAP Security Patch Day'; pptx.title = `SAP Security Patch Day — ${formatReportMonth(summary.releaseDate)}`;
    pptx.defineSlideMaster({ title: 'EXECUTIVO', background: { color: COLORS.white }, objects: [
        { rect: { x: 0, y: 0, w: 13.333, h: .08, fill: { color: COLORS.blue }, line: { color: COLORS.blue } } },
        { text: { text: 'SAP Security Patch Day', options: { x: .45, y: 7.08, w: 4, h: .25, fontSize: 8, color: COLORS.slate } } },
        { text: { text: summary.releaseDate || 'Ciclo mais recente', options: { x: 5, y: 7.08, w: 3.3, h: .25, fontSize: 8, color: COLORS.slate, align: 'center' } } },
    ], slideNumber: { x: 12.35, y: 7.08, w: .5, h: .25, fontSize: 8, color: COLORS.slate } });
    const analysis = buildSapReportAnalysis(summary);
    addCoverSlide(pptx, summary); addExecutiveSummarySlide(pptx, summary, analysis); addConsolidatedSlide(pptx, summary, analysis);
    addHighlightsSlide(pptx, analysis); addRecommendationsSlide(pptx, analysis); addReferencesSlide(pptx, summary, analysis);
    return pptx;
}

export async function exportSapPatchPPTX(summary: SapPatchSummary): Promise<void> {
    const { default: PptxGenLib } = await import('pptxgenjs');
    const pptx = buildSapPatchPresentation(summary, PptxGenLib);
    await pptx.writeFile({ fileName: `${baseFilename(summary)}.pptx` });
}

// ---- Excel ---------------------------------------------------------------------
export async function exportSapPatchExcel(s: SapPatchSummary): Promise<void> {
    const { default: ExcelLib } = await import('exceljs');
    const wb = new ExcelLib.Workbook();
    wb.creator = 'ThreatSumm4ry';
    wb.created = new Date();

    const headerFill = (ws: ExcelJS.Worksheet, row: number, lastCol: number, color = INK) => {
        const r = ws.getRow(row);
        for (let c = 1; c <= lastCol; c++) {
            const cell = r.getCell(c);
            cell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
            cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: `FF${color}` } };
            cell.alignment = { vertical: 'middle' };
        }
        r.height = 20;
    };

    const ov = wb.addWorksheet('Overview', { properties: { tabColor: { argb: 'FF2563EB' } } });
    ov.mergeCells('A1:B1');
    ov.getCell('A1').value = `SAP Security Patch Day — ${fmtDate(s.releaseDate)}`;
    ov.getCell('A1').font = { bold: true, size: 16, color: { argb: 'FF0F172A' } };
    ov.mergeCells('A2:B2');
    ov.getCell('A2').value = `Source: support.sap.com  ·  Generated ${new Date().toLocaleString('en-US')}`;
    ov.getCell('A2').font = { size: 10, color: { argb: 'FF64748B' } };
    ov.getRow(4).values = ['Metric', 'Value'];
    headerFill(ov, 4, 2);
    for (const k of kpiList(s)) ov.addRow([k.label, k.value]);
    ov.getColumn(1).width = 24;
    ov.getColumn(2).width = 14;

    const ws = wb.addWorksheet('Notes', { views: [{ state: 'frozen', ySplit: 1 }] });
    ws.columns = [
        { header: 'Note#', key: 'note', width: 12 },
        { header: 'Title', key: 'title', width: 70 },
        { header: 'CVE', key: 'cves', width: 22 },
        { header: 'Priority', key: 'priority', width: 12 },
        { header: 'CVSS', key: 'cvss', width: 8 },
        { header: 'CVSS Vector', key: 'cvssVector', width: 40 },
        { header: 'Update', key: 'isUpdate', width: 9 },
        { header: 'SAP Note URL', key: 'noteUrl', width: 40 },
    ];
    headerFill(ws, 1, 8, '2563EB');
    for (const n of s.notes) {
        ws.addRow({
            note: n.note, title: n.title, cves: n.cves.join(', '), priority: n.priority,
            cvss: n.cvss ?? '', cvssVector: n.cvssVector || '', isUpdate: n.isUpdate ? 'yes' : '', noteUrl: n.noteUrl,
        });
    }
    ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: 8 } };

    const buf = await wb.xlsx.writeBuffer();
    triggerDownload(new Blob([buf], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }), `${baseFilename(s)}.xlsx`);
}
