// Document generators for the SAP Security Patch Day summary (PDF / PPTX / Excel).
// Heavy libs (jspdf, jspdf-autotable, pptxgenjs, exceljs) are typed-only here and
// imported lazily inside each exporter, so the page route stays light.
import type { jsPDF } from 'jspdf';
import type PptxGenJS from 'pptxgenjs';
import type ExcelJS from 'exceljs';
import type { SapPatchSummary, SapNote } from '@/services/sapApi';

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

const baseFilename = (s: SapPatchSummary) => `SAP Security Patch Day - ${s.releaseDate || 'latest'}`;
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
export async function exportSapPatchPPTX(s: SapPatchSummary): Promise<void> {
    const { default: PptxGenLib } = await import('pptxgenjs');
    const pptx = new PptxGenLib();
    pptx.defineLayout({ name: 'WIDE', width: 13.333, height: 7.5 });
    pptx.layout = 'WIDE';
    pptx.title = 'SAP Security Patch Day';
    const W = 13.333;

    pptx.defineSlideMaster({
        title: 'BASE',
        background: { color: 'FFFFFF' },
        objects: [
            { rect: { x: 0, y: 7.05, w: W, h: 0.45, fill: { color: 'F1F5F9' } } },
            { text: { text: 'ThreatSumm4ry · SAP Security Patch Day', options: { x: 0.4, y: 7.05, w: 8, h: 0.45, fontSize: 9, color: MUTED, valign: 'middle' } } },
        ],
        slideNumber: { x: 12.4, y: 7.05, w: 0.6, h: 0.45, fontSize: 9, color: MUTED },
    });

    const s1 = pptx.addSlide();
    s1.background = { color: INK };
    s1.addShape(pptx.ShapeType.rect, { x: 0, y: 3.4, w: W, h: 0.08, fill: { color: BRAND } });
    s1.addText('SAP SECURITY PATCH DAY', { x: 0.7, y: 2.1, w: 12, h: 0.5, fontSize: 18, color: '93C5FD', bold: true, charSpacing: 3 });
    s1.addText(fmtDate(s.releaseDate), { x: 0.7, y: 2.6, w: 12, h: 1, fontSize: 40, color: 'FFFFFF', bold: true });
    s1.addText(`${s.summary.total} security notes  ·  ${s.summary.hotNews} Hot News  ·  Max CVSS ${s.summary.maxCvss.toFixed(1)}`,
        { x: 0.7, y: 3.7, w: 12, h: 1, fontSize: 16, color: 'CBD5E1' });
    s1.addText('Source: support.sap.com (SAP Security Notes)', { x: 0.7, y: 6.4, w: 12, h: 0.4, fontSize: 11, color: '64748B' });

    const s2 = pptx.addSlide({ masterName: 'BASE' });
    s2.addText('Overview', { x: 0.5, y: 0.35, w: 12, h: 0.6, fontSize: 24, bold: true, color: INK });
    const kpis = kpiList(s);
    const cw = 2.3;
    const gap = 0.2;
    const totalW = kpis.length * cw + (kpis.length - 1) * gap;
    kpis.forEach((k, i) => {
        const x = (W - totalW) / 2 + i * (cw + gap);
        s2.addShape(pptx.ShapeType.roundRect, { x, y: 2.4, w: cw, h: 1.6, fill: { color: 'F8FAFC' }, line: { color: 'E2E8F0', width: 1 }, rectRadius: 0.08 });
        s2.addText(String(k.value), { x, y: 2.7, w: cw, h: 0.7, fontSize: 30, bold: true, color: k.color, align: 'center' });
        s2.addText(k.label, { x, y: 3.45, w: cw, h: 0.4, fontSize: 12, color: MUTED, align: 'center' });
    });

    const s3 = pptx.addSlide({ masterName: 'BASE' });
    s3.addText('Security notes', { x: 0.5, y: 0.35, w: 12, h: 0.6, fontSize: 24, bold: true, color: INK });
    const rows: PptxGenJS.TableRow[] = [
        ['Note#', 'Title', 'Priority', 'CVSS'].map((h) => ({ text: h, options: { bold: true, color: 'FFFFFF', fill: { color: INK } } })),
    ];
    for (const n of s.notes.slice(0, 18)) {
        rows.push([
            { text: n.note, options: {} },
            { text: n.title.slice(0, 90), options: {} },
            { text: n.priority, options: { color: priorityHex(n.priority), bold: true } },
            { text: n.cvss == null ? '—' : String(n.cvss), options: { align: 'right' } },
        ]);
    }
    s3.addTable(rows, { x: 0.4, y: 1.1, w: 12.5, colW: [1.4, 8.1, 1.6, 1.4], fontSize: 10, border: { type: 'solid', color: 'E2E8F0', pt: 0.5 }, valign: 'middle' });

    await pptx.writeFile({ fileName: `${baseFilename(s)}.pptx` });
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
