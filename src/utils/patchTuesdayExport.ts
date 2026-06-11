// Professional document generators for the Microsoft Patch Tuesday summary.
// Produces consolidated PDF, PPTX and Excel artifacts from a normalized summary.
import { jsPDF } from 'jspdf';
import autoTable, { type CellHookData } from 'jspdf-autotable';
import PptxGenJS from 'pptxgenjs';
import ExcelJS from 'exceljs';
import type { PatchTuesdaySummary, PatchVulnerability } from '@/services/msrcApi';

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

export function exportPatchTuesdayPDF(summary: PatchTuesdaySummary): void {
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

    // ---- Severity + Impact + Family tables (two columns) ----
    sectionTitle('Severity Distribution');
    autoTable(doc, {
        startY: y,
        head: [['Severity', 'CVEs', 'Share']],
        body: [
            ['Critical', summary.totals.critical, pct(summary.totals.critical, summary.totals.total)],
            ['Important', summary.totals.important, pct(summary.totals.important, summary.totals.total)],
            ['Moderate', summary.totals.moderate, pct(summary.totals.moderate, summary.totals.total)],
            ['Low', summary.totals.low, pct(summary.totals.low, summary.totals.total)],
            ['Unrated / Edge', summary.totals.unknown, pct(summary.totals.unknown, summary.totals.total)],
        ],
        theme: 'grid',
        headStyles: { fillColor: [15, 23, 42], fontSize: 8.5 },
        bodyStyles: { fontSize: 8.5 },
        margin: { left: margin, right: margin },
    });
    y = finalY(doc) + 8;

    sectionTitle('Vulnerabilities by Impact');
    autoTable(doc, {
        startY: y,
        head: [['Impact / Category', 'CVEs', 'Share']],
        body: summary.byImpact.map((i) => [i.name, i.count, pct(i.count, summary.totals.total)]),
        theme: 'striped',
        headStyles: { fillColor: [37, 99, 235], fontSize: 8.5 },
        bodyStyles: { fontSize: 8.5 },
        margin: { left: margin, right: margin },
    });
    y = finalY(doc) + 8;

    if (y > pageH - 60) {
        doc.addPage();
        y = 20;
    }
    sectionTitle('Affected Product Families');
    autoTable(doc, {
        startY: y,
        head: [['Product Family', 'CVEs', 'Share']],
        body: summary.byFamily.map((f) => [f.name, f.count, pct(f.count, summary.totals.total)]),
        theme: 'striped',
        headStyles: { fillColor: [37, 99, 235], fontSize: 8.5 },
        bodyStyles: { fontSize: 8.5 },
        margin: { left: margin, right: margin },
    });
    y = finalY(doc) + 8;

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

const pct = (n: number, total: number) => (total ? `${((n / total) * 100).toFixed(1)}%` : '0%');

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

export async function exportPatchTuesdayPPTX(summary: PatchTuesdaySummary): Promise<void> {
    const pptx = new PptxGenJS();
    pptx.defineLayout({ name: 'WIDE', width: 13.333, height: 7.5 });
    pptx.layout = 'WIDE';
    pptx.author = 'ThreatSumm4ry';
    pptx.company = 'ThreatSumm4ry';
    pptx.title = `${summary.title} — Patch Tuesday`;

    const W = 13.333;
    const t = summary.totals;

    // Master with footer
    pptx.defineSlideMaster({
        title: 'BASE',
        background: { color: 'FFFFFF' },
        objects: [
            { rect: { x: 0, y: 7.05, w: W, h: 0.45, fill: { color: 'F1F5F9' } } },
            { text: { text: 'ThreatSumm4ry · Microsoft Patch Tuesday Summary', options: { x: 0.4, y: 7.05, w: 8, h: 0.45, fontSize: 9, color: MUTED, valign: 'middle' } } },
        ],
        slideNumber: { x: 12.4, y: 7.05, w: 0.6, h: 0.45, fontSize: 9, color: MUTED },
    });

    // ---- Slide 1: Title ----
    const s1 = pptx.addSlide();
    s1.background = { color: INK };
    s1.addShape(pptx.ShapeType.rect, { x: 0, y: 3.4, w: W, h: 0.08, fill: { color: BRAND } });
    s1.addText('MICROSOFT PATCH TUESDAY', { x: 0.7, y: 2.1, w: 12, h: 0.5, fontSize: 18, color: '93C5FD', bold: true, charSpacing: 3 });
    s1.addText(summary.title || 'Security Updates', { x: 0.7, y: 2.6, w: 12, h: 1, fontSize: 40, color: 'FFFFFF', bold: true });
    s1.addText(
        [
            { text: `Release date: ${fmtDate(summary.initialReleaseDate)}`, options: { breakLine: true } },
            { text: `${t.total} CVEs  ·  ${t.critical} Critical  ·  ${t.exploited} Exploited  ·  ${t.disclosed} Publicly Disclosed`, options: {} },
        ],
        { x: 0.7, y: 3.7, w: 12, h: 1, fontSize: 16, color: 'CBD5E1' }
    );
    s1.addText('Source: Microsoft Security Response Center (MSRC) CVRF v3.0', { x: 0.7, y: 6.4, w: 12, h: 0.4, fontSize: 11, color: '64748B' });

    // ---- Slide 2: Executive KPIs ----
    const s2 = pptx.addSlide({ masterName: 'BASE' });
    slideHeading(pptx, s2, 'Executive Summary');
    const cards = [
        { label: 'Total CVEs', value: t.total, color: BRAND },
        { label: 'Critical', value: t.critical, color: SEVERITY_HEX.Critical },
        { label: 'Important', value: t.important, color: SEVERITY_HEX.Important },
        { label: 'Exploited', value: t.exploited, color: 'B91C1C' },
        { label: 'Publicly Disclosed', value: t.disclosed, color: '7C3AED' },
        { label: 'Exploitation More Likely', value: t.exploitMoreLikely, color: 'C2410C' },
    ];
    const cw = 3.9, ch = 1.7, cgap = 0.35;
    cards.forEach((c, i) => {
        const col = i % 3, row = Math.floor(i / 3);
        const x = 0.7 + col * (cw + cgap);
        const yy = 1.7 + row * (ch + 0.35);
        s2.addShape(pptx.ShapeType.roundRect, { x, y: yy, w: cw, h: ch, rectRadius: 0.08, fill: { color: 'F8FAFC' }, line: { color: 'E2E8F0', width: 1 } });
        s2.addText(String(c.value), { x, y: yy + 0.2, w: cw, h: 0.9, fontSize: 40, bold: true, color: c.color, align: 'center' });
        s2.addText(c.label.toUpperCase(), { x, y: yy + 1.15, w: cw, h: 0.4, fontSize: 11, color: MUTED, align: 'center', charSpacing: 1 });
    });

    // ---- Slide 3: Severity + Impact charts ----
    const s3 = pptx.addSlide({ masterName: 'BASE' });
    slideHeading(pptx, s3, 'Severity & Impact Breakdown');
    s3.addChart(
        pptx.ChartType.doughnut,
        [{
            name: 'Severity',
            labels: ['Critical', 'Important', 'Moderate', 'Low', 'Unrated/Edge'],
            values: [t.critical, t.important, t.moderate, t.low, t.unknown],
        }],
        {
            x: 0.7, y: 1.7, w: 5.6, h: 4.8,
            chartColors: [SEVERITY_HEX.Critical, SEVERITY_HEX.Important, SEVERITY_HEX.Moderate, SEVERITY_HEX.Low, SEVERITY_HEX.Unknown],
            showLegend: true, legendPos: 'b', showTitle: true, title: 'By Severity', titleFontSize: 14,
            showValue: true, dataLabelFontSize: 9, holeSize: 55,
        }
    );
    const topImpacts = summary.byImpact.slice(0, 7);
    s3.addChart(
        pptx.ChartType.bar,
        [{ name: 'CVEs', labels: topImpacts.map((i) => i.name), values: topImpacts.map((i) => i.count) }],
        {
            x: 6.7, y: 1.7, w: 6, h: 4.8,
            barDir: 'bar', chartColors: [BRAND],
            showTitle: true, title: 'By Impact', titleFontSize: 14,
            showValue: true, dataLabelFontSize: 9, catAxisLabelFontSize: 9, valAxisHidden: true,
        }
    );

    // ---- Slide 4: Product families ----
    const s4 = pptx.addSlide({ masterName: 'BASE' });
    slideHeading(pptx, s4, 'Affected Product Families');
    const fams = summary.byFamily.slice(0, 10);
    s4.addChart(
        pptx.ChartType.bar,
        [{ name: 'CVEs', labels: fams.map((f) => f.name), values: fams.map((f) => f.count) }],
        {
            x: 0.7, y: 1.7, w: 12, h: 4.9,
            barDir: 'bar', chartColors: ['1E3A8A'],
            showValue: true, dataLabelFontSize: 10, catAxisLabelFontSize: 11, valAxisHidden: true,
        }
    );

    // ---- Slide 5: Priority CVEs table ----
    const s5 = pptx.addSlide({ masterName: 'BASE' });
    slideHeading(pptx, s5, 'Priority CVEs');
    const headerRow = ['CVE', 'Sev', 'CVSS', 'Impact', 'Status', 'Title'].map((h) => ({
        text: h, options: { bold: true, color: 'FFFFFF', fill: { color: INK }, fontSize: 11, valign: 'middle' as const },
    }));
    const rows = summary.topCves.slice(0, 10).map((v) => [
        { text: v.cve, options: { fontSize: 9, bold: true } },
        { text: v.severity.slice(0, 4), options: { fontSize: 9, color: SEVERITY_HEX[v.severity] || MUTED, bold: true } },
        { text: String(v.cvss ?? '-'), options: { fontSize: 9 } },
        { text: v.impact, options: { fontSize: 9 } },
        { text: exploitTag(v), options: { fontSize: 9, color: v.exploited ? SEVERITY_HEX.Critical : MUTED } },
        { text: v.title, options: { fontSize: 8.5 } },
    ]);
    s5.addTable([headerRow, ...rows], {
        x: 0.5, y: 1.7, w: 12.3, colW: [1.7, 0.9, 0.9, 2.1, 1.7, 5.0],
        border: { type: 'solid', color: 'E2E8F0', pt: 0.5 },
        rowH: 0.4, valign: 'middle', autoPage: false,
    });

    // ---- Slide 6: Recommendations ----
    const s6 = pptx.addSlide({ masterName: 'BASE' });
    slideHeading(pptx, s6, 'Recommended Actions');
    const recs: string[] = [];
    if (t.exploited > 0) recs.push(`Prioritize the ${t.exploited} actively exploited CVE(s) for emergency patching within 24-48h.`);
    if (t.disclosed > 0) recs.push(`Review the ${t.disclosed} publicly disclosed CVE(s) — exploit details may already be circulating.`);
    recs.push(`Deploy ${t.critical} Critical and ${t.important} Important updates across affected fleets following change-control windows.`);
    if (t.exploitMoreLikely > 0) recs.push(`Track the ${t.exploitMoreLikely} CVE(s) flagged "Exploitation More Likely" by Microsoft for accelerated rollout.`);
    recs.push('Validate KB applicability per product family and confirm via the Microsoft Update Catalog links in the Excel/PDF export.');
    recs.push('Communicate scope and timelines to stakeholders using this consolidated summary.');
    s6.addText(
        recs.map((r) => ({ text: r, options: { bullet: { code: '2022' }, paraSpaceAfter: 12 } })),
        { x: 0.8, y: 1.8, w: 11.7, h: 4.8, fontSize: 16, color: INK, valign: 'top' }
    );

    await pptx.writeFile({ fileName: `${baseFilename(summary)}.pptx` });
}

const slideHeading = (pptx: PptxGenJS, slide: PptxGenJS.Slide, text: string) => {
    slide.addText(text, { x: 0.7, y: 0.5, w: 12, h: 0.7, fontSize: 26, bold: true, color: INK });
    slide.addShape(pptx.ShapeType.rect, { x: 0.72, y: 1.25, w: 1.6, h: 0.06, fill: { color: BRAND } });
};

// =============================================================================
//  Excel  (exceljs)
// =============================================================================

export async function exportPatchTuesdayExcel(summary: PatchTuesdaySummary): Promise<void> {
    const wb = new ExcelJS.Workbook();
    wb.creator = 'ThreatSumm4ry';
    wb.created = new Date();

    const headerFill = (ws: ExcelJS.Worksheet, row: number, lastCol: number, color = INK) => {
        const r = ws.getRow(row);
        for (let c = 1; c <= lastCol; c++) {
            const cell = r.getCell(c);
            cell.font = { bold: true, color: { argb: `FF${color === INK ? 'FFFFFF' : 'FFFFFF'}` } };
            cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: `FF${color}` } };
            cell.alignment = { vertical: 'middle' };
            cell.border = { bottom: { style: 'thin', color: { argb: 'FFCBD5E1' } } };
        }
        r.height = 20;
    };

    // ---- Overview ----
    const ov = wb.addWorksheet('Overview', { properties: { tabColor: { argb: 'FF2563EB' } } });
    ov.mergeCells('A1:D1');
    ov.getCell('A1').value = summary.title || 'Microsoft Security Updates';
    ov.getCell('A1').font = { bold: true, size: 18, color: { argb: 'FF0F172A' } };
    ov.mergeCells('A2:D2');
    ov.getCell('A2').value = `Release ${fmtDate(summary.initialReleaseDate)}  ·  Source: MSRC CVRF v3.0  ·  Generated ${new Date().toLocaleString('en-US')}`;
    ov.getCell('A2').font = { size: 10, color: { argb: 'FF64748B' } };
    ov.addRow([]);

    const t = summary.totals;
    const kpiStart = 4;
    ov.getRow(kpiStart).values = ['Metric', 'Value'];
    headerFill(ov, kpiStart, 2);
    const kpiRows: [string, number][] = [
        ['Total CVEs', t.total],
        ['Critical', t.critical],
        ['Important', t.important],
        ['Moderate', t.moderate],
        ['Low', t.low],
        ['Unrated / Edge (Chromium)', t.unknown],
        ['Actively Exploited', t.exploited],
        ['Publicly Disclosed', t.disclosed],
        ['Exploitation More Likely', t.exploitMoreLikely],
    ];
    kpiRows.forEach((r) => ov.addRow(r));
    ov.getColumn(1).width = 32;
    ov.getColumn(2).width = 14;
    ov.getColumn(3).width = 20;
    ov.getColumn(4).width = 20;

    // ---- Breakdown sheets ----
    const breakdown = (name: string, label: string, rows: { name: string; count: number }[]) => {
        const ws = wb.addWorksheet(name);
        ws.getRow(1).values = [label, 'CVEs', 'Share'];
        headerFill(ws, 1, 3, '2563EB');
        rows.forEach((r) => ws.addRow([r.name, r.count, t.total ? r.count / t.total : 0]));
        ws.getColumn(1).width = 34;
        ws.getColumn(2).width = 12;
        ws.getColumn(3).width = 12;
        ws.getColumn(3).numFmt = '0.0%';
        ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: 3 } };
    };
    breakdown('By Severity', 'Severity', [
        { name: 'Critical', count: t.critical },
        { name: 'Important', count: t.important },
        { name: 'Moderate', count: t.moderate },
        { name: 'Low', count: t.low },
        { name: 'Unrated / Edge', count: t.unknown },
    ]);
    breakdown('By Impact', 'Impact / Category', summary.byImpact);
    breakdown('By Product Family', 'Product Family', summary.byFamily);

    // ---- Full CVE catalog ----
    const cols = [
        { header: 'CVE', key: 'cve', width: 18 },
        { header: 'Severity', key: 'severity', width: 12 },
        { header: 'CVSS', key: 'cvss', width: 8 },
        { header: 'Impact', key: 'impact', width: 24 },
        { header: 'Product Family', key: 'family', width: 22 },
        { header: 'Exploited', key: 'exploited', width: 10 },
        { header: 'Publicly Disclosed', key: 'disclosed', width: 16 },
        { header: 'Exploitability', key: 'exploitability', width: 22 },
        { header: 'CWE', key: 'cwe', width: 34 },
        { header: 'Affected Products', key: 'productCount', width: 14 },
        { header: 'KB Articles', key: 'kbs', width: 30 },
        { header: 'Title', key: 'title', width: 52 },
        { header: 'Description', key: 'description', width: 70 },
        { header: 'CVSS Vector', key: 'vector', width: 40 },
    ];
    const cve = wb.addWorksheet('All CVEs', {
        properties: { tabColor: { argb: 'FF0F172A' } },
        views: [{ state: 'frozen', ySplit: 1 }],
    });
    cve.columns = cols;
    headerFill(cve, 1, cols.length);
    summary.vulnerabilities.forEach((v) => {
        const row = cve.addRow({
            cve: v.cve,
            severity: v.severity,
            cvss: v.cvss ?? '',
            impact: v.impact,
            family: v.family,
            exploited: v.exploited ? 'Yes' : 'No',
            disclosed: v.publiclyDisclosed ? 'Yes' : 'No',
            exploitability: v.exploitability,
            cwe: v.cwe,
            productCount: v.productCount,
            kbs: v.kbs.map((k) => `KB${k.kb}`).join(', '),
            title: v.title,
            description: v.description,
            vector: v.vector,
        });
        const sevCell = row.getCell('severity');
        const h = SEVERITY_HEX[v.severity];
        if (h) sevCell.font = { bold: true, color: { argb: `FF${h}` } };
        if (v.exploited) row.getCell('exploited').font = { bold: true, color: { argb: 'FFDC2626' } };
    });
    cve.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: cols.length } };

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
