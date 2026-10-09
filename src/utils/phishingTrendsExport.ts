// Exportação do dashboard de tendências de phishing, mesmo padrão EY do
// Enriquecimento/Patch Tuesday/SAP: cabeçalho preto, aba amarela, cabeçalho
// congelado, autofiltro, sem cor nas linhas de dado.
import type ExcelJS from "exceljs";
import { SHEET_TAB, scrubXml, styleHeaderRow, workbookMetadata } from "./deckTemplate";
import type { NewsArchiveRow } from "@/services/threatApi";

export interface ExcelWorkbookFactory {
    Workbook: new () => ExcelJS.Workbook;
}

const REPORT_COLUMNS = [
    { header: "Data", key: "date", width: 22 },
    { header: "Título", key: "title", width: 70 },
    { header: "Fonte", key: "source", width: 28 },
    { header: "Categoria", key: "category", width: 20 },
    { header: "Técnicas", key: "techniques", width: 46 },
    { header: "Link", key: "link", width: 52 },
];

const fmtDateTimePt = (iso: string): string => {
    const date = new Date(iso);
    return isNaN(date.getTime()) ? "" : date.toLocaleString("pt-BR");
};

export function buildPhishingTrendsWorkbook(
    rawRows: NewsArchiveRow[],
    ExcelLib: ExcelWorkbookFactory,
): ExcelJS.Workbook {
    const rows = scrubXml(rawRows);
    const wb = new ExcelLib.Workbook();
    workbookMetadata(
        wb,
        "Tendências de Phishing",
        new Date().toISOString(),
        "phishing, campanha, clickfix, aitm, vishing, smishing, threat intelligence",
    );

    const reports = wb.addWorksheet("Reports", {
        properties: SHEET_TAB,
        views: [{ state: "frozen", ySplit: 1 }],
    });
    reports.columns = REPORT_COLUMNS;
    styleHeaderRow(reports, 1, REPORT_COLUMNS.length);
    reports.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: REPORT_COLUMNS.length } };
    rows.forEach((row) => {
        reports.addRow({
            date: fmtDateTimePt(row.pubDate),
            title: row.title,
            source: row.source,
            category: row.primaryCategory || row.categories.join(", "),
            techniques: row.phishingTechniques.join(", "),
            link: row.link,
        });
    });

    // ---- Técnicas (contagem) ----
    const counts = new Map<string, number>();
    for (const row of rows) for (const technique of row.phishingTechniques) counts.set(technique, (counts.get(technique) || 0) + 1);
    const tecnicas = wb.addWorksheet("Técnicas", { properties: SHEET_TAB });
    tecnicas.columns = [
        { header: "Técnica", key: "technique", width: 36 },
        { header: "Reports", key: "count", width: 14 },
    ];
    styleHeaderRow(tecnicas, 1, 2);
    [...counts.entries()].sort((a, b) => b[1] - a[1]).forEach(([technique, count]) => {
        tecnicas.addRow({ technique, count });
    });

    return wb;
}

export const phishingTrendsExcelFilename = (): string =>
    `Tendencias-de-Phishing-${new Date().toISOString().slice(0, 10)}.xlsx`;

const triggerDownload = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
};

export async function exportPhishingTrendsExcel(rows: NewsArchiveRow[]): Promise<void> {
    const { default: ExcelLib } = await import("exceljs");
    const wb = buildPhishingTrendsWorkbook(rows, ExcelLib as ExcelWorkbookFactory);
    const buffer = await wb.xlsx.writeBuffer();
    triggerDownload(
        new Blob([buffer], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }),
        phishingTrendsExcelFilename(),
    );
}
