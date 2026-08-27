// Planilha do Enriquecimento de Indicadores, no mesmo padrão EY do Patch
// Tuesday e do SAP: cabeçalho preto com Calibri 14 amarelo, aba amarela, linha
// de cabeçalho congelada, autofiltro e nenhuma cor nas linhas de dados — quem
// recebe filtra por coluna em vez de caçar cor.
//
// A construção do workbook é pura (a fábrica do exceljs entra por parâmetro),
// então o teste monta a planilha sem browser; só o download toca o DOM.
import type ExcelJS from "exceljs";
import {
    LINK_FONT, SHEET_HEADER, SHEET_TAB, scrubXml, styleHeaderRow, workbookMetadata,
} from "./deckTemplate";
import type { EnrichmentReport, NamedCount } from "./enrichment";

export interface ExcelWorkbookFactory {
    Workbook: new () => ExcelJS.Workbook;
}

const INDICATOR_COLUMNS = [
    { header: "Indicador", key: "indicator", width: 46 },
    { header: "Tipo", key: "type", width: 12 },
    { header: "Veredito", key: "verdict", width: 15 },
    { header: "Grupo / Ator", key: "actors", width: 30 },
    { header: "Campanha", key: "campaign", width: 38 },
    { header: "Família de Malware", key: "families", width: 30 },
    { header: "Confiança da Atribuição", key: "confidence", width: 22 },
    { header: "Base da Atribuição", key: "basis", width: 72 },
    { header: "Técnicas ATT&CK", key: "attackIds", width: 24 },
    { header: "Detecções VirusTotal", key: "vtDetections", width: 20 },
    { header: "Score AbuseIPDB", key: "abuseScore", width: 17 },
    { header: "Pulses OTX", key: "otxPulses", width: 12 },
    { header: "Tags", key: "tags", width: 40 },
    { header: "País", key: "country", width: 10 },
    { header: "ASN", key: "asn", width: 14 },
    { header: "Primeira Ocorrência", key: "firstSeen", width: 22 },
    { header: "Última Ocorrência", key: "lastSeen", width: 22 },
    { header: "Fontes Consultadas", key: "sources", width: 52 },
    { header: "Bases sem Resposta", key: "unanswered", width: 30 },
    { header: "Mencionado Em", key: "mentions", width: 76 },
];

const EVIDENCE_COLUMNS = [
    { header: "Indicador", key: "indicator", width: 46 },
    { header: "Fonte", key: "source", width: 20 },
    { header: "Tipo de Evidência", key: "kind", width: 22 },
    { header: "Título", key: "title", width: 52 },
    { header: "Detalhe", key: "detail", width: 88 },
    { header: "Data", key: "date", width: 24 },
    { header: "Link", key: "link", width: 18 },
];

const fmtDateTimePt = (iso: string): string => {
    const date = new Date(iso);
    return isNaN(date.getTime()) ? "" : date.toLocaleString("pt-BR");
};

const addTable = (
    ws: ExcelJS.Worksheet,
    columns: { header: string; key: string; width: number }[],
): void => {
    ws.columns = columns;
    styleHeaderRow(ws, 1, columns.length);
    ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: columns.length } };
};

export function buildEnrichmentWorkbook(
    rawReport: EnrichmentReport,
    ExcelLib: ExcelWorkbookFactory,
): ExcelJS.Workbook {
    // Comentário de denúncia da AbuseIPDB e nome de pulse são texto que
    // terceiros escreveram: um controle C0 no meio faz o Excel declarar o
    // arquivo corrompido e oferecer reparo.
    const report = scrubXml(rawReport);
    const wb = new ExcelLib.Workbook();
    workbookMetadata(
        wb,
        "Enriquecimento de Indicadores",
        report.generatedAt,
        "IOC, enriquecimento, atribuição, campanha, grupo, threat intelligence",
    );

    // ---- Indicadores ----
    const indicadores = wb.addWorksheet("Indicadores", {
        properties: SHEET_TAB,
        views: [{ state: "frozen", ySplit: 1 }],
    });
    addTable(indicadores, INDICATOR_COLUMNS);
    report.indicators.forEach((row) => {
        indicadores.addRow({ ...row, otxPulses: row.otxPulses || "" });
    });

    // ---- Evidências ----
    const evidencias = wb.addWorksheet("Evidências", {
        properties: SHEET_TAB,
        views: [{ state: "frozen", ySplit: 1 }],
    });
    addTable(evidencias, EVIDENCE_COLUMNS);
    report.evidence.forEach((row) => {
        const added = evidencias.addRow({
            ...row,
            link: row.link ? { text: "Abrir", hyperlink: row.link } : "",
        });
        if (row.link) added.getCell("link").font = LINK_FONT;
    });

    // ---- Sumário ----
    const sumario = wb.addWorksheet("Sumário", { properties: SHEET_TAB });
    sumario.mergeCells("A1:B1");
    sumario.getCell("A1").value = "Enriquecimento de Indicadores";
    sumario.getCell("A1").font = { name: "Calibri", bold: true, size: 12, color: { argb: `FF${SHEET_HEADER}` } };
    sumario.mergeCells("A2:B2");
    sumario.getCell("A2").value =
        `${report.indicators.length} indicadores · ${report.evidence.length} evidências · Gerado em ${fmtDateTimePt(report.generatedAt)}`;
    sumario.getCell("A2").font = { name: "Calibri", size: 10 };
    sumario.getColumn(1).width = 46;
    sumario.getColumn(2).width = 14;

    let row = 4;
    const block = (label: string, rows: NamedCount[]) => {
        sumario.getRow(row).values = [label, "Indicadores"];
        styleHeaderRow(sumario, row, 2);
        row += 1;
        // Bloco sem dado precisa dizer isso, senão o leitor acha que a seção
        // ficou faltando na geração.
        const body = rows.length ? rows : [{ name: "Nenhum", count: 0 }];
        body.forEach((entry) => {
            sumario.getRow(row).values = [entry.name, entry.count];
            row += 1;
        });
        row += 1;
    };
    block("Grupo / Ator", report.byActor);
    block("Família de Malware", report.byFamily);
    block("Veredito", report.byVerdict);
    block("País", report.byCountry);

    return wb;
}

export const enrichmentExcelFilename = (report: EnrichmentReport): string =>
    `Enriquecimento-de-Indicadores-${(report.generatedAt || "").slice(0, 10)}.xlsx`;

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

export async function exportEnrichmentExcel(report: EnrichmentReport): Promise<void> {
    const { default: ExcelLib } = await import("exceljs");
    const wb = buildEnrichmentWorkbook(report, ExcelLib as ExcelWorkbookFactory);
    const buffer = await wb.xlsx.writeBuffer();
    triggerDownload(
        new Blob([buffer], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }),
        enrichmentExcelFilename(report),
    );
}
