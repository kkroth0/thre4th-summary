// Download do JSON do boletim, e o nome de arquivo que os três formatos usam.
//
// Nem o PPTX nem o PDF são montados aqui. O deck do boletim é o template SRR, e
// template só se preenche com python-pptx (pptxgenjs desenha do zero, não abre
// um .pptx existente); o PDF é esse mesmo deck convertido. Os dois vêm prontos
// do worker na VPS e o site só baixa (threatApi.downloadBoletimDeck) — montar
// aqui produziria um documento parecido, nunca o da casa.
import type ExcelJS from 'exceljs';
import type { BoletimJob } from '@/services/threatApi';
import { SHEET_HEADER, SHEET_TAB, LINK_FONT, styleHeaderRow, workbookMetadata, fmtLongDatePt } from './deckTemplate';

// Nome da casa, o MESMO que o motor gera (url_report.srr_filename): título
// legível, com acentos e espaços, sem os caracteres que o Windows recusa em nome
// de arquivo. Os dois lados precisam bater — o analista baixa o JSON aqui e o
// deck vem do motor, e os dois sentam lado a lado na mesma pasta.
const SRR_PREFIX = 'SRR - Surface Risk Report';

export const boletimFilename = (job: BoletimJob) => {
    const title = (job.json?.titulo || job.title || job.url || '').trim();
    const name = `${SRR_PREFIX} - ${title}`
        .replace(/^[\s-]+|[\s-]+$/g, '')          // título vazio deixa só o prefixo
        // eslint-disable-next-line no-control-regex
        .replace(/[<>:"/\\|?*\u0000-\u001f]/g, '')
        .replace(/\s+/g, ' ')
        .trim().replace(/[.\s]+$/, '')            // Windows recusa ponto/espaço no fim
        .slice(0, 120)
        .trim().replace(/[.\s]+$/, '');
    return name || SRR_PREFIX;
};

export function exportBoletimJSON(job: BoletimJob): void {
    const blob = new Blob([JSON.stringify(job.json, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${boletimFilename(job)}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

// ---- IOCs (Excel) -----------------------------------------------------------
// O deck de campanha mostra no máximo 6 IOCs (o resto ficaria pequeno demais no
// slide); o boletim de vulnerabilidade nem tem slide de IOCs. A lista inteira
// já chega no JSON — este workbook é só pra compartilhar sem obrigar quem
// recebe a abrir o JSON bruto. Mesmo padrão de planilha do Patch Tuesday e do
// SAP: cabeçalho preto/amarelo, painel congelado, filtro, sem cor nos dados.
export const canExportBoletimIocs = (job: BoletimJob | null): boolean => Boolean(job?.json?.iocs?.length);

export const boletimIocsExcelFilename = (job: BoletimJob) => `${boletimFilename(job)} - IOCs.xlsx`;

export interface ExcelWorkbookFactory {
    Workbook: new () => ExcelJS.Workbook;
}

const isLikelyUrl = (value: string) => /^https?:\/\//i.test(value.trim());

export function buildBoletimIocsWorkbook(job: BoletimJob, ExcelLib: ExcelWorkbookFactory): ExcelJS.Workbook {
    const report = job.json;
    const iocs = report?.iocs || [];
    const sources = report?.iocs_fontes || [];
    const title = report?.titulo || job.title || job.url || 'Boletim';
    const generatedAt = report?.generated_at || job.updatedAt || job.createdAt || null;

    const wb = new ExcelLib.Workbook();
    workbookMetadata(wb, 'Indicadores de Comprometimento', generatedAt, 'IOC, threat intelligence, SRR');
    wb.description = `Indicadores de comprometimento — ${title}`;

    // ---- Resumo ----
    const resumo = wb.addWorksheet('Resumo', { properties: SHEET_TAB });
    resumo.mergeCells('A1:B1');
    resumo.getCell('A1').value = title;
    resumo.getCell('A1').font = { name: 'Calibri', bold: true, size: 12, color: { argb: `FF${SHEET_HEADER}` } };
    resumo.mergeCells('A2:B2');
    resumo.getCell('A2').value = `TLP: ${report?.tlp || 'Não informada'} · Gerado em ${generatedAt ? fmtLongDatePt(generatedAt) : new Date().toLocaleString('pt-BR')}`;
    resumo.getCell('A2').font = { name: 'Calibri', size: 10 };
    resumo.addRow([]);

    const byTipo = new Map<string, number>();
    iocs.forEach((i) => {
        const tipo = i.tipo || 'Não informado';
        byTipo.set(tipo, (byTipo.get(tipo) || 0) + 1);
    });

    resumo.getRow(4).values = ['Campo', 'Valor'];
    styleHeaderRow(resumo, 4, 2);
    ([
        ['Ator/Campanha', report?.ator?.threat_actor || 'Não informado'],
        ['Total de indicadores', iocs.length],
        ['Fontes externas listadas', sources.length],
        ...[...byTipo.entries()].map(([tipo, count]) => [`Indicadores — ${tipo}`, count]),
    ] as [string, string | number][]).forEach((row) => resumo.addRow(row));
    resumo.getColumn(1).width = 34;
    resumo.getColumn(2).width = 50;

    // ---- IOCs ----
    const sheet = wb.addWorksheet('IOCs', { properties: SHEET_TAB, views: [{ state: 'frozen', ySplit: 1 }] });
    sheet.columns = [
        { header: 'Categoria', key: 'categoria', width: 24 },
        { header: 'Tipo', key: 'tipo', width: 18 },
        { header: 'Indicador', key: 'valor', width: 60 },
    ];
    styleHeaderRow(sheet, 1, sheet.columns.length);
    iocs.forEach((i) => {
        const valor = i.valor || '';
        const row = sheet.addRow({ categoria: i.categoria || 'Não informada', tipo: i.tipo || 'Não informado', valor });
        if (isLikelyUrl(valor)) {
            row.getCell('valor').value = { text: valor, hyperlink: valor };
            row.getCell('valor').font = { ...LINK_FONT };
        }
    });
    sheet.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: sheet.columns.length } };

    // ---- Fontes ----
    // Repositórios/gists externos de onde os indicadores foram coletados — nem
    // todo boletim tem, então a aba só aparece quando há algo pra listar.
    if (sources.length > 0) {
        const fontes = wb.addWorksheet('Fontes', { properties: SHEET_TAB, views: [{ state: 'frozen', ySplit: 1 }] });
        fontes.columns = [{ header: 'Fonte externa dos indicadores', key: 'url', width: 90 }];
        styleHeaderRow(fontes, 1, 1);
        sources.forEach((sourceUrl) => {
            const row = fontes.addRow({ url: sourceUrl });
            row.getCell('url').value = { text: sourceUrl, hyperlink: sourceUrl };
            row.getCell('url').font = { ...LINK_FONT };
        });
    }

    return wb;
}

export async function exportBoletimIocsExcel(job: BoletimJob): Promise<void> {
    const { default: ExcelLib } = await import('exceljs');
    const wb = buildBoletimIocsWorkbook(job, ExcelLib);
    const buf = await wb.xlsx.writeBuffer();
    const blob = new Blob([buf], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = boletimIocsExcelFilename(job);
    a.click();
    URL.revokeObjectURL(url);
}
