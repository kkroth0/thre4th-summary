import type ExcelJS from 'exceljs';
import { SHEET_TAB, scrubXml, styleHeaderRow, workbookMetadata } from './deckTemplate';
import type { BulkRow } from './bulkEnrichment';
import { detectAnalyzerQueryType } from './iocExtract';
import { addOtPatchClientSheets } from './otPatchClientWorkbook';
import type { OtReportContext } from './otPatchIntelligence';
import { styleEnrichmentDetails } from './enrichmentPresentation';
import { analyzeBulkRows, type BulkAnalysis } from './bulkAnalysis';
import { addBulkDashboard } from './bulkDashboard';
import { ANALYTICAL_COLUMNS, styleAnalyticalSheet } from './bulkAnalyticalSheets';
import { createUnifiedBulkRegistry, projectUnifiedBulkRow, UNIFIED_INDICATOR_COLUMNS, UNIFIED_PUBLICATION_COLUMNS, UNIFIED_MENTION_COLUMNS, UNIFIED_RELATION_COLUMNS, UNIFIED_TECHNIQUE_COLUMNS } from './bulkUnifiedReport';

type RecordRow = Record<string, unknown>;
type Column = [string, string, number];
type ExcelFactory = { Workbook: new () => ExcelJS.Workbook };
const bulkSnapshots = new WeakMap<ExcelJS.Workbook,BulkAnalysis>();
export const bulkWorkbookSnapshot = (workbook:ExcelJS.Workbook) => bulkSnapshots.get(workbook);
export interface NewsExcelPayload { dataset: string; range: { from: string; to: string }; rows: RecordRow[]; generatedAt?: string; report?: OtReportContext }
export const valueText = (value: unknown): string => value == null ? '' : typeof value === 'object'
  // JSON Unicode escapes preserve astral characters through ExcelJS's UTF-8
  // serialization chunks. JSON.parse restores the original provider payload.
  ? Array.isArray(value) && value.every(item => typeof item === 'string') ? value.join(' | ') : JSON.stringify(value).replace(/[\uD800-\uDFFF]/g, unit => '\\u' + unit.charCodeAt(0).toString(16).padStart(4, '0'))
  : String(value);

function tables(wb: ExcelJS.Workbook, omitEmpty = false) {
  let overflow: ExcelJS.Worksheet | undefined;
  let sequence = 0;
  return (name: string, preferred: Column[], rows: RecordRow[], headerOffset = 0) => {
    if (rows.length > 1048575 - headerOffset) throw Error('Limite de registros por aba do Excel atingido. Reduza o período.');
    const keys = new Set(preferred.map(([key]) => key));
    const columns = [...preferred];
    for (const row of rows) for (const key of Object.keys(row)) if (!keys.has(key)) { keys.add(key); columns.push([key, key, 45]); }
    const sheet = wb.addWorksheet(name, { properties: SHEET_TAB, views: [{ state: 'frozen', ySplit: 1 }] });
    sheet.columns = columns.map(([key, header, width]) => ({ key, header, width }));
    styleHeaderRow(sheet, 1, columns.length);
    sheet.autoFilter = { from: { row: 1, column: 1 }, to: { row: rows.length + 1, column: columns.length } };
    for (const record of rows) {
      const values = columns.map(([key]) => {
        const value = record[key];
        // Sparse rows keep large bulk exports from allocating a styled cell
        // for every absent vendor field. Numeric zero is still a real value.
        if (value == null || value === '') return omitEmpty ? undefined : null;
        if (typeof value === 'number' && Number.isFinite(value)) return value;
        if (typeof value === 'boolean') return value;
        const text = scrubXml(valueText(value));
        if (text.length <= 32767) return text;
        // Excel cells cannot hold arbitrarily large provider responses. Preserve
        // every character in ordered parts instead of silently truncating JSON.
        if (!overflow) {
          overflow = wb.addWorksheet('Dados extensos', { properties: SHEET_TAB, views: [{ state: 'frozen', ySplit: 1 }] });
          overflow.columns = [{ header: 'Referência', width: 18 }, { header: 'Aba', width: 24 }, { header: 'Linha', width: 12 }, { header: 'Campo', width: 30 }, { header: 'Parte', width: 12 }, { header: 'Conteúdo', width: 100 }];
          styleHeaderRow(overflow, 1, 6);
        }
        const reference = `EXT-${++sequence}`;
        for (let start = 0, part = 1; start < text.length; part++) {
          let end = Math.min(text.length, start + 30000);
          if (end < text.length && /[\uD800-\uDBFF]/.test(text[end - 1])) end--;
          if (overflow.rowCount >= 1048576) throw Error('Limite do Excel atingido nos dados extensos. Reduza o período.');
          overflow.addRow([reference, name, sheet.rowCount + 1 + headerOffset, key, part, text.slice(start, end)]);
          start = end;
        }
        return `${reference} — conteúdo completo na aba Dados extensos`;
      });
      // Strings are written as string cells, including leading '=' or '@'.
      // Never pass third-party objects to ExcelJS as cell values/formulas.
      sheet.addRow(values).alignment = { vertical: 'top', wrapText: true };
    }
    return sheet;
  };
}

const common: Column[] = [['title', 'Publicação', 65], ['source', 'Fonte', 26], ['url', 'Referência', 65], ['date', 'Data e hora (ISO)', 28], ['dateBasis', 'Base da data', 24], ['storyId', 'ID do evento', 30], ['categories', 'Categorias', 30], ['cves', 'CVEs', 35], ['actors', 'Atores citados', 35], ['malware', 'Malware', 35]];

export function buildNewsExcelWorkbook(payload: NewsExcelPayload, ExcelLib: ExcelFactory) {
  if (!Array.isArray(payload.rows)) throw Error('Resposta de exportação inválida.');
  const wb = new ExcelLib.Workbook();
  const patchReport = ['ot-patches', 'ai-patches'].includes(payload.dataset), rawName = payload.dataset === 'ai-patches' ? 'AI Tools Patch Day' : 'OT ICS Patch Day';
  workbookMetadata(wb, patchReport ? (payload.dataset === 'ai-patches' ? 'AI Tools Patch Day' : 'OT/ICS Patch Day') : 'Notícias e IOCs', patchReport ? payload.range.from : payload.generatedAt || new Date().toISOString(), 'IOC, fontes, evidências');
  const table = tables(wb), isIocs = payload.dataset === 'iocs';
  if (patchReport) {
    addOtPatchClientSheets(wb, payload);
    table(rawName, [['id', 'Aviso', 25], ['title', 'Título', 65], ['vendors', payload.dataset === 'ai-patches' ? 'Ferramentas' : 'Fabricantes', 30], ['products', 'Produtos e versões da fonte', 80], ['patchLabel', 'Situação da correção', 28], ['cvss', 'CVSS', 12], ['kev', 'KEV', 12], ['cves', 'CVEs', 35], ['cveSignals', 'Sinais do catálogo de CVEs', 60], ['published', 'Publicação inicial', 28], ['updated', 'Última revisão', 28], ['source', 'Fonte', 20], ['url', 'Aviso oficial', 65], ['remediations', 'Correções e mitigações', 100], ['matches', 'Correspondências do catálogo (não confirma exposição)', 60], ['references', 'Referências', 80], ['stale', 'Cache anterior', 15], ['sourceCoverage', 'Estado e cobertura das fontes na exportação', 80]], payload.rows);
    const raw = wb.getWorksheet(rawName)!;
    raw.views = [{ state: 'frozen', ySplit: 1, xSplit: 1, showGridLines: false }];
    raw.eachRow((row, i) => { row.eachCell(cell => { cell.font = { name: 'Calibri', size: 11, color: { argb: i === 1 ? 'FFFFFF' : '14283F' }, bold: i === 1 }; cell.alignment = { vertical: 'top', wrapText: true }; if (i === 1) cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: '14283F' } }; }); if (i === 1) row.height = 34; });
    return wb;
  }
  table(isIocs ? 'IOCs' : 'Publicações', isIocs
    ? [['type', 'Tipo', 14], ['indicator', 'Indicador', 70], ...common]
    : [...common, ['ips', 'IPs', 42], ['domains', 'Domínios', 50], ['hashes', 'Hashes', 70], ['urls', 'URLs', 70]], payload.rows);
  table('Resumo', [['key', 'Campo', 40], ['value', 'Valor', 90]], [
    { key: 'Conteúdo', value: isIocs ? 'IOCs — uma linha por evidência de origem' : 'Publicações' },
    { key: 'Início do período (ISO)', value: payload.range.from }, { key: 'Final do período (ISO)', value: payload.range.to },
    { key: 'Registros exportados', value: payload.rows.length },
    ...(isIocs ? [{ key: 'Indicadores únicos', value: new Set(payload.rows.map(row => row.indicator)).size }] : []),
    { key: 'Gerado em (ISO)', value: payload.generatedAt || new Date().toISOString() },
    { key: 'Escopo', value: 'Todas as páginas do período autorizado, conforme as fontes e permissões da conta.' },
  ]);
  return wb;
}

export function buildBulkExcelWorkbook(rows: BulkRow[], ExcelLib: ExcelFactory, snapshot?: BulkAnalysis) {
  if (!Array.isArray(rows)) throw Error('Lote de exportação inválido.');
  const registry = createUnifiedBulkRegistry();
  const projections = (snapshot?.analyses || analyzeBulkRows(rows).analyses).map(analysis => registry.add(projectUnifiedBulkRow(analysis.row, analysis)));
  const report = registry.finish(), wb = new ExcelLib.Workbook();
  wb.addWorksheet('Dashboard');
  workbookMetadata(wb, 'Análise unificada de IOCs', new Date().toISOString(), 'Indicadores, atores, malware e publicações');
  addBulkDashboard(wb, report.analysis, new Date().toISOString(), report);
  const table = tables(wb, true);
  const add = (name:string, columns:Column[], entries:RecordRow[]) => {
    const ws = table(name,columns,entries);
    ws.views = [{state:'frozen',xSplit:1,ySplit:1,showGridLines:false,zoomScale:85}];
    ws.properties.tabColor = {argb:'FF087F8C'};
    ws.eachRow((row,n) => {
      row.height=n===1?42:42;
      row.font={name:'Arial',size:10,bold:n===1,color:{argb:n===1?'FFFFFFFF':'FF202936'}};
      row.alignment={vertical:'top',wrapText:true};
      if(n===1||n%2===0)row.fill={type:'pattern',pattern:'solid',fgColor:{argb:n===1?'FF202936':'FFF2F5F9'}};
      if(n>1)for(const [key] of columns){const cell=row.getCell(key);if(key==='link'&&typeof cell.value==='string'&&/^https?:\/\//.test(cell.value)){cell.value={text:cell.value,hyperlink:cell.value};cell.font={name:'Arial',size:10,color:{argb:'FF0563C1'},underline:true};}else if(['date','firstMention','lastMention','created'].includes(key)&&typeof cell.value==='string'&&Number.isFinite(Date.parse(cell.value))){cell.value=new Date(Date.parse(cell.value)-3*3600000);cell.numFmt='dd/mm/yyyy hh:mm';}}
    });
  };
  add('Indicadores',UNIFIED_INDICATOR_COLUMNS,projections.map(item=>item.record));
  add('Publicações',UNIFIED_PUBLICATION_COLUMNS,report.publications);
  add('Menções',UNIFIED_MENTION_COLUMNS,projections.flatMap(item=>item.mentions));
  add('Relações',UNIFIED_RELATION_COLUMNS,projections.flatMap(item=>item.relations));
  add('Técnicas ATT&CK',UNIFIED_TECHNIQUE_COLUMNS,report.techniques);
  bulkSnapshots.set(wb,report.analysis);
  return wb;
}
