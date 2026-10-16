import type ExcelJS from 'exceljs';
import { SHEET_TAB, scrubXml, styleHeaderRow, workbookMetadata } from './deckTemplate';
import { bulkField, type BulkRow } from './bulkEnrichment';
import { detectAnalyzerQueryType } from './iocExtract';
import { addOtPatchClientSheets } from './otPatchClientWorkbook';
import type { OtReportContext } from './otPatchIntelligence';

type RecordRow = Record<string, unknown>;
type Column = [string, string, number];
type ExcelFactory = { Workbook: new () => ExcelJS.Workbook };
export interface NewsExcelPayload { dataset: string; range: { from: string; to: string }; rows: RecordRow[]; generatedAt?: string; report?: OtReportContext }
const valueText = (value: unknown): string => value == null ? '' : typeof value === 'object'
  ? Array.isArray(value) && value.every(item => typeof item === 'string') ? value.join(' | ') : JSON.stringify(value)
  : String(value);

function tables(wb: ExcelJS.Workbook) {
  let overflow: ExcelJS.Worksheet | undefined;
  let sequence = 0;
  return (name: string, preferred: Column[], rows: RecordRow[]) => {
    if (rows.length > 1048575) throw Error('Limite do Excel: 1.048.575 registros por aba. Reduza o período.');
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
          overflow.addRow([reference, name, sheet.rowCount + 1, key, part, text.slice(start, end)]);
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

export function buildBulkExcelWorkbook(rows: BulkRow[], ExcelLib: ExcelFactory) {
  const wb = new ExcelLib.Workbook();
  workbookMetadata(wb, 'Enriquecimento em lote', new Date().toISOString(), 'IOC, enriquecimento, fontes, evidências');
  const table = tables(wb);
  table('Indicadores', [['indicator', 'Indicador', 70], ['type', 'Tipo', 14], ['state', 'Estado da consulta', 20], ['verdict', 'Veredito', 20], ['score', 'Score', 12], ['detections', 'Detecções', 14], ['country', 'País', 14], ['asn', 'ASN', 20], ['organization', 'Organização', 35], ['completedAt', 'Concluído em (ISO)', 28], ['sources', 'Fontes', 50], ['error', 'Erro', 55], ['contextErrors', 'Falhas de contexto', 70], ['result', 'Resultado completo (JSON)', 90]], rows.map(row => ({
    indicator: row.query, type: detectAnalyzerQueryType(row.query), state: row.state, verdict: row.result?.threatLevel || 'unknown', score: row.result?.overallScore ?? '', detections: row.result?.detections ?? '',
    country: bulkField(row, ['Country']).value, asn: bulkField(row, ['ASN', 'AS']).value, organization: bulkField(row, ['Organization', 'ISP']).value,
    completedAt: row.completedAt, sources: row.result?.vendorData.map(vendor => vendor.name) || [], error: row.error, contextErrors: row.context?.errors || [], result: row.result || null,
  })));
  table('Fontes', [['indicator', 'Indicador', 70], ['source', 'Fonte', 24], ['state', 'Estado da fonte', 40], ['reference', 'Referência', 65], ['data', 'Dados normalizados (JSON)', 90], ['raw', 'Resposta completa (JSON)', 90], ['timeline', 'Timeline (JSON)', 90], ['quota', 'Cota observada (JSON)', 55]], rows.flatMap(row => (row.result?.vendorData || []).map(vendor => ({
    indicator: row.query, source: vendor.name, state: vendor.error || (vendor.isLoading ? 'pending' : 'ok'), reference: vendor.link, data: vendor.data, raw: vendor.rawPayload ?? null, timeline: vendor.timeline || [], quota: vendor.quota || null,
  }))));
  table('Publicações', [['indicator', 'Indicador', 70], ...common], rows.flatMap(row => (row.context?.publications || []).map(publication => ({ ...publication, indicator: row.query, url: publication.link, date: publication.pubDate }))));
  table('Evidências', [['indicator', 'Indicador', 70], ['provider', 'Provedor', 24], ['source', 'Fonte', 24], ['title', 'Título', 65], ['link', 'Referência', 65], ['published', 'Publicação (ISO)', 28], ['collectedAt', 'Coleta (ISO)', 28], ['confidence', 'Confiança', 14], ['reputation', 'Reputação (JSON)', 70], ['entities', 'Entidades e relações (JSON)', 90]], rows.flatMap(row => (row.context?.evidence || []).map(evidence => ({ ...evidence, indicator: row.query }))));
  table('Resumo', [['key', 'Campo', 40], ['value', 'Valor', 90]], [{ key: 'Indicadores exportados', value: rows.length }, { key: 'Gerado em (ISO)', value: new Date().toISOString() }, { key: 'Escopo', value: 'Todas as linhas do filtro atual, incluindo parciais e falhas. Exportar não faz novas consultas às fontes.' }]);
  return wb;
}
