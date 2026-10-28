import type ExcelJS from 'exceljs';

export interface EnrichmentOverview {
  total: number; completed: number; partial: number; pending: number;
  malicious: number; suspicious: number; related: number; evidence: number;
  actors: { name: string; count: number }[];
  coverage: { name: string; count: number }[];
  generatedAt: string;
}
const C = { ink: 'FF2E2E38', yellow: 'FFFFE600', muted: 'FF666675', pale: 'FFF6F6FA', white: 'FFFFFFFF' };
function text(ws: ExcelJS.Worksheet, row: number, from: number, to: number, value: string | number, dark = false, size = 11) {
  ws.mergeCells(row, from, row, to);
  const cell = ws.getCell(row, from); cell.value = value;
  cell.font = { name: 'Calibri', size, bold: dark || size > 14, color: { argb: dark ? C.white : C.ink } };
  cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: dark ? C.ink : C.pale } };
  cell.alignment = { horizontal: 'left', vertical: 'middle', wrapText: true, indent: 1 };
  if (typeof value === 'number') cell.numFmt = '#,##0';
  return cell;
}
function page(wb: ExcelJS.Workbook, name: string, title: string, date: string) {
  const ws = wb.getWorksheet(name) || wb.addWorksheet(name);
  ws.views = [{ showGridLines: false, zoomScale: 90 }];
  ws.properties.tabColor = { argb: C.yellow };
  ws.pageSetup = { paperSize: 9, orientation: 'landscape', fitToPage: true, fitToWidth: 1, fitToHeight: 1, printArea: 'A1:N38' };
  for (let i = 1; i <= 14; i++) ws.getColumn(i).width = i === 1 || i === 14 ? 3 : 11;
  for (let i = 1; i <= 38; i++) ws.getRow(i).height = 21;
  text(ws, 2, 2, 13, title, true, 22); ws.getRow(2).height = 42;
  text(ws, 3, 2, 13, 'ThreatSumm4ry · ' + new Date(date).toLocaleString('pt-BR'), true);
  ws.headerFooter.oddFooter = '&LThreatSumm4ry · Inteligência de indicadores&R&P / &N';
  return ws;
}

/** Presentation is derived from the exported rows, never from another filter or API call. */
export function addEnrichmentPresentation(wb: ExcelJS.Workbook, data: EnrichmentOverview) {
  const dashboard = page(wb, 'Dashboard', 'Panorama do enriquecimento', data.generatedAt);
  const metrics = [[data.total, 'INDICADORES'], [data.malicious + data.suspicious, 'COM SINAL DE RISCO'], [data.related, 'COM CONTEXTO DE ATORES'], [data.partial + data.pending, 'COBERTURA INCOMPLETA']] as const;
  metrics.forEach(([n, label], i) => {
    const x = 2 + i * 3;
    text(dashboard, 5, x, x + 2, n, false, 28).alignment = { horizontal: 'center', vertical: 'middle' }; dashboard.getRow(5).height = 42;
    text(dashboard, 6, x, x + 2, label, true, 9); dashboard.getRow(6).height = 30;
  });
  const ranking = (start: number, title: string, entries: { name: string; count: number }[]) => {
    text(dashboard, start, 2, 13, title, true, 12);
    const sorted = [...entries].sort((a, b) => b.count - a.count || a.name.localeCompare(b.name)).slice(0, 7);
    const max = Math.max(1, ...sorted.map(item => item.count));
    if (!sorted.length) text(dashboard, start + 1, 2, 13, 'Nenhum vínculo disponível nas linhas exportadas.');
    sorted.forEach((item, i) => {
      text(dashboard, start + 1 + i, 2, 6, item.name);
      text(dashboard, start + 1 + i, 7, 7, item.count);
      for (let c = 8; c <= 13; c++) {
        const cell = dashboard.getCell(start + 1 + i, c); cell.value = null;
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: c < 8 + Math.ceil(item.count / max * 6) ? C.yellow : C.pale } };
      }
      dashboard.getRow(start + 1 + i).height = 28;
    });
  };
  ranking(9, 'ATORES CITADOS · IOCs únicos com vínculo contextual', data.actors);
  ranking(19, 'COBERTURA POR FONTE · IOCs com resposta concluída', data.coverage);
  text(dashboard, 29, 2, 13, 'Como interpretar', true, 12);
  text(dashboard, 30, 2, 13, 'Uma menção conjunta não comprova autoria. Veredito, confiança da relação e cobertura são informações distintas. Fontes com erro ou pendentes não equivalem a resultado negativo.'); dashboard.getRow(30).height = 48;
  text(dashboard, 33, 2, 13, `${data.completed} concluídos · ${data.partial} parciais/falhas · ${data.pending} pendentes · ${data.evidence} evidências. Exportação sem novas chamadas externas.`); dashboard.getRow(33).height = 34;

  const executive = page(wb, 'Resumo executivo', 'Leitura para o analista', data.generatedAt);
  executive.pageSetup.printArea = 'A1:N27';
  const paragraphs = [
    ['Escopo e cobertura', `O arquivo reúne ${data.total} indicadores do recorte exportado. ${data.completed} têm processamento concluído, ${data.partial} apresentam falhas ou cobertura parcial e ${data.pending} ainda aguardam conclusão. As respostas disponíveis e suas origens acompanham o detalhamento.`],
    ['Sinais de risco', `${data.malicious} indicadores receberam veredito malicioso e ${data.suspicious} suspeito nas fontes consultadas. Esses sinais ajudam a ordenar a investigação; ausência de detecção não comprova que um indicador seja benigno.`],
    ['Relações e contexto', `${data.related} indicadores possuem contexto de atores, apoiado em ${data.evidence} evidências exportadas. Uma entidade citada no mesmo relatório pode ser apenas contextual. O detalhamento mantém as evidências e as referências disponíveis para conferência.`],
    ['Decisão operacional', 'Antes de qualquer bloqueio de IP, domínio, URL ou hash, é necessário validar a evidência, a recência e o possível impacto em ativos, serviços legítimos e infraestrutura compartilhada. User-Agents genéricos e nomes de arquivos não sustentam bloqueio isoladamente.'],
  ];
  paragraphs.forEach(([title, body], i) => { const row = 6 + i * 5; text(executive, row, 2, 13, title, true, 12); text(executive, row + 1, 2, 13, body); executive.getRow(row + 1).height = 76; });
}

/** Retain data rows and literal text; compact headers and alternate bands aid filtering. */
export function styleEnrichmentDetails(wb: ExcelJS.Workbook, analytical = false) {
  for (const ws of wb.worksheets) {
    if (analytical && ['Indicadores', 'IPs', 'Domínios', 'Hashes', 'URLs', '_dados'].includes(ws.name)) continue;
    if (['Dashboard', 'Resumo executivo', 'Sumário', 'Resumo'].includes(ws.name)) continue;
    ws.views = [{ state: 'frozen', ySplit: 1, xSplit: 1, showGridLines: false, zoomScale: 85 }];
    ws.getRow(1).height = 34;
    ws.pageSetup = { orientation: 'landscape', fitToPage: true, fitToWidth: 1, fitToHeight: 0, printTitlesRow: '1:1' };
    ws.eachRow((row, n) => {
      if (n === 1) { row.eachCell(cell => { cell.font = { name: 'Calibri', size: 11, bold: true, color: { argb: C.yellow } }; cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: C.ink } }; cell.alignment = { wrapText: true, vertical: 'middle' }; }); return; }
      row.height = 34;
      row.eachCell(cell => {
        const key = String(ws.getColumn(cell.col).key || '');
        if (['url', 'link', 'reference'].includes(key) && typeof cell.value === 'string' && /^https?:\/\/[^\s]+$/i.test(cell.value)) {
          cell.value = { text: cell.value, hyperlink: cell.value };
        }
        const link = cell.value && typeof cell.value === 'object' && 'hyperlink' in cell.value;
        cell.font = link ? { name: 'Calibri', color: { argb: 'FF0563C1' }, underline: true } : { name: 'Calibri', size: 10, color: { argb: C.ink } };
        cell.alignment = { vertical: 'top', wrapText: true };
        if (n % 2 === 0) cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: C.pale } };
      });
    });
  }
}
