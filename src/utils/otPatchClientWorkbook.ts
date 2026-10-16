import type ExcelJS from 'exceljs';
import type { NewsExcelPayload } from './iocExcelWorkbook';
import { scrubXml } from './deckTemplate';
import { analyzeOtReport, OT_PRIORITY_CRITERIA, OT_PRIORITY_LABELS, percentPt } from './otPatchIntelligence';

const C = { ink: '14283F', blue: '2563EB', pale: 'EFF5FD', muted: '596B80', line: 'D9E2EE', white: 'FFFFFF', red: 'B42318', amber: '9A6700', green: '176B43' };
const text = (v: unknown) => scrubXml(String(v ?? ''));
const sourceName = (id: string) => ({ cisa: 'CISA OT · CSAF', rockwell: 'Rockwell Automation', cisco: 'Cisco · CSAF', schneider: 'Schneider Electric · CSAF' })[id] || id || 'Fonte não informada';
const safeLink = (url: unknown) => { try { const u = new URL(String(url)); return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : ''; } catch { return ''; } };
const split = (value: string, max = 1500) => {
  const result: string[] = []; let remaining = text(value);
  while (remaining.length > max) { let end = remaining.lastIndexOf(' ', max); if (end < max / 2) end = max; if (/[\uD800-\uDBFF]/.test(remaining[end - 1])) end--; result.push(remaining.slice(0, end)); remaining = remaining.slice(end); }
  result.push(remaining); return result;
};
function sheet(wb: ExcelJS.Workbook, name: string, widths: number[], presentation = false) {
  const ws = wb.addWorksheet(name, { properties: { tabColor: { argb: presentation ? C.ink : C.blue }, defaultRowHeight: 19 }, views: [{ showGridLines: false, zoomScale: 90, ...(presentation ? {} : { state: 'frozen' as const, ySplit: 5, xSplit: 2 }) }], pageSetup: { paperSize: 9, orientation: presentation ? 'portrait' : 'landscape', fitToPage: true, fitToWidth: 1, fitToHeight: 0, margins: { left: .3, right: .3, top: .4, bottom: .4, header: .15, footer: .15 } } });
  widths.forEach((width, i) => { ws.getColumn(i + 1).width = width; });
  ws.headerFooter.oddFooter = '&LThreatSumm4ry · Patch Day&R&P / &N';
  return ws;
}
function cellStyle(cell: ExcelJS.Cell, bold = false, color = C.ink) {
  cell.font = { name: 'Calibri', size: 11, bold, color: { argb: color } };
  cell.alignment = { vertical: 'top', wrapText: true };
}
function merged(ws: ExcelJS.Worksheet, row: number, from: number, to: number, value: ExcelJS.CellValue, options: { fill?: string; bold?: boolean; color?: string; size?: number } = {}) {
  ws.mergeCells(row, from, row, to); const cell = ws.getCell(row, from); cell.value = value; cellStyle(cell, options.bold, options.color);
  if (options.size) cell.font = { ...cell.font, size: options.size };
  if (options.fill) cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: options.fill } };
  return cell;
}
function heading(ws: ExcelJS.Worksheet, title: string, subtitle: string, end: number) {
  merged(ws, 2, 2, end, title, { bold: true, size: 16 }); ws.getRow(2).height = 28;
  merged(ws, 3, 2, end, subtitle, { color: C.muted }); ws.getRow(3).height = 30;
  for (let i = 2; i <= end; i++) ws.getCell(4, i).border = { bottom: { style: 'thin', color: { argb: C.blue } } };
}
function section(ws: ExcelJS.Worksheet, row: number, title: string) {
  merged(ws, row, 2, 13, title, { bold: true, color: C.white, fill: C.ink }); ws.getRow(row).height = 24;
}
function paragraph(ws: ExcelJS.Worksheet, row: number, label: string, body: string) {
  for (const [i, part] of split(body, 850).entries()) {
    const value = { richText: [...(i === 0 && label ? [{ text: text(label) + ' ', font: { name: 'Calibri', size: 11, bold: true, color: { argb: C.ink } } }] : []), { text: part, font: { name: 'Calibri', size: 11, color: { argb: C.ink } } }] };
    merged(ws, row, 2, 13, value);
    ws.getRow(row).height = Math.max(32, Math.ceil((label.length + part.length) / 115) * 16 + 10); row++;
  }
  return row;
}
type Column = { key: string; label: string; width: number; format?: string };
function readableTable(wb: ExcelJS.Workbook, name: string, subtitle: string, columns: Column[], records: Record<string, unknown>[], paginate = true) {
  const ws = sheet(wb, name, columns.map(c => c.width));
  ws.mergeCells(2, 1, 2, columns.length);
  ws.mergeCells(3, 1, 3, columns.length);
  ws.getCell('A2').value = name; cellStyle(ws.getCell('A2'), true); ws.getCell('A2').font = { ...ws.getCell('A2').font, size: 16 }; ws.getRow(2).height = 28;
  ws.getCell('A3').value = subtitle; cellStyle(ws.getCell('A3'), false, C.muted); ws.getCell('A3').alignment = { wrapText: false }; ws.getRow(3).height = 22;
  columns.forEach((c, i) => { const cell = ws.getCell(5, i + 1); cell.value = c.label; cellStyle(cell, true, C.white); cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: C.ink } }; cell.alignment = { horizontal: 'center', vertical: 'middle', wrapText: true }; }); ws.getRow(5).height = 30;
  for (const record of records) {
    const chunks = columns.map(c => typeof record[c.key] === 'string' && paginate ? split(String(record[c.key])) : [record[c.key]]);
    for (let part = 0; part < Math.max(1, ...chunks.map(a => a.length)); part++) {
      const row = ws.addRow(columns.map((c, i) => { const value = chunks[i][part] ?? (chunks[i].length === 1 ? record[c.key] ?? null : null); return value === '' ? null : value; }) as ExcelJS.CellValue[]);
      let lines = 1;
      columns.forEach((c, i) => {
        const cell = row.getCell(i + 1); cellStyle(cell);
        if (c.format) cell.numFmt = c.format;
        if (typeof cell.value === 'number') cell.alignment = { vertical: 'top', horizontal: 'right' };
        if (cell.value instanceof Date) cell.numFmt = 'dd/mm/yyyy';
        const value = String(cell.value ?? '');
        lines = Math.max(lines, ...value.split('\n').map(line => Math.ceil(line.length / Math.max(8, c.width - 3))));
        if (c.key === 'url' && safeLink(cell.value)) { cell.value = { text: 'Abrir referência oficial', hyperlink: safeLink(cell.value) }; cell.font = { ...cell.font, color: { argb: C.blue }, underline: true }; }
        cell.border = { bottom: { style: 'hair', color: { argb: C.line } } };
      });
      row.height = Math.min(409, Math.max(32, lines * 15 + 8));
    }
  }
  ws.autoFilter = { from: 'A5', to: { row: Math.max(5, ws.rowCount), column: columns.length } };
  ws.pageSetup.printTitlesRow = '1:5'; ws.pageSetup.printArea = `A1:${ws.getColumn(columns.length).letter}${Math.max(6, ws.rowCount)}`;
  return ws;
}
const wrapVendor = (s: string) => s.split(' ').reduce((lines: string[], word) => { if (lines.length && lines.at(-1)!.length + word.length < 19) lines[lines.length - 1] += ' ' + word; else lines.push(word); return lines; }, []).join('\n');

export function addOtPatchClientSheets(wb: ExcelJS.Workbook, payload: NewsExcelPayload) {
  const ai = payload.dataset === 'ai-patches', title = ai ? 'AI Tools Patch Day' : 'OT/ICS Patch Day', matchedLabel = ai ? 'Pacote citado' : 'Modelo citado';
  const a = analyzeOtReport(payload.rows, payload.report);
  const generatedAt = new Date(payload.generatedAt || Date.now()).toLocaleString('pt-BR', { timeZone: 'America/Fortaleza' });
  const period = `${payload.range.from.slice(8, 10)}/${payload.range.from.slice(5, 7)}/${payload.range.from.slice(0, 4)} a ${payload.range.to.slice(8, 10)}/${payload.range.to.slice(5, 7)}/${payload.range.to.slice(0, 4)}`;
  const context = payload.report?.filters;
  const scope = context ? [context.manufacturer, context.matching, context.remediation, context.query ? `Busca: ${context.query}` : ''].filter(Boolean).join(' · ') : `Seleção exportada do ${title}`;
  const dashboard = sheet(wb, 'Dashboard', [3, ...Array(12).fill(12)], true);
  dashboard.pageSetup.orientation = 'landscape'; dashboard.pageSetup.fitToHeight = 1; dashboard.pageSetup.printArea = 'B2:M35';
  heading(dashboard, title, `${period}  |  Emitido em ${generatedAt} (Fortaleza)`, 13);
  const end = Math.max(6, a.total + 5), plan = "'Plano de ação'!";
  const cards = [
    ['Avisos', `COUNTA(${plan}$A$6:$A$${end})`, a.total], ['CVEs distintas', `COUNTA($K$41:$K$${Math.max(41, 40 + a.cves)})`, a.cves],
    ['Sinal KEV', `COUNTIFS(${plan}$J$6:$J$${end},"Com sinal")`, a.kev], ['Correção publicada', `COUNTIFS(${plan}$H$6:$H$${end},"Correção publicada")`, a.fixes],
    ['Somente mitigação', `COUNTIFS(${plan}$H$6:$H$${end},"Mitigação sem correção confirmada")`, a.mitigations], [matchedLabel, `COUNTIFS(${plan}$I$6:$I$${end},"${matchedLabel}")`, a.matched],
  ] as const;
  cards.forEach(([label, formula, result], i) => {
    const col = 2 + i * 2;
    merged(dashboard, 6, col, col + 1, label, { bold: true, color: C.muted, fill: C.pale });
    merged(dashboard, 7, col, col + 1, { formula, result }, { bold: true, size: 20, color: i === 2 && result > 0 ? C.red : C.ink, fill: C.pale });
  }); dashboard.getRow(6).height = 30; dashboard.getRow(7).height = 32;
  merged(dashboard, 9, 2, 13, `${a.partial ? 'COBERTURA PARCIAL. ' : ''}${a.total} avisos nesta seleção; correspondência de catálogo não confirma a versão instalada.`, { color: a.partial ? C.amber : C.muted }); dashboard.getRow(9).height = 30;
  for (let r = 11; r <= 22; r++) dashboard.getRow(r).height = 18;
  section(dashboard, 24, 'Prioridades para decisão');
  merged(dashboard, 25, 2, 3, 'Prioridade', { bold: true }); merged(dashboard, 25, 4, 8, 'Aviso', { bold: true }); merged(dashboard, 25, 9, 13, 'Próximo passo', { bold: true });
  a.assessments.slice(0, 5).forEach((item, i) => {
    const r = 26 + i;
    merged(dashboard, r, 2, 3, item.priority + ' · ' + item.priorityLabel, { bold: true, color: item.priority === 'P1' ? C.red : C.ink });
    merged(dashboard, r, 4, 8, `${item.row.id} · ${item.row.vendors.join(', ')}`);
    merged(dashboard, r, 9, 13, item.row.patch === 'available' ? 'Validar aplicabilidade e homologar correção.' : item.row.patch === 'mitigation' ? 'Validar e avaliar as mitigações do fabricante.' : 'Confirmar solução e acompanhar o fabricante.');
    dashboard.getRow(r).height = 42;
  });
  if (!a.total) merged(dashboard, 26, 2, 13, 'Nenhum aviso na seleção exportada. A ausência de resultado não confirma ausência de vulnerabilidades.', { color: C.muted });
  merged(dashboard, 33, 2, 13, `Escopo: ${scope}`, { color: C.muted }); dashboard.getRow(33).height = 32;
  merged(dashboard, 38, 2, 13, 'Contagens que alimentam os gráficos e o painel', { bold: true });
  dashboard.getCell('B40').value = 'Prioridade'; dashboard.getCell('C40').value = 'Avisos'; dashboard.getCell('G40').value = 'Fabricante'; dashboard.getCell('H40').value = 'Avisos'; dashboard.getCell('K40').value = 'CVEs distintas';
  a.priorities.forEach((p, i) => { dashboard.getCell(41 + i, 2).value = p.label; dashboard.getCell(41 + i, 3).value = { formula: `COUNTIFS(${plan}$B$6:$B$${end},B${41 + i})`, result: p.count }; });
  for (let i = 0; i < 5; i++) { const vendor = a.vendors[i]; dashboard.getCell(41 + i, 7).value = vendor ? wrapVendor(vendor.label) : ''; dashboard.getCell(41 + i, 8).value = vendor?.count ?? 0; }
  const cves = [...new Set(a.assessments.flatMap(item => item.row.cves))].sort();
  cves.forEach((cve, i) => { dashboard.getCell(41 + i, 11).value = cve; });
  for (let r = 40; r <= Math.max(45, cves.length + 40); r++) dashboard.getRow(r).eachCell(c => cellStyle(c, r === 40));
  dashboard.getColumn('K').numFmt = '@';

  const executive = sheet(wb, 'Resumo executivo', [3, ...Array(12).fill(9)], true);
  heading(executive, 'Resumo executivo', `${title} · ${period}`, 13);
  let r = 6; section(executive, r++, 'Leitura do período');
  r = paragraph(executive, r, '', a.total ? `A seleção reúne ${a.total} avisos e ${a.cves} CVEs distintas. Há ${a.kev} avisos com sinal de exploração conhecida, ${a.fixes} com correção publicada, ${a.mitigations} com mitigação sem correção confirmada e ${a.unconfirmed} sem solução confirmada nos dados disponíveis.` : 'Não há avisos nesta seleção. Rever os filtros e a cobertura das fontes antes de concluir ausência de risco.');
  r = paragraph(executive, r, 'Relevância para o ambiente.', `${a.matched} avisos citam explicitamente ${ai ? 'pacotes' : 'modelos'} do catálogo. Esse vínculo orienta a triagem, mas não confirma a versão instalada ou a exposição do ambiente. Confira também as versões afetadas e as condições descritas no aviso antes de abrir uma mudança.`);
  r = paragraph(executive, r, 'Direcionamento.', a.kev ? 'Começar pelos avisos com exploração conhecida; confirmar produtos e versões aplicáveis e conduzir a resposta conforme as orientações do fabricante e as restrições operacionais.' : 'Começar pelos avisos de maior prioridade técnica e pelos modelos explicitamente citados. Confirmar aplicabilidade antes de abrir uma mudança em produção.');
  r++; section(executive, r++, 'Decisões recomendadas');
  r = paragraph(executive, r, 'Correções disponíveis.', `${a.fixes} avisos informam correção publicada. Confrontar as versões locais com as afetadas, homologar a atualização e definir a janela operacional com as equipes responsáveis.`);
  r = paragraph(executive, r, 'Mitigações e pendências.', `${a.mitigations + a.unconfirmed} avisos precisam de avaliação das medidas compensatórias ou confirmação de solução. Acompanhar revisões do fabricante e registrar o tratamento adotado.`);
  r++; section(executive, r++, 'Destaques para acompanhamento');
  for (const item of a.assessments.slice(0, 5)) {
    r = paragraph(executive, r, `${item.priority} · ${item.row.id}.`, `${item.row.title || 'Aviso sem título'} — ${item.row.vendors.join(', ') || 'Fabricante não informado'}.`);
    r = paragraph(executive, r, 'Por que priorizar.', item.reason);
    r = paragraph(executive, r, 'Aplicabilidade.', item.applicability);
    r = paragraph(executive, r, 'Ação recomendada.', item.action); r++;
  }
  section(executive, r++, 'Qualidade da informação');
  r = paragraph(executive, r, 'Cobertura.', a.sourcesKnown ? `${a.sourcesOk} de ${a.sources.length} índices de fontes disponíveis na emissão.${a.partial ? ' A coleta está parcial; conferir as pendências em Fontes e critérios.' : ''} ${a.missingCvss} avisos sem CVSS e ${a.missingEpss} sem EPSS disponível.` : 'O estado das fontes não foi informado nesta exportação. Dados ausentes permanecem identificados como não disponíveis.');
  paragraph(executive, r, 'Critério de leitura.', 'As prioridades são uma regra editorial de triagem baseada em KEV, CVSS e EPSS; não representam risco confirmado do cliente nem prazos de SLA. O texto reflete o snapshot da exportação. Os trechos dos fabricantes são preservados no idioma original nas evidências técnicas.');
  executive.pageSetup.printArea = `B2:M${executive.rowCount}`;

  const planRows = a.assessments.map((item, i) => ({ rank: i + 1, priority: item.priority, id: item.row.id, vendor: item.row.vendors.join('\n'), reason: item.reason, action: item.action, applicability: item.applicability, patch: item.patchLabel, match: item.modelMatches.length ? matchedLabel : item.row.matches.length ? 'Somente fabricante' : 'Não identificado', kev: item.kev ? 'Com sinal' : 'Sem sinal positivo', cvss: item.cvss, epss: item.epss, url: item.row.url }));
  const planSheet = readableTable(wb, 'Plano de ação', 'Ordem de triagem e decisões recomendadas para os avisos desta seleção.', [
    { key: 'rank', label: '#', width: 6 }, { key: 'priority', label: 'Prioridade', width: 12 }, { key: 'id', label: 'Aviso', width: 23 }, { key: 'vendor', label: 'Fabricante', width: 27 }, { key: 'reason', label: 'Justificativa', width: 56 }, { key: 'action', label: 'Ação recomendada', width: 58 }, { key: 'applicability', label: 'Validação de aplicabilidade', width: 54 }, { key: 'patch', label: 'Situação da correção', width: 27 }, { key: 'match', label: 'Catálogo', width: 22 }, { key: 'kev', label: 'Exploração conhecida', width: 22 }, { key: 'cvss', label: 'Maior CVSS', width: 13, format: '0.0' }, { key: 'epss', label: 'Maior EPSS', width: 14, format: '0.00%' }, { key: 'url', label: 'Fonte', width: 30 },
  ], planRows, false);
  for (let row = 6; row <= planSheet.rowCount; row++) { const cell = planSheet.getCell(row, 2); cell.font = { ...cell.font, bold: true, color: { argb: cell.value === 'P1' ? C.red : cell.value === 'P2' ? C.amber : C.ink } }; }

  readableTable(wb, 'Produtos e versões', 'Produtos mencionados nas fontes; versões instaladas no ambiente não foram avaliadas.', [
    { key: 'id', label: 'Aviso', width: 25 }, { key: 'vendor', label: 'Fabricante', width: 28 }, { key: 'product', label: 'Produto e versão informados', width: 83 }, { key: 'model', label: 'Códigos de modelo', width: 40 }, { key: 'status', label: 'Estado na fonte', width: 24 }, { key: 'url', label: 'Referência', width: 30 },
  ], a.assessments.flatMap(item => item.row.products.length ? item.row.products.map(p => ({ id: item.row.id, vendor: p.vendor || item.row.vendors.join(', '), product: p.name, model: (p.modelNumbers || []).join('\n'), status: p.status === 'affected' ? 'Afetado na fonte' : p.status === 'fixed' ? 'Versão corrigida' : 'Mencionado na fonte', url: item.row.url })) : [{ id: item.row.id, vendor: item.row.vendors.join(', '), product: 'Produto/versão não estruturados; consultar o aviso oficial.', model: '', status: 'Não informado', url: item.row.url }]));
  const remediationNames: Record<string, string> = { vendor_fix: 'Correção do fabricante', mitigation: 'Mitigação', workaround: 'Contorno', reference: 'Referência', no_fix_planned: 'Sem correção planejada', none_available: 'Solução não disponível' };
  readableTable(wb, 'Correções e evidências', 'Orientações e sínteses das fontes, preservadas no idioma original.', [
    { key: 'id', label: 'Aviso', width: 25 }, { key: 'cve', label: 'CVE', width: 24 }, { key: 'category', label: 'Tipo de informação', width: 28 }, { key: 'details', label: 'Texto da fonte', width: 100 }, { key: 'products', label: 'Produtos associados', width: 72 }, { key: 'url', label: 'Referência', width: 30 },
  ], a.assessments.flatMap(item => [
    ...(item.row.summary ? [{ id: item.row.id, cve: item.row.cves.join('\n'), category: 'Síntese do fabricante', details: item.row.summary, products: '', url: item.row.url }] : []),
    ...item.row.remediations.map(rem => ({ id: item.row.id, cve: rem.cve, category: remediationNames[rem.category] || rem.category, details: rem.details, products: (rem.products || []).join('\n'), url: rem.url || item.row.url })),
    ...item.row.cveSignals.map(signal => ({ id: item.row.id, cve: signal.id, category: 'Sinais do catálogo de CVEs', details: `KEV: ${signal.kev === true ? 'sinal positivo' : signal.kev === false ? 'sem sinal positivo no catálogo consultado' : 'não informado'}. CVSS: ${signal.cvss ?? 'não informado'}. EPSS: ${signal.epss != null ? percentPt(signal.epss) : 'não informado'}.`, products: '', url: `https://nvd.nist.gov/vuln/detail/${signal.id}` })),
  ]));

  const sources = sheet(wb, 'Fontes e critérios', [3, ...Array(12).fill(9)], true);
  heading(sources, 'Fontes e critérios', `${title} · ${period}`, 13);
  r = 6; section(sources, r++, 'Escopo e fechamento');
  r = paragraph(sources, r, 'Seleção.', scope);
  r = paragraph(sources, r, 'Período.', `${payload.range.from} a ${payload.range.to}; considera publicação inicial ou última revisão no mês. Emitido em ${generatedAt}, America/Fortaleza.`);
  r = paragraph(sources, r, 'Estado da coleta.', `${a.partial ? 'Cobertura parcial' : a.sourcesKnown ? 'Índices disponíveis na emissão' : 'Cobertura não informada'}. ${payload.report?.status ? `${payload.report.status.pending} pendências; ${payload.report.status.failed} falhas de coleta.` : 'Pendências e falhas de coleta não informadas.'} Os indicadores do dashboard usam somente as linhas efetivamente exportadas.`);
  section(sources, ++r, 'Regra de priorização'); r++;
  for (const [priority, criterion] of OT_PRIORITY_CRITERIA) r = paragraph(sources, r, `${priority} · ${OT_PRIORITY_LABELS[priority as keyof typeof OT_PRIORITY_LABELS]}.`, criterion);
  r = paragraph(sources, r, 'Interpretação.', 'O limiar EPSS de 50% é uma regra editorial deste relatório. EPSS estima exploração de uma CVE nos próximos 30 dias; não mede probabilidade de incidente no cliente. CVSS descreve severidade técnica. A priorização não substitui validação de exposição e criticidade operacional.');
  section(sources, ++r, 'Fontes e referências'); r++;
  for (const source of a.sources) {
    r = paragraph(sources, r, source.name + '.', `${source.status === 'ok' ? 'Disponível' : source.status === 'stale' ? 'Cache anterior' : 'Indisponível ou não consultada'}. Último sucesso: ${source.lastSuccess || 'não informado'}. ${source.coverage || ''}${source.error ? ' Falha: ' + source.error : ''}`);
    const cell = merged(sources, r++, 2, 13, ''); const url = safeLink(source.url); if (url) { cell.value = { text: source.url, hyperlink: url }; cell.font = { name: 'Calibri', size: 11, color: { argb: C.blue }, underline: true }; cell.alignment = { wrapText: true }; sources.getRow(r - 1).height = 36; }
  }
  for (const [label, url] of [['EPSS · FIRST', 'https://www.first.org/epss/'], ['CVSS · FIRST', 'https://www.first.org/cvss/'], ['CISA · KEV', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog']]) {
    const cell = merged(sources, r++, 2, 13, { text: label, hyperlink: url }); cell.font = { name: 'Calibri', size: 11, color: { argb: C.blue }, underline: true }; sources.getRow(r - 1).height = 22;
  }
  for (const item of a.assessments) {
    r = paragraph(sources, ++r, item.row.id + '.', `${sourceName(item.row.source)} · publicação ${item.row.published || 'não informada'} · última revisão ${item.row.updated || 'não informada'}.`);
    for (const url of [...new Set([item.row.url, ...item.row.references])].filter(safeLink)) { const cell = merged(sources, r++, 2, 13, { text: url, hyperlink: safeLink(url) }); cell.font = { name: 'Calibri', size: 11, color: { argb: C.blue }, underline: true }; cell.alignment = { wrapText: true }; sources.getRow(r - 1).height = Math.max(24, Math.ceil(url.length / 110) * 15 + 6); }
  }
  sources.pageSetup.printArea = `B2:M${sources.rowCount}`;
  wb.calcProperties.fullCalcOnLoad = true;
  return a;
}
