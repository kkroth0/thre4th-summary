import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import JSZip from 'jszip';
import { assessOtPatch, analyzeOtReport } from './otPatchIntelligence';
import { buildNewsExcelWorkbook, type NewsExcelPayload } from './iocExcelWorkbook';
import { addOtPatchExcelCharts } from './otPatchExcelCharts';
import { shiftPatchMonth, otCurrentMonth } from '../services/otPatchApi';
const Excel = createRequire(`${process.cwd()}/package.json`)('exceljs') as typeof import('exceljs');
const row = (extra = {}) => ({ id: 'SEVD-2026-123', title: 'Security update', vendors: ['Schneider Electric'], published: '2026-10-01', updated: '2026-10-02', source: 'schneider', url: 'https://www.se.com/advisory', references: ['https://www.se.com/advisory'], cves: ['CVE-2026-12345'], cvss: null, cveSignals: [], patch: 'unconfirmed', matches: [], remediations: [], products: [], ...extra });

test('triage preserves unknown versus zero, separates mitigations from fixes, and ranks KEV first', () => {
  const unknown = assessOtPatch(row()); assert.equal(unknown.cvss, null); assert.equal(unknown.epss, null); assert.equal(unknown.priority, 'P3');
  const zero = assessOtPatch(row({ cvss: 0, cveSignals: [{ id: 'CVE-2026-12345', cvss: 0, epss: 0, kev: false }] }));
  assert.equal(zero.cvss, 0); assert.equal(zero.epss, 0); assert.equal(zero.priority, 'P4');
  const data = analyzeOtReport([row({ id: 'high', cvss: 10, patch: 'available' }), row({ id: 'kev', kev: true, patch: 'mitigation' }), row({ id: 'unknown' })]);
  assert.equal(data.assessments[0].row.id, 'kev'); assert.equal(data.fixes, 1); assert.equal(data.mitigations, 1); assert.equal(data.unconfirmed, 1); assert.equal(data.cves, 1);
  assert.equal(assessOtPatch(row({ cvss: NaN, cveSignals: [{ cvss: 99, epss: 1.2 }] })).cvss, null);
});

test('monthly navigation crosses years and uses Fortaleza date for current month', () => {
  assert.equal(shiftPatchMonth('2026-01', -1), '2025-12'); assert.equal(shiftPatchMonth('2026-12', 1), '2027-01');
  assert.equal(otCurrentMonth(new Date('2026-11-01T02:00:00Z')), '2026-10');
});

test('client report has cached dashboard formulas, formatted narrative, numeric EPSS and full long evidence', async () => {
  const narrative = 'Texto completo com evidência. '.repeat(1500) + 'FIM-DA-EVIDENCIA';
  const payload: NewsExcelPayload = { dataset: 'ot-patches', range: { from: '2026-10-01', to: '2026-10-31' }, rows: [row({ summary: narrative, cvss: 9.8, kev: true, patch: 'available', cveSignals: [{ id: 'CVE-2026-12345', kev: true, epss: 0, cvss: 9.8 }] })] };
  const wb = buildNewsExcelWorkbook(payload, Excel);
  assert.deepEqual(wb.worksheets.slice(0, 7).map(s => s.name), ['Dashboard','Resumo executivo','Plano de ação','Produtos e versões','Correções e evidências','Fontes e critérios','OT ICS Patch Day']);
  const dashboard = wb.getWorksheet('Dashboard')!;
  assert.equal(dashboard.getCell('B7').result, 1); assert.equal(dashboard.getCell('D7').result, 1); assert.equal(dashboard.getCell('F7').result, 1);
  assert.equal(wb.getWorksheet('Plano de ação')!.getCell('L6').value, 0); assert.equal(wb.getWorksheet('Plano de ação')!.getCell('L6').numFmt, '0.00%');
  const executive = wb.getWorksheet('Resumo executivo')!;
  assert.equal(executive.getCell('B7').alignment.wrapText, true); assert.ok(executive.getCell('B7').value && typeof executive.getCell('B7').value === 'object');
  assert.ok(JSON.stringify(wb.getWorksheet('Correções e evidências')!.getSheetValues()).includes('FIM-DA-EVIDENCIA'));
  assert.ok(JSON.stringify(wb.getWorksheet('Fontes e critérios')!.getSheetValues()).includes('Pendências e falhas de coleta não informadas'));
  const bytes = await addOtPatchExcelCharts(new Uint8Array(await wb.xlsx.writeBuffer()), payload);
  const zip = await JSZip.loadAsync(bytes), chart1 = await zip.file('xl/drawings/charts/chart1.xml')!.async('string');
  assert.match(chart1, /<c:pt idx="0"><c:v>1<\/c:v>/); assert.match(chart1, /Dashboard.*\$C\$41:\$C\$44/);
  assert.match(chart1, /<c:min val="0"\/>/);
  assert.match(await zip.file('xl/worksheets/_rels/sheet1.xml.rels')!.async('string'), /Target="..\/drawings\/drawing1.xml"/);
  assert.match(await zip.file('[Content_Types].xml')!.async('string'), /drawingml.chart\+xml/);
  const restored = new Excel.Workbook(); await restored.xlsx.load(bytes as unknown as ArrayBuffer);
  assert.equal(restored.getWorksheet('Dashboard')!.getCell('B7').result, 1);
});

test('AI report is titled correctly and package matching is explicit without claiming installed exposure', () => {
  const wb = buildNewsExcelWorkbook({ dataset: 'ai-patches', report: { domain: 'ai' }, range: { from: '2026-10-01', to: '2026-10-31' }, rows: [row({ matches: [{ vendor: 'MCP SDK', level: 'model', models: ['mcp'] }] })] }, Excel);
  assert.equal(wb.getWorksheet('Dashboard')!.getCell('B2').value, 'AI Tools Patch Day');
  assert.ok(wb.getWorksheet('AI Tools Patch Day')); assert.ok(!wb.getWorksheet('OT ICS Patch Day'));
  assert.equal(wb.getWorksheet('Plano de ação')!.getCell('I6').value, 'Pacote citado');
  assert.match(String(wb.getWorksheet('Plano de ação')!.getCell('G6').value), /Pacote citado/);
});

test('multiline source text is fully readable in continuation rows rather than clipped at Excel height limits', () => {
  const summary = Array.from({ length: 70 }, (_, i) => `Linha ${i + 1}: evidência da fonte.\n`).join('');
  const wb = buildNewsExcelWorkbook({ dataset: 'ai-patches', report: { domain: 'ai', sources: [{ id: 'github', name: 'GitHub', url: 'https://github.com/advisories', coverage: 'Histórico em atualização', status: 'pending' }] }, range: { from: '2026-10-01', to: '2026-10-31' }, rows: [row({ summary })] }, Excel);
  const sheet = wb.getWorksheet('Correções e evidências')!; const parts: string[] = [];
  sheet.eachRow((r, index) => { if (index >= 6) { parts.push(String(r.getCell(4).value)); assert.ok((r.height || 0) < 409); } });
  assert.ok(parts.length >= 4); assert.equal(parts.join(''), summary);
  assert.ok(JSON.stringify(wb.getWorksheet('Fontes e critérios')!.getSheetValues()).includes('Em atualização'));
});
