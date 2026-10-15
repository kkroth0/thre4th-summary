import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { buildNewsExcelWorkbook, buildBulkExcelWorkbook, type NewsExcelPayload } from './iocExcelExport';
import type { BulkRow } from './bulkEnrichment';
const Excel = createRequire(`${process.cwd()}/package.json`)('exceljs') as typeof import('exceljs');
const payload = (): NewsExcelPayload => ({ dataset: 'iocs', range: { from: '2026-10-08T03:00:00.000Z', to: '2026-10-16T02:59:59.999Z' }, rows: [
  { type: 'hash', indicator: '0'.repeat(64), title: '=HYPERLINK("https://bad.test")', source: 'news', url: 'https://lab.example/a', date: '2026-10-15T13:45:12Z', dateBasis: 'published', storyId: 'story-A', actors: ['APT42'], malware: ['Family'], cves: ['CVE-2026-10001'] },
  { type: 'hash', indicator: '0'.repeat(64), source: 'ThreatFox', storyId: 'story-A', date: '2026-10-15T14:01:00Z' },
] });

test('IOC Excel preserves each source evidence, full hash identity, dates, entities and range', async () => {
  const wb = buildNewsExcelWorkbook(payload(), Excel), sheet = wb.getWorksheet('IOCs')!;
  assert.equal(sheet.rowCount, 3);
  assert.equal(sheet.getRow(2).getCell('indicator').value, '0'.repeat(64));
  assert.equal(sheet.getRow(2).getCell('date').value, '2026-10-15T13:45:12Z');
  assert.equal(sheet.getRow(2).getCell('actors').value, 'APT42');
  assert.equal(sheet.getRow(3).getCell('source').value, 'ThreatFox');
  assert.equal(sheet.getRow(2).getCell('title').type, Excel.ValueType.String);
  assert.equal(sheet.getRow(2).getCell('title').value, '=HYPERLINK("https://bad.test")');
  assert.ok(sheet.autoFilter); assert.equal(sheet.views[0].state, 'frozen');
  const restored = new Excel.Workbook(); await restored.xlsx.load(await wb.xlsx.writeBuffer());
  assert.equal(restored.getWorksheet('IOCs')!.getCell('B2').value, '0'.repeat(64));
  assert.equal(restored.getWorksheet('IOCs')!.getCell('C2').type, Excel.ValueType.String);
  assert.ok(JSON.stringify(restored.getWorksheet('Resumo')!.getSheetValues()).includes(payload().range.to));
});

test('empty Excel export has headers, a zero count and an explicit evidence scope', () => {
  const wb = buildNewsExcelWorkbook({ ...payload(), rows: [] }, Excel);
  assert.equal(wb.getWorksheet('IOCs')!.rowCount, 1);
  assert.ok(JSON.stringify(wb.getWorksheet('Resumo')!.getSheetValues()).includes('Registros exportados'));
  const bulk = buildBulkExcelWorkbook([], Excel);
  for (const name of ['Indicadores', 'Fontes', 'Publicações', 'Evidências', 'Resumo']) assert.ok(bulk.getWorksheet(name));
});

test('news Excel retains unknown additive fields and sanitizes illegal XML text without executing formulas', () => {
  const wb = buildNewsExcelWorkbook({ ...payload(), dataset: 'news', rows: [{ title: 'Report\u0000 title', futureEvidence: { confidence: 0, title: '@external' }, hashes: ['a'.repeat(64)] }] }, Excel);
  const sheet = wb.getWorksheet('Publicações')!;
  assert.equal(sheet.getRow(2).getCell('title').value, 'Report title');
  assert.equal(sheet.getRow(2).getCell('futureEvidence').value, '{"confidence":0,"title":"@external"}');
});

test('bulk Excel includes provider failures, raw responses, publications and entity relationships', async () => {
  const rows: BulkRow[] = [{ query: '9.9.9.10', state: 'partial', result: { query: '9.9.9.10', overallScore: 0, threatLevel: 'unknown', totalVendors: 2, detections: 0,
    vendorData: [{ name: 'OTX', data: { 'Pulse count': 4 }, rawPayload: { pulses: [{ name: 'Example' }] }, quota: { remaining: 0 }, link: 'https://otx.example/pulse' }, { name: 'VirusTotal', data: {}, error: 'Quota exceeded' }] },
    context: { errors: ['Base unavailable'], publications: [{ storyId: 'event', title: 'Report', source: 'Lab', link: 'https://lab.example/a', pubDate: '2026-10-15T13:15:10Z', actors: ['Actor'], categories: [] }],
      evidence: [{ provider: 'OTX', title: 'Pulse', link: 'https://otx.example/pulse', published: '2026-10-15T13:00:00Z', collectedAt: '2026-10-15T14:00:00Z', confidence: 0, reputation: null, entities: [{ kind: 'actor', id: 'G1', name: 'Actor', relation: 'mentioned-with' }] }] } }];
  const wb = buildBulkExcelWorkbook(rows, Excel);
  assert.equal(wb.getWorksheet('Fontes')!.getRow(3).getCell('state').value, 'Quota exceeded');
  assert.equal(wb.getWorksheet('Fontes')!.getRow(2).getCell('raw').value, '{"pulses":[{"name":"Example"}]}');
  assert.equal(wb.getWorksheet('Indicadores')!.getRow(2).getCell('score').value, 0);
  assert.equal(wb.getWorksheet('Publicações')!.getRow(2).getCell('storyId').value, 'event');
  assert.ok(String(wb.getWorksheet('Evidências')!.getRow(2).getCell('entities').value).includes('mentioned-with'));
  assert.equal(wb.getWorksheet('Evidências')!.getRow(2).getCell('confidence').value, 0);
  const restored = new Excel.Workbook(); await restored.xlsx.load(await wb.xlsx.writeBuffer());
  assert.equal(restored.getWorksheet('Fontes')!.getCell('C3').value, 'Quota exceeded');
});

test('large provider JSON survives Excel roundtrip as ordered chunks without truncation or split Unicode pairs', async () => {
  const raw = { evidence: 'x'.repeat(29985) + '🚀'.repeat(24000), final: 'last evidence retained' };
  const rows: BulkRow[] = [{ query: '9.9.9.10', state: 'complete', result: { query: '9.9.9.10', overallScore: 0, threatLevel: 'unknown', detections: 0, totalVendors: 1, vendorData: [{ name: 'OTX', data: {}, rawPayload: raw }] } }];
  const wb = buildBulkExcelWorkbook(rows, Excel), reference = String(wb.getWorksheet('Fontes')!.getRow(2).getCell('raw').value).split(' — ')[0];
  const restored = new Excel.Workbook(); await restored.xlsx.load(await wb.xlsx.writeBuffer());
  const parts: string[] = [];
  restored.getWorksheet('Dados extensos')!.eachRow((row, index) => { if (index > 1 && row.getCell(1).value === reference) { const text = String(row.getCell(6).value); assert.ok(text.length <= 30000); parts.push(text); } });
  assert.deepEqual(JSON.parse(parts.join('')), raw);
});

test('invalid news export payload is rejected instead of producing a misleading empty workbook', () => {
  assert.throws(() => buildNewsExcelWorkbook({ ...payload(), rows: null as unknown as [] }, Excel), /inválida/);
});
