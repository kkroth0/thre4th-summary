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

test('empty bulk export keeps the unified analytical tabs and omits diagnostics and summaries',()=>{
 const wb=buildBulkExcelWorkbook([],Excel);
 for(const name of ['Dashboard','Indicadores','Publicações','Menções','Relações','Técnicas ATT&CK'])assert.ok(wb.getWorksheet(name));
 for(const name of ['Resumo','Resumo executivo','Dados extensos','Fontes','Evidências','Consulta original','Detalhes por fonte'])assert.equal(wb.getWorksheet(name),undefined);
 assert.equal(wb.getWorksheet('Dashboard')!.getCell('B5').value,0);
});
test('unified bulk columns retain infrastructure and the observed classification without processing messages',()=>{
 const wb=buildBulkExcelWorkbook([{query:'93.184.216.34',state:'partial',result:{query:'93.184.216.34',overallScore:80,threatLevel:'malicious',detections:1,totalVendors:2,vendorData:[{name:'VirusTotal',data:{Malicious:12}},{name:'DNS / Team Cymru',data:{'Reverse Hostname':'resolver.example'},error:'ASN unavailable'}]}}],Excel);
 const row=wb.getWorksheet('Indicadores')!.getRow(2);assert.equal(row.getCell('rdns').value,'resolver.example');assert.equal(row.getCell('verdict').value,'Malicioso');
 const text=JSON.stringify(wb.getWorksheet('Indicadores')!.getSheetValues());for(const message of ['VirusTotal','Consulta incompleta','ASN unavailable','JSON'])assert.ok(!text.includes(message));
});

test('news Excel retains unknown additive fields and sanitizes illegal XML text without executing formulas', () => {
  const wb = buildNewsExcelWorkbook({ ...payload(), dataset: 'news', rows: [{ title: 'Report\u0000 title', futureEvidence: { confidence: 0, title: '@external' }, hashes: ['a'.repeat(64)] }] }, Excel);
  const sheet = wb.getWorksheet('Publicações')!;
  assert.equal(sheet.getRow(2).getCell('title').value, 'Report title');
  assert.equal(sheet.getRow(2).getCell('futureEvidence').value, '{"confidence":0,"title":"@external"}');
});

test('large provider payloads are not embedded and input history is unchanged',async()=>{
 const raw={evidence:'x'.repeat(500000),final:'saved upstream'};
 const rows:BulkRow[]=[{query:'93.184.216.34',state:'complete',result:{query:'93.184.216.34',overallScore:0,threatLevel:'unknown',detections:0,totalVendors:1,vendorData:[{name:'OTX',data:{},rawPayload:raw}]}}];
 const wb=buildBulkExcelWorkbook(rows,Excel);const buffer=await wb.xlsx.writeBuffer();assert.ok(buffer.byteLength<50000);assert.equal(rows[0].result!.vendorData[0].rawPayload,raw);
 const restored=new Excel.Workbook();await restored.xlsx.load(buffer);assert.equal(restored.getWorksheet('Dados extensos'),undefined);assert.equal(restored.getWorksheet('Resumo'),undefined);assert.equal(restored.getWorksheet('Indicadores')!.getCell('A2').value,rows[0].query);
});

test('invalid news export payload is rejected instead of producing a misleading empty workbook', () => {
  assert.throws(() => buildNewsExcelWorkbook({ ...payload(), rows: null as unknown as [] }, Excel), /inválida/);
});
test('OT Patch Day Excel retains versions, fixes, matches, source status and period as literal values', async () => {
  const row = { id: 'SEVD-2025-224-05', title: '=untrusted title', products: [{ name: 'Module before 6.80', modelNumbers: ['BMXNOE0110'], status: 'affected' }], remediations: [{ category: 'vendor_fix', details: 'Upgrade to 6.80' }], matches: [{ vendor: 'Schneider Electric', level: 'model', models: ['BMXNOE0110'] }], cveSignals: [{ id: 'CVE-2025-6625', kev: null, epss: null }], sourceCoverage: [{ id: 'schneider', status: 'ok' }] };
  const wb = buildNewsExcelWorkbook({ dataset: 'ot-patches', range: { from: '2026-08-01', to: '2026-08-31' }, rows: [row] }, Excel);
  const restored = new Excel.Workbook(); await restored.xlsx.load(await wb.xlsx.writeBuffer());
  const sheet = restored.getWorksheet('OT ICS Patch Day')!;
  assert.equal(sheet.rowCount, 2); assert.equal(sheet.getCell('B2').type, Excel.ValueType.String);
  const text = JSON.stringify(sheet.getSheetValues());
  for (const value of ['BMXNOE0110', 'Upgrade to 6.80', 'model', 'schneider', 'CVE-2025-6625']) assert.ok(text.includes(value));
  assert.ok(JSON.stringify(restored.getWorksheet('Fontes e critérios')!.getSheetValues()).includes('2026-08-31'));
});
