import test from 'node:test';
import assert from 'node:assert/strict';
import Excel from 'exceljs';
import { buildNewsExcelWorkbook } from './iocExcelWorkbook';
const range = { from: '2026-11-20T03:00:00.000Z', to: '2026-11-28T02:59:59.999Z' };
test('empty news and IOC exports never produce a header-only Excel', () => {
  assert.throws(() => buildNewsExcelWorkbook({ dataset: 'news', range, rows: [] }, Excel), /Nenhuma notícia encontrada/);
  assert.throws(() => buildNewsExcelWorkbook({ dataset: 'iocs', range, rows: [] }, Excel), /Nenhum IOC encontrado/);
});
test('news Excel serializes every publication and the selected local-day period', async () => {
  const rows = [{ title: 'Security report', url: 'https://research.example/current', date: '2026-11-25T12:00:00Z' }];
  const workbook = buildNewsExcelWorkbook({ dataset: 'news', range, rows }, Excel);
  const restored = new Excel.Workbook();
  await restored.xlsx.load(await workbook.xlsx.writeBuffer());
  const publications = restored.getWorksheet('Publicações')!;
  assert.equal(publications.rowCount, 2);
  assert.equal(publications.getCell('A2').value, rows[0].title);
  assert.equal(publications.getCell('C2').value, rows[0].url);
  assert.equal(restored.getWorksheet('Resumo')!.getCell('B5').value, 1);
  assert.equal(restored.getWorksheet('Resumo')!.getCell('B4').value, range.to);
});
