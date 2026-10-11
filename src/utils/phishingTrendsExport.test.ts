import assert from 'node:assert/strict';
import test from 'node:test';
import { createRequire } from 'node:module';
import type { PhishingDataset } from '@/services/threatApi';
import { buildPhishingDataset } from '../../server/phishingDataset.js';
import { buildPhishingTrendsWorkbook, phishingTrendsExcelFilename } from './phishingTrendsExport';

const ExcelJS = createRequire(`${process.cwd()}/package.json`)('exceljs') as typeof import('exceljs');
const rows = [
    { link: 'https://example.com/a', title: 'ClickFix phishing campaign uses fake Adobe login pages', description: 'Attackers target banks in Brazil, T1204.004.', source: 'Research', pubDate: '2026-10-08T23:59:00Z', storyId: 'same-event' },
    { link: 'https://example.com/b', title: 'ClickFix phishing targets banks', description: 'The campaign targets banks in Brazil using fake login pages to capture credentials.', source: 'News', pubDate: '2026-10-07T12:00:00Z', storyId: 'same-event' },
    { link: 'https://example.com/c', title: 'Smishing campaign targets hospitals in Japan', source: 'News', pubDate: '2026-09-01T00:00:00Z' },
];
const dataset = (filters = {}, profiles = []): PhishingDataset => buildPhishingDataset(rows, {
    filters, profiles, range: { from: '2026-08-01', to: '2026-10-08' },
    techniqueCatalog: [{ id: 'T1204.004', name: 'Malicious Copy and Paste', tactics: ['Execution'] }],
});
const value = (wb: import('exceljs').Workbook, sheet: string, row: number, col: number) => wb.getWorksheet(sheet)!.getRow(row).getCell(col).value;

test('reference structure exports publications, campaigns, sources, TTPs and regional cuts', () => {
    const wb = buildPhishingTrendsWorkbook(dataset(), ExcelJS);
    assert.deepEqual(wb.worksheets.map(sheet => sheet.name), ['Resumo', 'Reports', 'Campanhas', 'TTPs', 'Fontes', 'Brasil', 'Latam', 'Premissas recortes']);
    assert.equal(wb.getWorksheet('Reports')!.rowCount, 4);
    assert.equal(wb.getWorksheet('Campanhas')!.rowCount, 3);
    assert.equal(wb.getWorksheet('Brasil')!.rowCount, 3);
    assert.equal(wb.getWorksheet('Latam')!.rowCount, 3);
    assert.equal(value(wb, 'Resumo', 4, 2), 3);
    assert.equal(value(wb, 'Resumo', 5, 2), 2);
    assert.equal(value(wb, 'Campanhas', 2, 5), 2);
    assert.equal(value(wb, 'Fontes', 2, 2), 2);
    assert.equal(value(wb, 'Reports', 1, 23), 'Recortes (abas)');
    assert.match(String(value(wb, 'Reports', 2, 25)), /ClickFix \[title\]/);
    assert.match(String(value(wb, 'Reports', 2, 26)), /T1204.004: Citado/);
});
test('filtered workbook totals and cuts reconcile and exclude publications outside selection', () => {
    const wb = buildPhishingTrendsWorkbook(dataset({ region: 'Brazil' }), ExcelJS);
    assert.equal(value(wb, 'Resumo', 4, 2), 2);
    assert.equal(value(wb, 'Resumo', 5, 2), 1);
    assert.equal(wb.getWorksheet('Reports')!.rowCount, 3);
    assert.equal(wb.getWorksheet('Campanhas')!.rowCount, 2);
    assert.equal(wb.getWorksheet('Fontes')!.getColumn(2).values.slice(2).reduce<number>((sum, value) => sum + Number(value), 0), 2);
});
test('dates survive XLSX roundtrip as dates, headers are frozen and data remain uncoloured', async () => {
    const wb = buildPhishingTrendsWorkbook(dataset(), ExcelJS);
    assert.equal(value(wb, 'Reports', 2, 2) instanceof Date, true);
    assert.equal((value(wb, 'Reports', 2, 4) as Date).toISOString(), '2026-10-05T00:00:00.000Z');
    const sheet = wb.getWorksheet('Reports')!;
    assert.equal(sheet.getCell('B2').numFmt, 'yyyy-mm-dd');
    assert.deepEqual(sheet.views, [{ state: 'frozen', ySplit: 1 }]);
    assert.ok(sheet.autoFilter);
    assert.equal(sheet.getCell('E2').fill, undefined);
    const restored = new ExcelJS.Workbook();
    await restored.xlsx.load(await wb.xlsx.writeBuffer());
    assert.equal((restored.getWorksheet('Reports')!.getCell('B2').value as Date).toISOString(), '2026-10-08T23:59:00.000Z');
});
test('organization cuts use only supplied profiles with explicit relevance reasons and valid unique sheet names', () => {
    const profiles = [{ id: 'one', name: 'Reports/?', sectors: ['Financial'] }, { id: 'two', name: 'reports/?', sectors: ['Financial'] }];
    const wb = buildPhishingTrendsWorkbook(dataset({}, profiles), ExcelJS);
    const cuts = wb.worksheets.filter(sheet => sheet.name.startsWith('Org -'));
    assert.equal(cuts.length, 2);
    assert.notEqual(cuts[0].name.toLowerCase(), cuts[1].name.toLowerCase());
    assert.equal(cuts[0].rowCount, 3);
    assert.equal(cuts[0].getCell('AA2').value, 'Setor: Financial');
    assert.ok(wb.worksheets.every(sheet => sheet.name.length <= 31 && !/[\\/*?:[\]]/.test(sheet.name)));
});
test('unknown metadata and uncorrelated groups are clearly labelled', () => {
    const wb = buildPhishingTrendsWorkbook(dataset({ region: 'Japan' }), ExcelJS);
    assert.equal(value(wb, 'Reports', 2, 14), 'Não identificado');
    assert.equal(value(wb, 'Reports', 2, 15), 'Não identificado');
    assert.equal(value(wb, 'Reports', 2, 24), 'Publicação sem correlação confirmada');
});
test('empty datasets export an intact workbook and truncation is disclosed', () => {
    const wb = buildPhishingTrendsWorkbook(buildPhishingDataset([]), ExcelJS);
    assert.equal(wb.getWorksheet('Reports')!.rowCount, 1);
    const data = dataset(); data.truncated = true; data.total = 100;
    assert.match(String(value(buildPhishingTrendsWorkbook(data, ExcelJS), 'Resumo', 11, 2)), /3 de 100/);
});
test('filename preserves requested inclusive period', () => {
    assert.equal(phishingTrendsExcelFilename({ from: '2026-08-01', to: '2026-10-08' }), 'Campanhas_Phishing_2026-08-01_a_2026-10-08.xlsx');
    assert.match(phishingTrendsExcelFilename(), /^Campanhas_Phishing_\d{4}-\d{2}-\d{2}\.xlsx$/);
});
