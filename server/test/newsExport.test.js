import test from 'node:test';
import assert from 'node:assert/strict';
import { newsExportQuery, newsExportRows, newsExportCsv } from '../newsExport.js';

test('export validates dates and includes the entire final day', () => {
    assert.deepEqual(newsExportQuery({ from: '2026-10-01', to: '2026-10-13' }), { from: '2026-10-01T00:00:00.000Z', to: '2026-10-13T23:59:59.999Z', dataset: 'news', format: 'csv' });
    for (const query of [{}, { from: '2026-02-30', to: '2026-10-13' }, { from: '2026-10-13', to: '2026-10-12' }, { from: '2026-10-01', to: '2026-10-13', format: 'xlsx' }, { from: '2026-10-01', to: '2026-10-13', dataset: '../other' }]) assert.throws(() => newsExportQuery(query), { status: 400 });
    assert.equal(newsExportQuery({ from: '2026-10-13T03:00:00.000Z', to: '2026-10-14T02:59:59.999Z' }).to, '2026-10-14T02:59:59.999Z');
});

test('IOC export deduplicates within each source while preserving independent evidence and date provenance', () => {
    const publication = { title: 'Report', link: 'https://example.com/a', source: 'Research', pubDate: '2026-10-13T12:00:00Z', dateInferred: true, actors: [{ name: 'Actor' }], malware: [{ name: 'Family' }], iocs: { ips: ['9.9.9.10', '9.9.9.10'], domains: ['example.net'], hashes: ['a'.repeat(64)], urls: ['https://example.net/payload'] } };
    const rows = newsExportRows([publication, publication, { ...publication, link: 'https://example.com/b', source: 'News', dateInferred: false }], 'iocs');
    assert.equal(rows.length, 8);
    assert.deepEqual(rows.map(row => row.type), ['ip', 'domain', 'hash', 'url', 'ip', 'domain', 'hash', 'url']);
    assert.equal(rows[0].dateBasis, 'collected'); assert.equal(rows[4].dateBasis, 'published');
    assert.deepEqual(rows[0].actors, ['Actor']); assert.deepEqual(rows[0].malware, ['Family']);
    const news = newsExportRows([publication], 'news');
    assert.equal(news.length, 1); assert.ok(news[0].ips.length);
});

test('CSV escapes untrusted headlines and quotes without losing Unicode or multiline text', () => {
    const csv = newsExportCsv([{ title: ' =HYPERLINK("bad")', source: 'Pesquisa\nOT', categories: ['OT/ICS'] }], 'news');
    assert.ok(csv.startsWith('\uFEFF')); assert.ok(csv.includes('"\' =HYPERLINK(""bad"")"')); assert.ok(csv.includes('"Pesquisa\nOT"'));
    assert.equal(newsExportCsv([], 'iocs').split('\r\n').length, 2);
});
