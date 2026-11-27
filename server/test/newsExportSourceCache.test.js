import test from 'node:test';
import assert from 'node:assert/strict';
import { createNewsExportSourceCache } from '../newsExportSourceCache.js';
import { selectNewsExportPublications } from '../newsExportSelection.js';
import { newsExportRows, newsExportCsv } from '../newsExport.js';

test('an interrupted feed cycle exports enabled source caches by date and account, preserving authoritative rejections', async () => {
    const date = '2026-11-25T12:00:00Z';
    const item = (link, extra = {}) => ({ link, title: 'Update', text: 'Security vulnerability', source: 'Research', pubDate: date, ...extra });
    const pages = { enabled: { items: [item('new', { vendors: [{ id: 'microsoft' }] }), item('other'), item('rejected'),
        item('published'), item('old', { pubDate: '2026-11-09T12:00:00Z' }), item('irrelevant', { text: 'Music' })] } };
    const reads = [];
    const read = createNewsExportSourceCache({ getAsync: async key => { reads.push(key); return pages[key]; } });
    const sources = [{ url: 'enabled' }];
    const [sourceCache, same] = await Promise.all([read(sources), read(sources)]);
    assert.equal(sourceCache, same);
    assert.deepEqual(reads, ['enabled']);
    const options = { sourceCache, current: [], stories: [], from: '2026-11-20T03:00:00Z', to: '2026-11-28T02:59:59Z',
        archive: [item('rejected', { securityRelevant: false }), item('published', { cves: ['CVE-2026-12345'] })] };
    const exportFor = preferences => newsExportRows(selectNewsExportPublications({ ...options, preferences }).publications, 'news');
    const rows = exportFor({ mode: 'all' });
    assert.deepEqual(rows.map(row => row.url), ['new', 'other', 'published']);
    assert.equal(rows[0].analysisStatus, 'Análise pendente');
    assert.equal(rows[2].analysisStatus, undefined);
    assert.deepEqual(rows[2].cves, ['CVE-2026-12345']);
    assert.match(newsExportCsv(rows, 'news'), /Análise pendente/);
    assert.deepEqual(exportFor({ mode: 'selected', vendorIds: ['microsoft'] }).map(row => row.url), ['new']);
    assert.deepEqual(await read([]), []);
});
