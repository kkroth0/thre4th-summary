import test from 'node:test';
import assert from 'node:assert/strict';
import { createNewsFeedResponse } from '../newsFeedResponse.js';
import { newsExportRows } from '../newsExport.js';
import { selectNewsExportPublications } from '../newsExportSelection.js';

const from = '2026-11-20T03:00:00.000Z', to = '2026-11-28T02:59:59.999Z';
const preferences = { mode: 'all', vendorIds: [] };
const row = (link, over = {}) => ({ link, title: 'Security vulnerability report', source: 'Research', layer: 1,
    pubDate: '2026-11-25T12:00:00.000Z', categories: ['Vulnerabilities'], ...over });
const select = over => selectNewsExportPublications({ current: [], archive: [], stories: [], preferences, from, to, ...over });

test('weekly export retains publications visible in a restored feed before the archive is committed', () => {
    const current = [row('https://research.example/current')];
    const display = createNewsFeedResponse()({ current, archive: [], stories: [], owner: 'user', preferences });
    const exported = select({ current });
    assert.equal(JSON.parse(display.body).length, 1);
    assert.deepEqual(newsExportRows(exported.publications, 'news').map(item => item.url), ['https://research.example/current']);
    assert.equal(exported.evidence[0].link, current[0].link);
});

test('retained story sources recover missing publications without inheriting event-wide evidence or dates', () => {
    const stories = [{ id: 'event', lastSeen: '2026-11-25T00:00:00Z', cves: ['CVE-2026-99999'], iocs: { ips: ['9.9.9.9'] }, sources: [
        row('https://research.example/retained', { text: 'Retained original body' }),
        row('https://research.example/old', { pubDate: '2026-11-19T00:00:00Z' }),
    ] }];
    const { publications, evidence } = select({ stories });
    assert.equal(publications.length, 1); assert.equal(publications[0].storyId, 'event');
    assert.equal(publications[0].cves, undefined); assert.equal(publications[0].iocs, undefined);
    assert.equal(evidence[0].text, 'Retained original body');
    assert.equal(publications[0].text, undefined);
});

test('archive revisions take precedence, URLs are deduplicated and rejected publications stay excluded', () => {
    const link = 'https://research.example/shared';
    const current = [row(link, { cves: ['CVE-2026-10000'] }), row('https://research.example/rejected')];
    const archive = [row(link, { title: 'Corrected vulnerability report', cves: ['CVE-2026-10001'] }), row('https://research.example/rejected', { securityRelevant: false })];
    const { publications } = select({ current, archive, stories: [{ id: 'event', sources: [row(link)] }] });
    assert.equal(publications.length, 1); assert.equal(publications[0].title, 'Corrected vulnerability report');
    assert.deepEqual(publications[0].cves, ['CVE-2026-10001']);
});

test('whole local days include both boundaries and missing dates use the first collection with explicit provenance', () => {
    const current = [row('start', { pubDate: from }), row('end', { pubDate: to }),
        row('before', { pubDate: '2026-11-20T02:59:59.999Z' }), row('after', { pubDate: '2026-11-28T03:00:00.000Z' }),
        row('collected', { pubDate: '', firstCollectedAt: '2026-11-26T00:00:00Z' }),
        row('legacy', { pubDate: 'invalid', archivedAt: '2026-11-24T00:00:00Z' }), row('undated', { pubDate: '' })];
    const exported = newsExportRows(select({ current }).publications, 'news');
    assert.deepEqual(exported.map(item => item.url), ['end', 'collected', 'legacy', 'start']);
    assert.equal(exported.find(item => item.url === 'collected').dateBasis, 'collected');
    assert.equal(exported.find(item => item.url === 'legacy').dateBasis, 'collected');
    assert.equal(exported.find(item => item.url === 'start').dateBasis, 'published');
});

test('monitoring applies equally to live, archived and retained publications without leaking other evidence', () => {
    const microsoft = row('microsoft', { vendors: [{ id: 'microsoft' }], text: 'Microsoft source body' });
    const cisco = row('cisco', { vendors: [{ id: 'cisco' }], text: 'Cisco source body' });
    const limited = { mode: 'selected', vendorIds: ['microsoft'] };
    const result = select({ current: [microsoft], archive: [cisco], stories: [{ id: 'cisco-event', sources: [cisco] }], preferences: limited });
    assert.deepEqual(result.publications.map(item => item.link), ['microsoft']);
    assert.deepEqual(result.evidence.map(item => item.text), ['Microsoft source body']);
    assert.equal(select({ current: [microsoft], preferences: { mode: 'selected', vendorIds: [] } }).publications.length, 0);
});

test('weekly exports include every archived page and preserve source IOC evidence', () => {
    const archive = Array.from({ length: 5001 }, (_, index) => row(`https://research.example/${index}`, { iocs: { ips: [`192.0.2.${index % 254 + 1}`] } }));
    const { publications } = select({ archive });
    assert.equal(newsExportRows(publications, 'news').length, 5001);
    assert.equal(newsExportRows(publications, 'iocs').length, 5001);
    assert.equal(archive[0].storyId, undefined);
});
