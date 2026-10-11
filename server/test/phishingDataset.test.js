import test from 'node:test';
import assert from 'node:assert/strict';
import { buildPhishingDataset, phishingQuery } from '../phishingDataset.js';

const row = (link, extra = {}) => ({ link: `https://example.com/${link}`, title: 'Phishing campaign uses fake Adobe login pages', description: 'Attackers target banks in Brazil and capture credentials.', source: 'Research', pubDate: '2026-10-08T23:59:00Z', ...extra });
test('correlated publications count once per group; identical techniques alone stay separate', () => {
    const a = row('a', { storyId: 'one' });
    const data = buildPhishingDataset([a, row('b', { storyId: 'one', source: 'News' }), row('c'), a, row('d', { title: 'Router vulnerability', description: 'Apply patches.' })]);
    assert.equal(data.summary.publications, 3);
    assert.equal(data.summary.groups, 2);
    assert.equal(data.summary.correlatedGroups, 1);
    assert.equal(data.campaigns[0].sources.length, 2);
    assert.equal(data.campaigns.reduce((sum, group) => sum + group.reportCount, 0), data.reports.length);
    assert.equal(data.summary.sources.reduce((sum, source) => sum + source.count, 0), data.reports.length);
});
test('named campaign must occur explicitly; ambiguous catalogue matches cannot merge reports', () => {
    const match = { id: 'c', name: 'Operation Example' };
    const data = buildPhishingDataset([row('a', { title: 'Operation Example phishing campaign', campaigns: [match] }), row('b', { title: 'Operation Example phishing wave', campaigns: [match] }), row('c', { campaigns: [match] })]);
    assert.equal(data.campaigns.length, 2);
    assert.equal(data.campaigns[0].basis, 'named-campaign');
    assert.equal(data.campaigns[1].basis, 'publication');
});
test('filters, profile reasons and counts reflect only selected publications', () => {
    const profiles = [{ id: 'finance', name: 'Finance', sectors: ['Financial'], regions: ['Latin America'], assets: [], brands: [], actors: [] }, { id: 'energy', name: 'Energy', sectors: ['Energy'] }];
    const data = buildPhishingDataset([row('a'), row('b', { description: 'Attackers target hospitals in Japan.' })], { profiles, filters: { region: 'LATAM', profileId: 'finance', brand: 'Adobe' } });
    assert.equal(data.total, 1);
    assert.equal(data.summary.brazil, 1);
    assert.deepEqual(data.reports[0].profileMatches[0].reasons, ['Setor: Financial', 'Região: Latin America']);
    assert.equal(data.reports[0].profileMatches.some(match => match.profileId === 'energy'), false);
});
test('pinned actors, exact product boundaries and partial content do not invent attribution', () => {
    const data = buildPhishingDataset([row('a', { actors: [{ id: 'actor', name: 'Example actor' }] })], { profiles: [{ id: 'org', name: 'Org', assets: [{ product: 'Ad' }], actors: ['actor'] }] });
    assert.deepEqual(data.reports[0].profileMatches[0].reasons, ['Ator acompanhado']);
    assert.equal(data.reports[0].nationState, 'unknown');
});
test('MITRE aggregates reconcile citations and inferences without duplicates', () => {
    const data = buildPhishingDataset([row('a', { description: 'Attackers use fake login pages; T1056.003.' }), row('b')], { techniqueCatalog: [{ id: 'T1056.003', name: 'Web Portal Capture', tactics: ['Credential Access'] }] });
    const ttp = data.ttps.find(row => row.id === 'T1056.003');
    assert.equal(ttp.reports, 2);
    assert.equal(ttp.reported, 1);
    assert.equal(ttp.inferred, 1);
    assert.equal(ttp.name, 'Web Portal Capture');
});
test('truncation is explicit and query dates are strict, inclusive bounds prepared by route', () => {
    assert.equal(buildPhishingDataset([row('a'), row('b')], { limit: 1 }).truncated, true);
    assert.deepEqual(phishingQuery({ from: '2026-08-01', to: '2026-10-08' }).range, { from: '2026-08-01', to: '2026-10-08' });
    for (const query of [{ from: 'bad' }, { from: '2026-02-30' }, { to: '2026-13-01' }, { from: '2026-10-08', to: '2026-08-01' }]) assert.throws(() => phishingQuery(query), error => error.status === 400);
});
