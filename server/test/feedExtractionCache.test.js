import test from 'node:test';
import assert from 'node:assert/strict';
import { createFeedExtractionCache } from '../feedExtractionCache.js';
import { enrichFeedItems, enrichFeedItemsAsync, applyVulnerabilityContext } from '../feedEnrichment.js';
import { buildActorIndex, matchActors } from '../actorMatch.js';
import { buildMalwareIndex, matchMalware } from '../malwareMatch.js';
import { buildCampaignIndex, matchCampaigns } from '../campaignMatch.js';
import { categorize } from '../newsCategories.js';

const raw = (extra = {}) => ({ link: 'https://lab.example/report', title: 'APT28 malware campaign',
    text: 'APT28 deployed Emotet malware in Operation Dream Job. CVE-2026-12345. Contact 193.143.1.131.',
    description: 'Threat research', layer: 3, source: 'Lab', weight_boost: 10, pubDate: '2026-10-15T12:00:00Z', ...extra });
const actorIndex = buildActorIndex([{ id: 'a1', name: 'APT28', aliases: ['Fancy Bear'] }]);
const malwareIndex = buildMalwareIndex([{ id: 'm1', name: 'Emotet', aliases: ['Geodo'] }]);
const campaignIndex = buildCampaignIndex([{ id: 'c1', name: 'Operation Dream Job', aliases: [] }]);
const options = () => ({ actors: text => matchActors(text, actorIndex), malware: text => matchMalware(text, malwareIndex, { news: true }),
    campaigns: text => matchCampaigns(text, campaignIndex), seller: () => null, categorize });

test('warm extraction preserves real entity/IOC evidence, updates collection telemetry and never caches KEV/EPSS boosts', async () => {
    const extractionCache = createFeedExtractionCache();
    const config = { ...options(), extractionCache, catalogRevision: 'catalog-1' };
    const source = raw({ collectedAt: 'old', collectionStatus: 'fresh', articleCollectionStatus: 'fresh' });
    const expected = enrichFeedItems([source], options());
    const cold = await enrichFeedItemsAsync([source], config);
    assert.deepEqual(cold, expected);
    assert.equal(cold[0].actors[0].id, 'a1'); assert.equal(cold[0].malware[0].id, 'm1');
    assert.equal(cold[0].campaigns[0].id, 'c1'); assert.deepEqual(cold[0].iocs.ips, ['193.143.1.131']);
    applyVulnerabilityContext(cold, new Map([['CVE-2026-12345', { ransomware: true }]]), new Map([['CVE-2026-12345', .8]]));
    cold[0].iocs.ips.push('91.92.241.210'); delete cold[0].text;
    const fresh = raw({ collectedAt: 'new', collectionStatus: 'stale' });
    const warm = await enrichFeedItemsAsync([fresh], config);
    assert.equal(warm[0].actors[0].name, 'APT28');
    assert.equal(warm[0].score, expected[0].score); assert.equal(warm[0].kev, undefined); assert.equal(warm[0].epss, undefined);
    assert.equal(warm[0].reasons.some(value => value.includes('CISA KEV')), false);
    assert.deepEqual(warm[0].iocs.ips, ['193.143.1.131']); assert.equal(warm[0].collectedAt, 'new');
    assert.equal(warm[0].collectionStatus, 'stale'); assert.equal(Object.hasOwn(warm[0], 'articleCollectionStatus'), false);
    applyVulnerabilityContext(warm, new Map(), new Map([['CVE-2026-12345', 0]]));
    assert.equal(warm[0].epss, 0);
    warm[0].reasons.push('another caller mutation'); warm[0].actors[0].name = 'caller edit';
    assert.equal(enrichFeedItems([fresh], config)[0].reasons.includes('another caller mutation'), false);
    assert.equal(extractionCache.stats().hits, 2); assert.equal(extractionCache.stats().misses, 1);
});

test('body, appendix IOCs, source rules, repository evidence and catalog changes each invalidate cached extraction', () => {
    const extractionCache = createFeedExtractionCache();
    const source = raw();
    const texts = new Map(), supplementalIocs = new Map();
    const config = { ...options(), extractionCache, catalogRevision: 'catalog-1', texts, supplementalIocs };
    const read = (item = source, settings = config) => enrichFeedItems([item], settings);
    read(); read(); assert.equal(extractionCache.stats().hits, 1);
    texts.set(source.link, 'New malware infrastructure at 91.92.241.210.');
    assert.ok(read()[0].iocs.ips.includes('91.92.241.210'));
    supplementalIocs.set(source.link, { hashes: ['a'.repeat(64)] });
    assert.deepEqual(read()[0].iocs.hashes, ['a'.repeat(64)]);
    supplementalIocs.set(source.link, { hashes: ['b'.repeat(64)] });
    assert.deepEqual(read()[0].iocs.hashes, ['b'.repeat(64)]);
    const changed = raw({ title: 'New Emotet campaign', weight_boost: 0, sourceCategories: ['OT/ICS'] });
    assert.ok(read(changed)[0].newsCategories.includes('OT/ICS'));
    const renewed = { ...config, catalogRevision: 'catalog-2', actors: () => [{ id: 'a2', name: 'New actor' }] };
    assert.equal(read(changed, renewed)[0].actors[0].id, 'a2');
    const repository = raw({ repositoryReport: true, repository: { repo: 'PaloAltoNetworks/Unit42-timely-threat-intel' },
        text: "A malware family we named ExampleAgent", iocs: { ips: ['1.1.1.1'] } });
    assert.equal(read(repository)[0].malware[0].name, 'ExampleAgent');
    assert.deepEqual(read({ ...repository, iocs: { ips: ['4.2.2.2'] } })[0].iocs.ips, ['4.2.2.2']);
    const expected = enrichFeedItems([{ ...repository, iocs: { ips: ['4.2.2.2'] } }], { ...config, extractionCache: undefined });
    assert.deepEqual(read({ ...repository, iocs: { ips: ['4.2.2.2'] } }), expected);
    assert.equal(extractionCache.stats().misses, 8);
});

test('cached empty/no-IOC results do not skip a newly relevant article or newly collected IOC evidence', () => {
    const extractionCache = createFeedExtractionCache(), config = { ...options(), extractionCache, catalogRevision: '1' };
    const irrelevant = raw({ title: 'A quiet afternoon', text: 'A walk through the countryside.', description: '' });
    assert.deepEqual(enrichFeedItems([irrelevant], config), []);
    assert.deepEqual(enrichFeedItems([irrelevant], config), []);
    const ai = { ...irrelevant, title: 'Artificial intelligence model prompt injection' };
    assert.equal(enrichFeedItems([ai], config).length, 1);
    const source = raw({ title: 'Malware technical report', text: 'Analysis of a new malware attack.' });
    assert.deepEqual(enrichFeedItems([source], config)[0].iocs.ips, []);
    const update = { ...config, texts: new Map([[source.link, 'Malware uses 193.143.1.132.']]) };
    assert.deepEqual(enrichFeedItems([source], update)[0].iocs.ips, ['193.143.1.132']);
    assert.equal(extractionCache.stats().hits, 1);
});

test('canonical input order is reusable but real metadata/rule revisions and absent catalog revision cannot use an old result', () => {
    const extractionCache = createFeedExtractionCache(), identity = { extractionVersion: 'v1', catalogRevision: 'a' };
    let computes = 0;
    const compute = () => ({ value: ++computes, optional: undefined });
    const source = raw({ repository: { sha: 'a', repo: 'lab/reports' } });
    const first = extractionCache.extract(source, identity, compute);
    assert.deepEqual(extractionCache.extract({ ...source, repository: { repo: 'lab/reports', sha: 'a' } }, identity, compute), first);
    extractionCache.extract({ ...source, pubDate: '2026-10-15T12:01:00Z' }, identity, compute);
    extractionCache.extract(source, { ...identity, extractionVersion: 'v2' }, compute);
    extractionCache.extract(source, {}, compute);
    assert.equal(computes, 4); assert.equal(extractionCache.stats().bypassed, 1);
});

test('LRU entry/serialized-byte limits evict evidence safely and failed extraction is retried', () => {
    const cache = createFeedExtractionCache({ maxEntries: 2, maxBytes: 1000 });
    const identity = { extractionVersion: '1', catalogRevision: '1' };
    let computes = 0;
    const read = (link, value = 'small') => cache.extract({ link }, identity, () => ({ value, count: ++computes }));
    read('a'); read('b'); read('a'); read('c'); read('a');
    assert.equal(computes, 3); assert.equal(cache.stats().entries, 2);
    read('b'); assert.equal(computes, 4); assert.equal(cache.stats().evictions, 2);
    read('huge', 'x'.repeat(2000)); read('huge', 'x'.repeat(2000));
    assert.equal(computes, 6); assert.ok(cache.stats().bytes <= 1000);
    assert.throws(() => cache.extract({ link: 'failed' }, identity, () => { throw Error('retry me'); }), /retry me/);
    assert.equal(read('failed').value, 'small');
    const disabled = createFeedExtractionCache({ maxEntries: 0 });
    disabled.extract({ link: 'a' }, identity, () => null);
    assert.equal(disabled.stats().entries, 0);
});
