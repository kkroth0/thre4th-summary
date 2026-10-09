import test from 'node:test';
import assert from 'node:assert/strict';
import { collectArticleTexts } from '../articleCollector.js';
import { enrichFeedItems, applyVulnerabilityContext } from '../feedEnrichment.js';
import { scoreArticle } from '../ctiIntel.js';
import { mergeIntoStories } from '../newsStories.js';
import { categorize } from '../newsCategories.js';

const NOW = new Date('2026-10-09T12:00:00Z');
const item = (extra = {}) => ({ title: 'Technical report', description: 'Research', pubDate: NOW.toISOString(), link: 'https://lab.example/report', layer: 3, text: 'Short RSS summary', weight_boost: 10, source: 'Lab', ...extra });
const cache = () => {
    const map = new Map();
    return { get: (key) => map.get(key), set: (key, value) => map.set(key, value) };
};
const enrich = (items, texts) => enrichFeedItems(items, { texts, actors: () => [], malware: () => [], campaigns: () => [], seller: () => null, categorize });

test('NetScaler: notícias de três fontes correlacionam após extrair CVE do corpo, mantendo outra falha separada', async () => {
    const raw = [
        item({ layer: 2, source: 'BleepingComputer', link: 'https://bleeping.example/citrix', title: 'Citrix warns admins to patch new NetScaler RCE flaw immediately' }),
        item({ layer: 2, source: 'The Hacker News', link: 'https://thn.example/citrix', title: 'Citrix Patches Critical NetScaler Flaw That Could Enable RCE in SAML Deployments', text: 'CVE-2026-107406 remote code execution' }),
        item({ layer: 2, source: 'SecurityWeek', link: 'https://sw.example/citrix', title: 'Citrix Urges Immediate Patching of Critical NetScaler Vulnerability', text: 'CVE-2026-107406 remote code execution' }),
        item({ layer: 2, source: 'Other', link: 'https://other.example/citrix', title: 'Citrix Urges Immediate Patching of Critical NetScaler Vulnerability', text: 'CVE-2026-88771 remote code execution' }),
    ];
    const bodies = await collectArticleTexts(raw, { cache: cache(), now: NOW,
        fetchText: async (link) => `${link.includes('other.example') ? 'CVE-2026-88771' : 'CVE-2026-107406'} remote code execution in Citrix NetScaler.`,
    });
    assert.equal(bodies.stats.fetched, 4, 'notícias layer 2 também recebem texto completo');
    const stories = mergeIntoStories([], enrich(raw, bodies.texts), NOW);
    assert.equal(stories.length, 2);
    const main = stories.find((story) => story.cves.includes('CVE-2026-107406'));
    assert.equal(main.sources.length, 3);
    assert.deepEqual(main.cves, ['CVE-2026-107406']);
    assert.equal(stories.find((story) => story.cves.includes('CVE-2026-88771')).sources.length, 1);
});

test('article body drives CVE, TTP, IOC extraction and KEV/EPSS before correlation', async () => {
    const raw = [item(), item({ source: 'News', link: 'https://news.example/coverage', layer: 2, title: 'Emergency advisory', text: 'CVE-2026-12345 actively exploited' })];
    const bodies = await collectArticleTexts(raw, { cache: cache(), now: NOW, fetchText: async () => 'CVE-2026-12345 remote code execution. PowerShell downloads malware from 193.143.1[.]131.' });
    const enriched = enrich(raw, bodies.texts);
    assert.deepEqual(enriched[0].cves, ['CVE-2026-12345']);
    assert.deepEqual(enriched[0].iocs.ips, ['193.143.1.131']);
    assert.ok(enriched[0].ttpIds.includes('T1059.001'));
    applyVulnerabilityContext(enriched, new Map([['CVE-2026-12345', { ransomware: true }]]), new Map([['CVE-2026-12345', 0.7]]));
    assert.equal(enriched[0].kev, true);
    assert.equal(enriched[0].epss, 0.7);
    const stories = mergeIntoStories([], enriched, NOW);
    assert.equal(stories.length, 1);
    assert.equal(stories[0].sources.length, 2);
    assert.match(stories[0].sources[0].contentHash, /^[a-f0-9]{64}$/);
});

test('reports without IOCs are cached, and a changed feed body invalidates the article cache', async () => {
    const storage = cache();
    let calls = 0;
    const options = { cache: storage, now: NOW, fetchText: async () => { calls++; return 'APT report without indicators'; } };
    const first = await collectArticleTexts([item()], options);
    const second = await collectArticleTexts([item()], options);
    assert.equal(calls, 1);
    assert.equal(first.texts.get(item().link), second.texts.get(item().link));
    await collectArticleTexts([item({ text: 'Summary updated with new evidence' })], options);
    assert.equal(calls, 2);
});

test('article failure is isolated, retry window prevents repeated empty fetches and budget advances', async () => {
    const storage = cache();
    const raw = [item({ link: 'https://lab.example/a' }), item({ link: 'https://lab.example/b' })];
    let calls = 0;
    const options = { cache: storage, now: NOW, maxFetches: 1, fetchText: async () => { calls++; throw new Error('403'); } };
    const first = await collectArticleTexts(raw, options);
    assert.equal(first.stats.failed, 1);
    assert.equal(first.stats.deferred, 1);
    await collectArticleTexts(raw, options);
    assert.equal(calls, 2, 'cached failed first article leaves budget for the next');
    await collectArticleTexts(raw, options);
    assert.equal(calls, 2, 'failed articles wait before retry');
});

test('full RSS content avoids a body download even when there are no IOCs', async () => {
    let calls = 0;
    const result = await collectArticleTexts([item({ text: 'content '.repeat(300) })], { cache: cache(), now: NOW, fetchText: async () => { calls++; return 'x'; } });
    assert.equal(calls, 0);
    assert.equal(result.stats.fetched, 0);
});

test('an expired body keeps its evidence while waiting for the next fetch budget', async () => {
    const storage = cache();
    await collectArticleTexts([item()], { cache: storage, now: NOW, fetchText: async () => 'CVE-2026-12345 exploited in the wild' });
    const nextDay = new Date(NOW.getTime() + 2 * 86400000);
    const deferred = await collectArticleTexts([item()], { cache: storage, now: nextDay, maxFetches: 0, fetchText: async () => { throw new Error('must not fetch'); } });
    assert.equal(deferred.stats.deferred, 1);
    assert.deepEqual(enrich([item()], deferred.texts)[0].cves, ['CVE-2026-12345']);
});

test('article downloads respect concurrency even with bad configuration', async () => {
    let active = 0, peak = 0;
    await collectArticleTexts(Array.from({ length: 6 }, (_, i) => item({ link: 'https://lab.example/' + i })), {
        cache: cache(), now: NOW, concurrency: 2,
        fetchText: async () => { active++; peak = Math.max(peak, active); await new Promise((resolve) => setImmediate(resolve)); active--; return 'body'; },
    });
    assert.equal(peak, 2);
});

test('function/announces do not match UNC and vendor/region alone cannot excuse webinar noise', () => {
    assert.ok(!scoreArticle('A new function improves application performance').categories.includes('Threat Group'));
    assert.ok(!scoreArticle('Microsoft announces a webinar in Brazil').categories.includes('Threat Group'));
    assert.equal(scoreArticle('Microsoft announces a webinar in Brazil', 15).score, 0);
    assert.ok(scoreArticle('UNC3886 compromises a gateway').categories.includes('Threat Group'));
    assert.ok(scoreArticle('Storm-0558 phishing campaign').categories.includes('Threat Group'));
});
