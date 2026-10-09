import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { canonicalArticleUrl, createFeedCache, createFeedCollector, singleFlightRefresh } from '../feedCollector.js';
import { parseFeed } from '../feedParse.js';

const NOW = new Date('2026-10-09T12:00:00Z');
const feed = { url: 'https://vendor.example/rss', source: 'Vendor', layer: 3, weight_boost: 10 };
const xml = (title = 'Gateway advisory', link = '/Post?utm_source=rss', date = NOW.toISOString()) =>
    '<rss><channel><item><title>' + title + '</title><link>' + link.replaceAll('&', '&amp;') + '</link><pubDate>' + date + '</pubDate><description>Security research</description></item></channel></rss>';
const memoryCache = () => {
    const state = new Map();
    return { get: (key) => structuredClone(state.get(key)), set: (key, value) => state.set(key, structuredClone(value)) };
};

test('canonical URL removes tracking while retaining path case and meaningful query values', () => {
    assert.equal(canonicalArticleUrl('https://Vendor.example/Post?utm_source=x&id=ABC&fbclid=y#top'), 'https://vendor.example/Post?id=ABC');
    assert.notEqual(canonicalArticleUrl('https://vendor.example/Post'), canonicalArticleUrl('https://vendor.example/post'));
    assert.equal(canonicalArticleUrl('javascript:alert(1)'), null);
    assert.equal(canonicalArticleUrl('', feed.url), null);
});

test('RSS cache survives restart, sends validators and keeps items on 304 or outage', async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'feed-cache-'));
    const createCache = () => createFeedCache({ directory, fs, writeJsonAtomic: (file, value) => fs.writeFileSync(file, JSON.stringify(value)) });
    let phase = 0;
    const request = async (_, options) => {
        if (phase === 0) return { status: 200, headers: { etag: '"v1"', 'last-modified': 'Thu, 08 Oct 2026 12:00:00 GMT' }, data: xml() };
        assert.equal(options.headers['If-None-Match'], '"v1"');
        assert.ok(options.headers['If-Modified-Since']);
        if (phase === 1) return { status: 304 };
        throw new Error('503 unavailable');
    };
    const make = () => createFeedCollector({ request, parse: parseFeed, cache: createCache(), now: () => NOW });
    const first = await make().collect([feed]);
    phase++;
    const unchanged = await make().collect([feed]);
    assert.equal(unchanged.items[0].link, first.items[0].link);
    assert.equal(unchanged.health.get(feed.url).status, 'unchanged');
    phase++;
    const failed = await make().collect([feed]);
    assert.equal(failed.items.length, 1);
    assert.equal(failed.items[0].collectionStatus, 'stale');
    assert.equal(failed.health.get(feed.url).ok, false);
    assert.equal(failed.health.get(feed.url).lastSuccessfulAt, NOW.toISOString());
    assert.match(fs.readdirSync(directory)[0], /^[a-f0-9]{64}\.json$/);
});

test('HTML/WAF and unexpected 304 do not erase a successful snapshot', async () => {
    const cache = memoryCache();
    let data = xml();
    const collector = createFeedCollector({ cache, parse: parseFeed, now: () => NOW, request: async () => ({ status: 200, data }) });
    await collector.collect([feed]);
    data = '<html><body>Access denied</body></html>';
    const failed = await collector.collect([feed]);
    assert.equal(failed.items.length, 1);
    assert.equal(failed.health.get(feed.url).status, 'stale');
    const cold = createFeedCollector({ cache: memoryCache(), parse: parseFeed, now: () => NOW, request: async () => ({ status: 304 }) });
    assert.equal((await cold.collect([feed])).health.get(feed.url).ok, false);
});

test('rolling snapshot retains publications omitted by the current RSS and stable inferred dates', async () => {
    let now = NOW;
    let data = xml('Missing date', '/a', 'invalid date');
    const collector = createFeedCollector({ cache: memoryCache(), parse: parseFeed, now: () => now, request: async () => ({ status: 200, data }) });
    const first = await collector.collect([feed]);
    now = new Date(NOW.getTime() + 86400000);
    const second = await collector.collect([feed]);
    assert.equal(second.items[0].pubDate, first.items[0].pubDate);
    data = xml('New report', '/b', now.toISOString());
    assert.equal((await collector.collect([feed])).items.length, 2);
    now = new Date(NOW.getTime() + 32 * 86400000);
    data = '<rss><channel></channel></rss>';
    assert.equal((await collector.collect([feed])).items.length, 0);
});

test('feed requests respect concurrency and one failed source does not stop the others', async () => {
    let active = 0, peak = 0;
    const feeds = Array.from({ length: 8 }, (_, i) => ({ ...feed, url: feed.url + i }));
    const collector = createFeedCollector({
        cache: memoryCache(), parse: parseFeed, now: () => NOW, concurrency: 2,
        request: async (url) => {
            active++; peak = Math.max(peak, active);
            await new Promise((resolve) => setImmediate(resolve)); active--;
            if (url.endsWith('0')) throw new Error('timeout');
            return { status: 200, data: xml() };
        },
    });
    const result = await collector.collect(feeds);
    assert.equal(peak, 2);
    assert.equal(result.items.length, 7);
    assert.equal([...result.health.values()].filter((health) => health.ok).length, 7);
});

test('concurrent refreshes coalesce and source edits queue one additional cycle', async () => {
    let release, calls = 0;
    const refresh = singleFlightRefresh(async () => {
        calls++;
        if (calls === 1) await new Promise((resolve) => { release = resolve; });
    });
    const first = refresh();
    assert.equal(refresh(), first);
    assert.equal(refresh({ force: true }), first);
    refresh({ force: true });
    release();
    await first;
    assert.equal(calls, 2);
    await refresh();
    assert.equal(calls, 3);
});

test('a rejected refresh releases the lock for subsequent cycles', async () => {
    let calls = 0;
    const refresh = singleFlightRefresh(async () => { if (++calls === 1) throw new Error('disk'); });
    await assert.rejects(refresh(), /disk/);
    await refresh();
    assert.equal(calls, 2);
});
