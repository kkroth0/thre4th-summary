import test from 'node:test';
import assert from 'node:assert/strict';
import { createPhishingSources, matchOpenPhish, parseOpenPhishFeed, validatePhishTank } from '../phishingSources.js';

test('OpenPhish matches exact URLs and domain boundaries, never paths or lookalike hosts', () => {
    const urls = parseOpenPhishFeed('https://bad.example.com/login\nhttps://notexample.com/example.com\nhttps://other.test/example.com\n');
    assert.equal(matchOpenPhish(urls, 'example.com', 'domain'), true);
    assert.equal(matchOpenPhish(urls.slice(1), 'example.com', 'domain'), false);
    assert.equal(matchOpenPhish(urls, 'https://bad.example.com/log', 'url'), false);
    assert.equal(matchOpenPhish(urls, urls[0], 'url'), true);
    assert.throws(() => parseOpenPhishFeed('<html>Unavailable</html>'));
});

test('PhishStats uses the current API, sends credentials only in headers and caches bounded exact matches', async () => {
    const calls = [];
    const sources = createPhishingSources({ now: () => 0, getKey: () => 'psk_test_secret', http: { get: async (url, config) => {
        calls.push({ url, config });
        return { data: [{ url: 'https://example.com/login?a=(b,c)' }, { url: 'https://notexample.com/' }, { url: 'https://example.com/different' }] };
    } } });
    const query = 'https://example.com/login?a=(b,c)';
    assert.deepEqual(await sources.phishStats(query), [{ url: query }]);
    assert.equal(calls[0].url, 'https://api.phishstats.info/api/phishing');
    assert.deepEqual(calls[0].config.headers, { 'X-API-Key': 'psk_test_secret' });
    assert.equal(calls[0].config.params._where, '(url,like,example.com)');
    assert.equal(calls[0].config.maxRedirects, 0);
    await sources.phishStats(query); assert.equal(calls.length, 1);
    assert.equal(sources.activity().PhishStats.state, 'healthy');
    assert.ok(!JSON.stringify(sources.activity()).includes('psk_test_secret'));
    assert.ok(!JSON.stringify(sources.activity()).includes(query));
});

test('provider activity measures real validated responses, including malformed 200s and upstream failures', async () => {
    const sources = createPhishingSources({ now: () => 0, http: { get: async () => ({ data: '<html>Challenge</html>' }), post: async () => ({ data: { results: {} } }) } });
    assert.equal(sources.activity().PhishTank.state, 'unchecked');
    await assert.rejects(sources.phishStats('example.com'));
    await assert.rejects(sources.phishTank('https://example.com/'));
    assert.equal(sources.activity().PhishStats.state, 'failed');
    assert.equal(sources.activity().PhishTank.httpStatus, 502);
    assert.throws(() => validatePhishTank({ results: {} }));
    assert.deepEqual(validatePhishTank({ results: { in_database: false } }), { results: { in_database: false } });
});

test('concurrent OpenPhish lookups share one feed request and failed feed is never treated as empty', async () => {
    let calls = 0;
    const sources = createPhishingSources({ http: { get: async () => { calls++; return { data: 'https://bad.example.com/' }; } } });
    const responses = await Promise.all([sources.openPhish('example.com', 'domain'), sources.openPhish('other.test', 'domain')]);
    assert.equal(calls, 1); assert.equal(responses[0].listed, true); assert.equal(responses[1].listed, false);
    const failed = createPhishingSources({ http: { get: async () => { throw Object.assign(new Error('quota'), { response: { status: 429 } }); } } });
    await assert.rejects(failed.openPhish('example.com', 'domain'));
    assert.equal(failed.activity().OpenPhish.httpStatus, 429);
});
