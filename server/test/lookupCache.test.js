import test from 'node:test';
import assert from 'node:assert/strict';
import { createLookupCache } from '../lookupCache.js';

const key = { provider: 'provider', query: '9.9.9.10', owner: 'user', credentials: ['test-key'] };

test('fifty simultaneous reads use one upstream call, cache copies stay independent', async () => {
    const cache = createLookupCache(); let calls = 0;
    const load = async () => { calls++; await new Promise(resolve => setImmediate(resolve)); return { data: { ips: ['9.9.9.10'] } }; };
    const replies = await Promise.all(Array.from({ length: 50 }, () => cache.get(key, load)));
    assert.equal(calls, 1); assert.equal(replies.filter(row => row.state === 'shared').length, 49);
    const hit = await cache.get(key, load); hit.value.data.ips.push('other');
    assert.deepEqual((await cache.get(key, load)).value.data.ips, ['9.9.9.10']);
    assert.equal(calls, 1); assert.equal(cache.stats().coalesced, 49);
    assert.ok(!JSON.stringify(cache.stats()).includes('test-key'));
});

test('credentials, accounts, provider and case-sensitive URL paths isolate cached answers', async () => {
    const cache = createLookupCache(); let calls = 0;
    const load = async () => ({ data: { call: ++calls } });
    for (const request of [key, { ...key, credentials: ['rotated-key'] }, { ...key, owner: 'other' }, { ...key, provider: 'other' }, { ...key, query: 'https://example.com/Case' }, { ...key, query: 'https://example.com/case' }]) await cache.get(request, load);
    assert.equal(calls, 6);
});

test('expiry and explicit refresh fetch again, failed refreshes are never cached', async () => {
    let time = 0, calls = 0;
    const cache = createLookupCache({ now: () => time, ttlMs: 100 });
    const load = async () => ({ data: { revision: ++calls } });
    await cache.get(key, load); time = 101;
    assert.equal((await cache.get(key, load)).value.data.revision, 2);
    assert.equal((await cache.get({ ...key, fresh: true }, load)).value.data.revision, 3);
    await assert.rejects(cache.get({ ...key, fresh: true }, async () => { throw new Error('upstream failed'); }));
    assert.equal((await cache.get(key, load)).value.data.revision, 3);
    const empty = createLookupCache();
    const invalid = async () => ({ data: { query_status: 'invalid_auth_key' } });
    await empty.get(key, invalid); await empty.get(key, invalid);
    assert.equal(empty.stats().entries, 0); assert.equal(empty.stats().misses, 2);
});

test('cache bounds memory and pending calls without dropping a running lookup', async () => {
    const cache = createLookupCache({ maxPending: 1, maxEntries: 1, maxBytes: 1000 });
    let release;
    const flight = cache.get(key, () => new Promise(resolve => { release = resolve; }));
    await Promise.resolve();
    await assert.rejects(cache.get({ ...key, query: 'other' }, async () => ({ data: {} })), error => error.response.status === 503);
    release({ data: { a: 1 } }); await flight;
    await cache.get({ ...key, query: 'other' }, async () => ({ data: { b: 2 } }));
    assert.equal(cache.stats().entries, 1);
    await cache.get({ ...key, query: 'large' }, async () => ({ data: { text: 'x'.repeat(2000) } }));
    assert.equal(cache.stats().entries, 1); assert.ok(cache.stats().bytes <= 1000);
});
