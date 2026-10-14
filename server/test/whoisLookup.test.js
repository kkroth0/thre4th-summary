import test from 'node:test';
import assert from 'node:assert/strict';
import { createWhoisLookup, normalizeWhois } from '../whoisLookup.js';

const record = { domain: 'example.com', registrar: 'Example Registrar', snapshot_time: '2026-10-08', statuses: ['ok'], events: [{ event_action: 'registration', event_date: '2000-01-01' }, { event_action: 'expiration', event_date: '2027-01-01' }], nameservers: [{ ldh_name: 'ns.example.com' }], contacts: { registrant: { email: 'private@example.com' } } };

test('Who.is metadata preserves registrar, events, nameservers and snapshot without leaking contacts', () => {
    const result = normalizeWhois(record);
    assert.equal(result.source, 'Who.is');
    assert.equal(result.WhoisRecord.createdDate, '2000-01-01');
    assert.equal(result.WhoisRecord.expiresDate, '2027-01-01');
    assert.deepEqual(result.WhoisRecord.nameServers, ['ns.example.com']);
    assert.equal(result.WhoisRecord.snapshotTime, '2026-10-08');
    assert.ok(!JSON.stringify(result).includes('private@example.com'));
    assert.throws(() => normalizeWhois({}));
});

test('Who.is uses bearer authentication, snapshot endpoint and single-flight cache', async () => {
    const calls = [];
    const lookup = createWhoisLookup({ getKey: () => 'wis_test_secret', now: () => 0, http: { get: async (url, config) => { calls.push({ url, config }); return { data: record }; } } });
    await Promise.all([lookup('example.com'), lookup('example.com')]);
    await lookup('example.com');
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, 'https://api.who.is/v1/whois/example.com');
    assert.deepEqual(calls[0].config.headers, { Authorization: 'Bearer wis_test_secret' });
    assert.equal(calls[0].config.maxRedirects, 0);
    assert.equal(calls[0].config.params, undefined, 'no paid live refresh or credentials in query');
});

test('missing Who.is key fails before contacting a provider', async () => {
    const lookup = createWhoisLookup({ getKey: () => '', http: { get: () => assert.fail('must not call upstream') } });
    await assert.rejects(lookup('example.com'), /key missing/);
});

test('manual refresh and credential rotation cannot reuse an older WHOIS snapshot', async () => {
    let key = 'old-test-key', calls = 0;
    const lookup = createWhoisLookup({ getKey: () => key, http: { get: async () => { calls++; return { data: record }; } } });
    await lookup('example.com'); await lookup('example.com'); assert.equal(calls, 1);
    await lookup('example.com', { fresh: true }); assert.equal(calls, 2);
    key = 'rotated-test-key'; await lookup('example.com'); assert.equal(calls, 3);
});

test('WHOIS quota is observed only on real requests, never replayed from cached snapshots', async () => {
    const observed = [];
    const lookup = createWhoisLookup({ getKey: () => 'test-key', onQuota: (headers, key) => observed.push([headers, key]),
        http: { get: async () => ({ data: record, headers: { 'x-ratelimit-remaining': '490' } }) },
    });
    await lookup('example.com'); await lookup('example.com');
    assert.deepEqual(observed, [[{ 'x-ratelimit-remaining': '490' }, 'test-key']]);
});
