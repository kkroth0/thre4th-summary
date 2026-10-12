import test from 'node:test';
import assert from 'node:assert/strict';
import { domainTarget, normalizeSubdomains, normalizeCertificates, normalizeDnsHistory, createDomainIntelligence } from '../domainIntelligence.js';

test('registrable domains respect the public suffix list, IDNs and strict host validation', () => {
    assert.equal(domainTarget('Shop.Example.CO.UK.').apex, 'example.co.uk');
    assert.equal(domainTarget('www.example.com.br').apex, 'example.com.br');
    assert.equal(domainTarget('café.com').hostname, 'xn--caf-dma.com');
    for (const value of ['127.0.0.1', 'example.com/a', 'example.com?x', 'example.com@evil.com', '-foo.com', 'example..com', 'localhost', 'printer.local', 'com']) assert.throws(() => domainTarget(value), value);
});
test('crt.name normalizes passive names and dates without inventing certificate metadata or IP resolution', () => {
    const result = normalizeSubdomains([{ sub: 'WWW.example.com', first_seen: '2020-01-01T00:00:00Z' }, { sub: '*.example.com', first_seen: null }, { sub: 'www.example.com', first_seen: '2021-01-01T00:00:00Z' }, { sub: 'example.com.attacker.com' }], 'example.com');
    assert.equal(result.hosts.length, 2);
    assert.equal(result.hosts.find(row => row.hostname === 'www.example.com').firstSeen, '2020-01-01T00:00:00.000Z');
    assert.equal(result.hosts[0].issuer, undefined); assert.equal(result.hosts[0].addresses, undefined);
    assert.throws(() => normalizeSubdomains('<html>captcha</html>', 'example.com'));
});
test('CT certificate rows deduplicate IDs, preserve SANs and reject suffix lookalikes', () => {
    const cert = { id: 1, name_value: '*.example.com\nexample.com', issuer_name: 'Test CA', not_before: '2026-01-01T00:00:00', not_after: '2027-01-01T00:00:00' };
    const result = normalizeCertificates([cert, cert, { ...cert, id: 2, name_value: 'example.com.evil.com' }], 'example.com');
    assert.equal(result.total, 1); assert.equal(result.certificates[0].notBefore, '2026-01-01T00:00:00.000Z');
    assert.throws(() => normalizeCertificates({}, 'example.com'));
});
test('DNS changes are host-scoped and retain the opaque upstream cursor', () => {
    const result = normalizeDnsHistory({ domain: 'example.com', changes: [{ hostname: 'www.example.com', records: { A: ['1.1.1.1'], UNSUPPORTED: ['x'] } }, { hostname: 'another.example.com', records: { A: ['8.8.8.8'] } }], pagination: { next_cursor: 'opaque+/=' } }, 'www.example.com');
    assert.equal(result.changes.length, 1); assert.equal(result.nextCursor, 'opaque+/='); assert.deepEqual(result.changes[0].records, { A: ['1.1.1.1'] });
    assert.throws(() => normalizeDnsHistory({ domain: 'evil.com', changes: [] }, 'example.com'));
});
test('cache and single-flight avoid repeated crt.name requests for the same apex', async () => {
    let calls = 0;
    const api = createDomainIntelligence({ getWhoisKey: () => '', http: { get: async () => { calls++; return { data: [{ sub: 'example.com' }, { sub: 'www.example.com' }] }; } } });
    await Promise.all([api.subdomains('example.com'), api.subdomains('www.example.com')]);
    assert.equal(calls, 1); assert.equal((await api.subdomains('www.example.com')).hosts.length, 1);
});
test('paid-history failure is explicit and persisted local snapshots remain available', async () => {
    let saved; let clock = Date.parse('2026-01-01T00:00:00Z'); const calls = [];
    const options = { getWhoisKey: () => 'test-key', now: () => clock, saveObservations: data => { saved = structuredClone(data); }, http: { get: async (url, options) => { calls.push(options); throw { response: { status: 403 } }; } } };
    const api = createDomainIntelligence(options); api.observe('example.com', { A: ['1.1.1.1'], NS: ['ns.example.com'] }); clock += 86400_000;
    api.observe('example.com', { NS: ['ns.example.com'], A: ['1.1.1.1'] }); clock += 86400_000;
    api.observe('example.com', { A: ['8.8.8.8'] });
    const data = await api.history('example.com'); assert.equal(data.status, 'unavailable'); assert.equal(data.error, 'plan_required'); assert.equal(data.local.length, 2);
    assert.equal(data.local[0].lastSeen, '2026-01-02T00:00:00.000Z'); assert.equal(calls[0].headers.Authorization, 'Bearer test-key'); assert.equal(calls[0].maxRedirects, 0);
    const restarted = createDomainIntelligence({ ...options, readObservations: () => saved }); assert.equal((await restarted.history('example.com')).local.length, 2);
});
test('credential rotation and pagination do not reuse a history response from a different key', async () => {
    let key = 'one'; let calls = 0;
    const api = createDomainIntelligence({ getWhoisKey: () => key, http: { get: async (_, options) => { calls++; return { data: { domain: 'example.com', changes: [], pagination: { next_cursor: null } } }; } } });
    await api.history('example.com'); await api.history('example.com'); key = 'two'; await api.history('example.com'); await api.history('example.com', 'page2');
    assert.equal(calls, 3);
});
