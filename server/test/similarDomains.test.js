import test from 'node:test';
import assert from 'node:assert/strict';
import { similarDomainCandidates, createSimilarDomains } from '../similarDomains.js';

const missing = () => Promise.reject(Object.assign(new Error('not found'), { code: 'ENOTFOUND' }));
test('similar domains use the registrable name, bounded TLD/typo variants and strict validation', () => {
    const data = similarDomainCandidates('shop.example.com.br');
    assert.equal(data.apex, 'example.com.br'); assert.ok(data.candidates.length <= 32);
    assert.ok(data.candidates.some(row => row.domain === 'example.cn' && row.kind === 'tld'));
    assert.ok(data.candidates.some(row => row.domain === 'example.com.tr'));
    assert.ok(data.candidates.some(row => row.domain === 'eaxmple.com.br' && row.kind === 'transposition'));
    assert.ok(data.candidates.every(row => row.domain !== data.apex && !row.domain.includes('shop.')));
    assert.equal(new Set(data.candidates.map(row => row.domain)).size, data.candidates.length);
    assert.ok(similarDomainCandidates('café.com').candidates.every(row => row.kind === 'tld'));
    for (const value of ['localhost', '127.0.0.1', 'example.com/a', 'example.com@evil.net']) assert.throws(() => similarDomainCandidates(value));
});
test('only DNS-observed candidates appear, IPv6 and NS-only work, registry failures preserve evidence', async () => {
    const seen = []; let cancelled = 0;
    const resolver = { resolve4: name => name === 'example.net' ? Promise.resolve(['8.8.8.8']) : missing(), resolve6: name => name === 'example.org' ? Promise.resolve(['2001:4860:4860::8888']) : missing(), resolveNs: name => name === 'example.cn' ? Promise.resolve(['ns.test.cn']) : missing(), cancel: () => cancelled++ };
    const api = createSimilarDomains({ resolverFactory: () => resolver, registration: { serverFor: async () => {}, domain: async name => { seen.push(name); if (name.endsWith('.org')) throw new Error('timeout'); return name.endsWith('.cn') ? { supported: false } : { found: true, registrar: 'Example Registrar', expiresAt: '2027-01-01T00:00:00Z' }; } } });
    const result = await api.search('www.example.com');
    assert.equal(result.status, 'available'); assert.equal(result.domains.length, 3); assert.equal(seen.length, 3); assert.equal(cancelled, 1);
    assert.deepEqual(result.domains.find(row => row.domain === 'example.net').source, ['DNS', 'RDAP']);
    assert.equal(result.domains.find(row => row.domain === 'example.net').expiresAt, '2027-01-01T00:00:00Z');
    assert.equal(result.domains.find(row => row.domain === 'example.org').registrationStatus, 'unavailable');
    assert.equal(result.domains.find(row => row.domain === 'example.cn').registrationStatus, 'unsupported');
});
test('same apex searches coalesce and cache; DNS failures do not claim domains available for registration', async () => {
    let factories = 0; let clock = 0;
    const api = createSimilarDomains({ now: () => clock, resolverFactory: () => { factories++; return { resolve4: missing, resolve6: missing, resolveNs: missing, cancel: () => {} }; } });
    const [a, b] = await Promise.all([api.search('www.example.com'), api.search('example.com')]);
    assert.equal(a, b); assert.equal(a.domains.length, 0); assert.equal(a.status, 'available'); assert.equal(factories, 1);
    await api.search('mail.example.com'); assert.equal(factories, 1); clock += 21_600_001; await api.search('example.com'); assert.equal(factories, 2);
    const broken = createSimilarDomains({ resolverFactory: () => ({ resolve4: () => Promise.reject({ code: 'ETIMEOUT' }), resolve6: missing, resolveNs: missing, cancel: () => {} }) });
    const result = await broken.search('example.com'); assert.equal(result.status, 'unavailable'); assert.deepEqual(result.domains, []);
});
test('registration calls are bounded and a slow DNS phase stops scheduling more candidates', async () => {
    let registryCalls = 0;
    const api = createSimilarDomains({ resolverFactory: () => ({ resolve4: async () => ['1.1.1.1'], resolve6: missing, resolveNs: missing, cancel: () => {} }), registration: { serverFor: async () => {}, domain: async () => { registryCalls++; return { found: true }; } } });
    const result = await api.search('example.com'); assert.equal(result.domains.length, 32); assert.equal(registryCalls, 12);
    assert.equal(result.domains.filter(row => row.registrationStatus === 'not_checked').length, 20);
    let clock = 0;
    const slow = createSimilarDomains({ now: () => clock, resolverFactory: () => ({ resolve4: async () => { clock += 7000; return []; }, resolve6: missing, resolveNs: missing, cancel: () => {} }) });
    const partial = await slow.search('example.com'); assert.ok(partial.checked < partial.candidateCount); assert.ok(partial.incomplete > 0);
});
