import { Resolver } from 'node:dns/promises';
import { parse } from 'tldts';
import { domainTarget } from './domainIntelligence.js';
import { createRdap } from './rdap.js';

const SUFFIXES = ['com', 'net', 'org', 'com.br', 'co', 'io', 'cn', 'com.tr', 'co.uk', 'br', 'app', 'dev', 'ai', 'online', 'site', 'xyz', 'shop', 'info', 'biz', 'tech'];
export function similarDomainCandidates(value) {
    const { apex } = domainTarget(value); const info = parse(apex); const label = info.domainWithoutSuffix;
    const rows = new Map();
    const add = (domain, kind) => {
        try { if (domain !== apex && domainTarget(domain).apex === domain && !rows.has(domain)) rows.set(domain, { domain, kind }); } catch { /* invalid generated label */ }
    };
    for (const suffix of SUFFIXES) add(`${label}.${suffix}`, 'tld');
    // Internationalized labels remain ASCII/punycode; mutating xn-- can change meaning unpredictably.
    if (!label.startsWith('xn--')) {
        for (let i = 0; i < label.length && rows.size < 32; i++) {
            add(`${label.slice(0, i)}${label.slice(i + 1)}.${info.publicSuffix}`, 'omission');
            if (i + 1 < label.length && label[i] !== label[i + 1]) add(`${label.slice(0, i)}${label[i + 1]}${label[i]}${label.slice(i + 2)}.${info.publicSuffix}`, 'transposition');
        }
    }
    return { apex, candidates: [...rows.values()].slice(0, 32) };
}
async function mapLimit(rows, limit, run) {
    let cursor = 0; const results = new Array(rows.length);
    await Promise.all(Array.from({ length: Math.min(limit, rows.length) }, async () => {
        while (cursor < rows.length) { const index = cursor++; results[index] = await run(rows[index]); }
    })); return results;
}
export function createSimilarDomains({ now = () => Date.now(), resolverFactory = () => new Resolver({ timeout: 1000, tries: 1 }), registration = createRdap({ timeoutMs: 3000 }) } = {}) {
    const cache = new Map(); const pending = new Map();
    async function search(value) {
        const { apex, candidates } = similarDomainCandidates(value); const saved = cache.get(apex);
        if (saved && now() - saved.at < saved.ttl) return saved.result;
        if (pending.has(apex)) return pending.get(apex);
        if (pending.size >= 3) return { status: 'unavailable', source: 'DNS / RDAP', apex, domains: [], error: 'busy' };
        const request = (async () => {
            const resolver = resolverFactory(); const deadline = now() + 6500; let checked = 0; let incomplete = 0;
            const timer = setTimeout(() => resolver.cancel(), 6500);
            let rows;
            try {
                rows = await mapLimit(candidates, 6, async candidate => {
                    if (now() >= deadline) { incomplete++; return null; }
                    checked++;
                    const result = await Promise.allSettled([resolver.resolve4(candidate.domain), resolver.resolve6(candidate.domain), resolver.resolveNs(candidate.domain)]);
                    const values = result.map(row => row.status === 'fulfilled' ? row.value : []);
                    if (result.some(row => row.status === 'rejected' && !['ENOTFOUND', 'ENODATA'].includes(row.reason?.code))) incomplete++;
                    if (!values.some(items => items.length)) return null;
                    return { ...candidate, addresses: [...values[0], ...values[1]].slice(0, 20), nameservers: values[2].slice(0, 20), registrar: null, expiresAt: null, registrationStatus: 'not_checked', source: ['DNS'] };
                });
            } finally { clearTimeout(timer); resolver.cancel(); }
            const domains = rows.filter(Boolean);
            // Only observed names receive registry lookups; never fan out paid Who.is calls.
            try { if (domains.length) await registration.serverFor(apex); } catch { /* DNS evidence remains useful */ }
            await mapLimit(domains.slice(0, 12), 6, async row => {
                try {
                    const data = await registration.domain(row.domain);
                    row.registrationStatus = data.found ? 'available' : data.supported === false ? 'unsupported' : 'unavailable';
                    if (data.found) { row.registrar = data.registrar || null; row.expiresAt = data.expiresAt || null; row.source.push('RDAP'); }
                } catch { row.registrationStatus = 'unavailable'; }
            });
            const result = { status: !domains.length && incomplete === candidates.length ? 'unavailable' : 'available', source: 'DNS / RDAP', apex, fetchedAt: new Date(now()).toISOString(), checked, candidateCount: candidates.length, incomplete, domains };
            cache.set(apex, { at: now(), ttl: result.status === 'available' ? incomplete ? 300_000 : 21_600_000 : 60_000, result });
            while (cache.size > 128) cache.delete(cache.keys().next().value);
            return result;
        })().finally(() => pending.delete(apex));
        pending.set(apex, request); return request;
    }
    return { search };
}
