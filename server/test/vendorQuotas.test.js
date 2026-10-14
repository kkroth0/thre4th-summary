import test from 'node:test';
import assert from 'node:assert/strict';

import {
    parseVirusTotal, parseShodan, parseUrlscan,
    parseRateLimitHeaders, parseQuotaWindows, createQuotaReader, QUOTA_SOURCES, NO_QUOTA_VENDORS,
} from '../vendorQuotas.js';

// Formato real da API, capturado em 2026-08-26.
const URLSCAN = { limits: { search: { day: { limit: 1000, percent: 2, remaining: 980, used: 20, reset: '2026-08-27T00:00:00.000Z' } } } };

test('cada provedor fecha usado/limite/restante a partir do que manda', () => {
    assert.deepEqual(parseVirusTotal({ data: { api_requests_daily: { user: { allowed: 500, used: 120 } } } }),
        { state: 'ok', used: 120, limit: 500, remaining: 380, period: 'day', resetAt: null });

    // Shodan manda restante, não usado: o usado é derivado.
    assert.deepEqual(parseShodan({ query_credits: 87, usage_limits: { query_credits: 100 } }),
        { state: 'ok', used: 13, limit: 100, remaining: 87, period: 'month', resetAt: null });

    assert.deepEqual(parseUrlscan(URLSCAN),
        { state: 'ok', used: 20, limit: 1000, remaining: 980, period: 'day', resetAt: '2026-08-27T00:00:00.000Z' });


});

test('header de rate limit vale como cota, e string vira número', () => {
    const item = parseRateLimitHeaders({ 'x-ratelimit-limit': '1000', 'x-ratelimit-remaining': '994' });
    assert.deepEqual(item, { state: 'ok', used: 6, limit: 1000, remaining: 994, period: 'day', resetAt: null });
    // Headers do fetch são um Map-like, não objeto puro.
    assert.equal(parseRateLimitHeaders(new Headers({ 'x-ratelimit-limit': '10', 'x-ratelimit-remaining': '3' })).remaining, 3);
});

test('resposta sem campo de cota nenhum é erro, não item vazio', () => {
    assert.throws(() => parseVirusTotal({ data: {} }));
    assert.throws(() => parseRateLimitHeaders({}));
});

test('base sem chave, provedor fora do ar e cache', async () => {
    let calls = 0;
    const reader = createQuotaReader({
        getKeys: (env) => (env === 'VIRUSTOTAL_API_KEY' ? ['k'] : []),
        fetchImpl: async () => { calls++; return { ok: true, json: async () => ({ data: { api_requests_daily: { user: { allowed: 500, used: 1 } } } }) }; },
        now: () => 0,
    });

    const items = await reader.read();
    const by = (name) => items.find((i) => i.name === name);
    assert.equal(by('VirusTotal').remaining, 499);
    assert.equal(by('Shodan').state, 'unconfigured');       // sem chave não vira erro
    assert.equal(by('AbuseIPDB').state, 'unconfigured');
    assert.equal(by('Censys'), undefined);
    assert.equal(by('Team Cymru'), undefined);
    assert.equal(items.length, QUOTA_SOURCES.length + 2 + NO_QUOTA_VENDORS.length);

    await reader.read();
    assert.equal(calls, 1, 'segunda leitura dentro do TTL não pode bater na rede');
});

test('provedor que responde erro não derruba o resto', async () => {
    const reader = createQuotaReader({
        getKeys: () => ['k'],
        fetchImpl: async (url) => (url.includes('shodan')
            ? { ok: false, status: 401 }
            : { ok: true, json: async () => { throw new Error('json quebrado'); } }),
        now: () => 0,
    });
    const items = await reader.read();
    assert.equal(items.find((i) => i.name === 'Shodan').state, 'error');
    assert.equal(items.find((i) => i.name === 'VirusTotal').state, 'error');
});

test('AbuseIPDB se preenche de carona na busca', async () => {
    const reader = createQuotaReader({ getKeys: env => env === 'ABUSEIPDB_API_KEY' ? ['k'] : [], now: () => 0 });
    reader.record('AbuseIPDB', { 'x-ratelimit-limit': '1000', 'x-ratelimit-remaining': '12' });
    const item = (await reader.read()).find((i) => i.name === 'AbuseIPDB');
    assert.equal(item.state, 'ok');
    assert.equal(item.remaining, 12);

    // Resposta sem header não pode apagar o que já se sabia.
    reader.record('AbuseIPDB', {});
    assert.equal((await reader.read()).find((i) => i.name === 'AbuseIPDB').remaining, 12);
});

test('daily and monthly VT windows remain separate and reset in UTC', () => {
    const windows = parseQuotaWindows('VirusTotal', { data: {
        api_requests_daily: { user: { allowed: 500, used: 120 } },
        api_requests_monthly: { user: { allowed: 15500, used: 3000 } },
    } }, Date.parse('2026-10-31T23:59:59Z'));
    assert.deepEqual(windows.map(window => [window.period, window.remaining, window.resetAt]), [
        ['day', 380, '2026-11-01T00:00:00.000Z'], ['month', 12500, '2026-11-01T00:00:00.000Z'],
    ]);
    assert.equal(parseQuotaWindows('VirusTotal', { data: { api_requests_daily: { user: { allowed: 500, used: 501 } } } })[0].remaining, 0);
});

test('short windows and query credits never invent daily or monthly allowances', () => {
    const windows = parseQuotaWindows('urlscan.io', { limits: { search: { ...URLSCAN.limits.search,
        minute: { limit: 30, remaining: 12, reset: '2026-08-26T12:01:00Z' },
        hour: { limit: 100, remaining: 75 },
    } } });
    assert.deepEqual(windows.map(window => window.period), ['minute', 'hour', 'day']);
    assert.deepEqual(parseQuotaWindows('Shodan', { query_credits: 12 }).map(window => [window.period, window.remaining, window.limit]), [['month', 12, null]]);
    assert.equal(parseRateLimitHeaders({ 'x-ratelimit-limit': '1000', 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '1792022400' }).resetAt, '2026-10-15T00:00:00.000Z');
});

test('quota reads deduplicate concurrent calls and isolate changed personal credentials', async () => {
    let calls = 0; let time = 0;
    const reader = createQuotaReader({ getKeys: env => env === 'SHODAN_API_KEY' ? ['shared'] : [], now: () => time,
        fetchImpl: async url => { calls++; await new Promise(resolve => setTimeout(resolve, 10)); return { ok: true, json: async () => ({ query_credits: url.includes('personal') ? 11 : 42 }) }; },
    });
    const results = await Promise.all([reader.read(), reader.read()]);
    assert.equal(calls, 1);
    assert.equal(results[0].find(item => item.name === 'Shodan').remaining, 42);
    const personal = await reader.read({ keysFor: env => env === 'SHODAN_API_KEY' ? ['personal'] : [] });
    assert.equal(personal.find(item => item.name === 'Shodan').remaining, 11);
    await reader.read({ fresh: true }); assert.equal(calls, 2, 'rapid refresh reuses its recent reading');
    time = 16000; await reader.read({ fresh: true }); assert.equal(calls, 3);
});

test('AbuseIPDB separates operations and keys, survives restart, and expires balances', async () => {
    const state = new Map(); let time = Date.parse('2026-10-14T12:00:00Z');
    const options = { getKeys: env => env === 'ABUSEIPDB_API_KEY' ? ['shared'] : [], now: () => time,
        loadState: key => state.get(key), saveState: (key, value) => state.set(key, value),
    };
    let reader = createQuotaReader(options);
    const headers = remaining => ({ 'x-ratelimit-limit': '1000', 'x-ratelimit-remaining': String(remaining), 'x-ratelimit-reset': '1792022400' });
    reader.record('AbuseIPDB', headers(998));
    reader.record('AbuseIPDB', headers(99), { key: 'shared', operation: 'check-block' });
    reader.record('AbuseIPDB', headers(4), { key: 'shared', operation: 'blacklist' });
    reader.record('AbuseIPDB', headers(13), { key: 'private-key', operation: 'check' });
    reader = createQuotaReader(options);
    const shared = (await reader.read()).find(item => item.name === 'AbuseIPDB');
    assert.equal(shared.remaining, 998);
    assert.deepEqual(shared.windows.map(window => window.remaining), [998, 99, 4]);
    const personal = (await reader.read({ keysFor: env => env === 'ABUSEIPDB_API_KEY' ? ['private-key'] : [] })).find(item => item.name === 'AbuseIPDB');
    assert.equal(personal.remaining, 13);
    assert.equal(personal.windows[1].state, 'pending');
    assert.equal(JSON.stringify([...state]).includes('private-key'), false);
    time = Date.parse('2026-10-15T00:00:00Z');
    const expired = (await reader.read()).find(item => item.name === 'AbuseIPDB');
    assert.equal(expired.state, 'pending'); assert.equal(expired.remaining, null);
});

test('provider errors do not leak authenticated URLs or keys', async () => {
    const reader = createQuotaReader({ getKeys: () => ['secret-token'], fetchImpl: async () => { throw Error('fetch failed https://example.test?key=secret-token'); } });
    assert.equal(JSON.stringify(await reader.read()).includes('secret-token'), false);
});

test('Who.is credit buckets remain distinct from daily or monthly request allowances', async () => {
    const reader = createQuotaReader({ getKeys: env => env === 'WHOIS_API_KEY' ? ['whois-test'] : [] });
    assert.equal((await reader.read()).find(item => item.name === 'WHOIS').windows[0].state, 'pending');
    reader.record('WHOIS', { 'x-ratelimit-limit': '500', 'x-ratelimit-remaining': '473' });
    const item = (await reader.read()).find(item => item.name === 'WHOIS');
    assert.equal(item.remaining, 473); assert.equal(item.period, 'credits');
    assert.equal(item.resetAt, null, 'purchased credits have no documented monthly reset');
    assert.equal(item.windows.some(window => window.period === 'day'), false);
});
