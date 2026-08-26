import test from 'node:test';
import assert from 'node:assert/strict';

import {
    parseVirusTotal, parseShodan, parseUrlscan, parseHybridAnalysis, parseMetaDefender,
    parseRateLimitHeaders, createQuotaReader, QUOTA_SOURCES, NO_QUOTA_VENDORS,
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

    // Só teto, sem consumo: restante fica nulo em vez de virar zero.
    assert.deepEqual(parseHybridAnalysis({ limits: { minute: 5, hour: 40, month: 800 } }),
        { state: 'ok', used: null, limit: 800, remaining: null, period: 'month', resetAt: null });

    assert.equal(parseMetaDefender({ limits: [{ limit: 1000, used: 4 }] }).remaining, 996);
    assert.equal(parseMetaDefender({ limit_scan: 500 }).limit, 500);
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
    assert.equal(by('AbuseIPDB').state, 'pending');          // ainda não houve busca
    assert.equal(by('Censys').state, 'none');                // Platform API não expõe cota
    assert.equal(items.length, QUOTA_SOURCES.length + 1 + NO_QUOTA_VENDORS.length);

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
    const reader = createQuotaReader({ getKeys: () => [], now: () => 0 });
    reader.record('AbuseIPDB', { 'x-ratelimit-limit': '1000', 'x-ratelimit-remaining': '12' });
    const item = (await reader.read()).find((i) => i.name === 'AbuseIPDB');
    assert.equal(item.state, 'ok');
    assert.equal(item.remaining, 12);

    // Resposta sem header não pode apagar o que já se sabia.
    reader.record('AbuseIPDB', {});
    assert.equal((await reader.read()).find((i) => i.name === 'AbuseIPDB').remaining, 12);
});
