// Provider-reported balances for enrichment and the source directory.
//
// Cada provedor expõe cota de um jeito diferente, então cada um ganha o seu
// parser com o formato documentado em cima. Nada de parser genérico caçando
// campo: quando o formato mudar, o teste quebra no parser certo.
//
// Duas famílias:
//  - endpoint próprio: VirusTotal, Shodan, urlscan.
//  - header da própria consulta: AbuseIPDB devolve X-RateLimit-* em todo /check,
//    então perguntar num endpoint gastaria um crédito só pra saber quantos
//    sobraram. Esse se preenche de carona nas buscas (record()).
//
// 'none' means this integration has no queryable balance, not unlimited use.

import { createHash } from 'node:crypto';

export const QUOTA_TTL_MS = 5 * 60 * 1000;

// state: ok | unconfigured | none | pending | error
export const NO_QUOTA_VENDORS = [
    'AlienVault OTX', 'URLhaus', 'MalwareBazaar', 'ThreatFox', 'Google Safe Browsing',
    'PhishTank', 'PhishStats', 'Ransomware.live',
    'OpenPhish', 'IP Geolocation',
];

const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : (typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v)) ? Number(v) : null));

// Fecha o item a partir de dois dos três valores: o provedor que dá usado+limite
// não dá restante, e vice-versa.
const resetDate = value => {
    if (value === null || value === undefined || value === '') return null;
    const numeric = num(value);
    const time = numeric === null ? Date.parse(value) : numeric * (numeric < 1e12 ? 1000 : 1);
    return Number.isFinite(time) ? new Date(time).toISOString() : null;
};
const quota = ({ used = null, limit = null, remaining = null, period = 'day', resetAt = null }) => {
    const u = num(used), l = num(limit), r = num(remaining);
    const rem = r ?? (l !== null && u !== null ? Math.max(0, l - u) : null);
    const usd = u ?? (l !== null && r !== null ? l - r : null);
    if (rem === null && l === null) throw new Error('resposta de cota sem limite nem restante');
    return { state: 'ok', used: usd, limit: l, remaining: rem, period, resetAt: resetDate(resetAt) };
};

// { data: { api_requests_daily: { user: { allowed, used } } } }
export const parseVirusTotal = (body) => {
    const d = body?.data?.api_requests_daily?.user;
    return quota({ used: d?.used, limit: d?.allowed, period: 'day' });
};

// { query_credits, usage_limits: { query_credits } }  — crédito é mensal no plano pago
export const parseShodan = (body) => quota({
    remaining: body?.query_credits,
    limit: body?.usage_limits?.query_credits,
    period: 'month',
});

// Verificado contra a API: limits.search.day = { limit, used, remaining, reset }
export const parseUrlscan = (body) => {
    const d = body?.limits?.search?.day;
    return quota({ used: d?.used, limit: d?.limit, remaining: d?.remaining, period: 'day', resetAt: d?.reset ?? null });
};

// X-RateLimit-Limit / X-RateLimit-Remaining de qualquer resposta do provedor.
export const parseRateLimitHeaders = (headers) => {
    const get = (k) => (typeof headers?.get === 'function' ? headers.get(k) : headers?.[k]);
    return quota({
        limit: get('x-ratelimit-limit'),
        remaining: get('x-ratelimit-remaining'),
        period: 'day',
        resetAt: get('x-ratelimit-reset') ?? null,
    });
};

export function parseQuotaWindows(name, body, at = Date.now()) {
    const windows = [];
    if (name === 'VirusTotal') {
        for (const [period, field] of [['day', 'api_requests_daily'], ['month', 'api_requests_monthly']]) {
            const data = body?.data?.[field]?.user;
            if (!data || (num(data.allowed) === null && num(data.used) === null)) continue;
            const date = new Date(at);
            const resetAt = period === 'day' ? Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate() + 1) : Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 1);
            windows.push({ ...quota({ used: data.used, limit: data.allowed, period }), resetAt: new Date(resetAt).toISOString(), operation: 'api' });
        }
    } else if (name === 'Shodan') windows.push({ ...parseShodan(body), operation: 'query_credits' });
    else if (name === 'urlscan.io') {
        for (const period of ['minute', 'hour', 'day', 'month']) {
            const data = body?.limits?.search?.[period];
            if (data) windows.push({ ...quota({ used: data.used, limit: data.limit, remaining: data.remaining, period, resetAt: data.reset }), operation: 'search' });
        }
    }
    if (!windows.length) throw new Error('Quota unavailable');
    return windows;
}

export const QUOTA_SOURCES = [
    {
        name: 'VirusTotal', env: 'VIRUSTOTAL_API_KEY', parse: parseVirusTotal,
        request: (key) => [`https://www.virustotal.com/api/v3/users/${encodeURIComponent(key)}/overall_quotas`, { 'x-apikey': key }],
    },
    {
        name: 'Shodan', env: 'SHODAN_API_KEY', parse: parseShodan,
        request: (key) => [`https://api.shodan.io/api-info?key=${encodeURIComponent(key)}`, {}],
    },
    {
        name: 'urlscan.io', env: 'URLSCAN_API_KEY', parse: parseUrlscan,
        request: (key) => ['https://urlscan.io/user/quotas/', { 'API-Key': key }],
    },
];

export const HEADER_QUOTA_VENDORS = ['AbuseIPDB', 'WHOIS'];
const headerEnv = name => name === 'WHOIS' ? 'WHOIS_API_KEY' : 'ABUSEIPDB_API_KEY';

/**
 * Lê a cota das bases que expõem, com cache curto: a faixa recarrega a cada
 * busca e sem cache um lote grande viraria uma consulta de cota por IOC.
 */
export function createQuotaReader({ getKeys, fetchImpl = fetch, ttlMs = QUOTA_TTL_MS, timeoutMs = 8000, now = () => Date.now(), loadState = () => null, saveState = () => {} }) {
    const cache = new Map();
    const flights = new Map();
    const fromHeaders = new Map();
    const identity = (name, key, operation = '') => 'quota:' + createHash('sha256').update(JSON.stringify([name, key, operation])).digest('hex');

    const fetchOne = async (source, keysFor, fresh) => {
        const key = (keysFor(source.env) || [])[0];
        if (!key) return { name: source.name, state: 'unconfigured' };
        const id = identity(source.name, key);
        const cached = cache.get(id);
        if (cached && now() - cached.at < (fresh ? 15000 : ttlMs) && !cached.item.windows?.some(window => window.resetAt && Date.parse(window.resetAt) <= now())) return cached.item;
        if (flights.has(id)) return flights.get(id);
        const flight = (async () => {
        const at = new Date(now()).toISOString();
        let item;
        try {
            const [url, headers] = source.request(key);
            const response = await fetchImpl(url, {
                headers: { Accept: 'application/json', ...headers },
                signal: AbortSignal.timeout(timeoutMs),
            });
            if (!response.ok) item = { name: source.name, state: 'error', error: `HTTP ${response.status}`, at };
            else {
                const windows = parseQuotaWindows(source.name, await response.json(), now());
                const primary = windows.find(window => window.period === (source.name === 'Shodan' ? 'month' : 'day')) || windows[0];
                item = { name: source.name, ...primary, windows, at };
            }
        } catch {
            // Fetch errors can contain authenticated URLs; return only safe text.
            item = { name: source.name, state: 'error', error: 'Quota unavailable', at };
        }
        cache.set(id, { at: now(), item });
        return item;
        })().finally(() => flights.delete(id));
        flights.set(id, flight);
        return flight;
    };

    const headerItem = (name, keysFor) => {
        const key = (keysFor(headerEnv(name)) || [])[0];
        if (!key) return { name, state: 'unconfigured' };
        const windows = (name === 'WHOIS' ? ['credits'] : ['check', 'check-block', 'blacklist']).flatMap(operation => {
            const id = identity(name, key, operation);
            const hit = fromHeaders.get(id) || loadState(id);
            if (!hit) return [{ state: 'pending', period: name === 'WHOIS' ? 'credits' : 'day', operation }];
            const expired = hit.item.resetAt ? Date.parse(hit.item.resetAt) <= now() : hit.at.slice(0, name === 'WHOIS' ? 7 : 10) !== new Date(now()).toISOString().slice(0, name === 'WHOIS' ? 7 : 10);
            return [{ ...hit.item, ...(expired ? { state: 'pending', used: null, remaining: null } : {}), operation, at: hit.at }];
        });
        const primary = windows.find(window => window.operation === (name === 'WHOIS' ? 'credits' : 'check'));
        return { name, ...(primary || { state: 'pending' }), windows };
    };

    return {
        /** Guarda a cota que veio de carona numa consulta normal do provedor. */
        record(name, headers, { key = (getKeys(headerEnv(name)) || [])[0], operation = name === 'WHOIS' ? 'credits' : 'check' } = {}) {
            if (!key) return;
            try {
                const id = identity(name, key, operation);
                const parsed = parseRateLimitHeaders(headers);
                const hit = { item: { ...parsed, ...(name === 'WHOIS' ? { period: 'credits' } : {}) }, at: new Date(now()).toISOString() };
                fromHeaders.set(id, hit); saveState(id, hit);
            }
            catch { /* provedor não mandou header desta vez: mantém o último */ }
        },
        async read({ keysFor = getKeys, fresh = false } = {}) {
            const items = await Promise.all(QUOTA_SOURCES.map(source => fetchOne(source, keysFor, fresh)));
            return [
                ...items,
                ...HEADER_QUOTA_VENDORS.map(name => headerItem(name, keysFor)),
                ...NO_QUOTA_VENDORS.map((name) => ({ name, state: 'none' })),
            ];
        },
    };
}
