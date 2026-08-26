// Cota restante por base, pra faixa abaixo da barra de busca.
//
// Cada provedor expõe cota de um jeito diferente, então cada um ganha o seu
// parser com o formato documentado em cima. Nada de parser genérico caçando
// campo: quando o formato mudar, o teste quebra no parser certo.
//
// Duas famílias:
//  - endpoint próprio: VirusTotal, Shodan, urlscan, Hybrid Analysis, MetaDefender.
//  - header da própria consulta: AbuseIPDB devolve X-RateLimit-* em todo /check,
//    então perguntar num endpoint gastaria um crédito só pra saber quantos
//    sobraram. Esse se preenche de carona nas buscas (record()).
//
// O resto do catálogo não expõe cota nenhuma e é reportado como 'none' — melhor
// dizer "sem cota" do que inventar número.

export const QUOTA_TTL_MS = 5 * 60 * 1000;

// state: ok | unconfigured | none | pending | error
export const NO_QUOTA_VENDORS = [
    'AlienVault OTX', 'URLhaus', 'MalwareBazaar', 'ThreatFox', 'Google Safe Browsing',
    'PhishTank', 'Pulsedive', 'CIRCL hashlookup', 'PhishStats', 'Ransomware.live',
    'OpenPhish', 'Team Cymru', 'Censys', 'IP Geolocation', 'WHOIS',
];

const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : (typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v)) ? Number(v) : null));

// Fecha o item a partir de dois dos três valores: o provedor que dá usado+limite
// não dá restante, e vice-versa.
const quota = ({ used = null, limit = null, remaining = null, period = 'day', resetAt = null }) => {
    const u = num(used), l = num(limit), r = num(remaining);
    const rem = r ?? (l !== null && u !== null ? l - u : null);
    const usd = u ?? (l !== null && r !== null ? l - r : null);
    if (rem === null && l === null) throw new Error('resposta de cota sem limite nem restante');
    return { state: 'ok', used: usd, limit: l, remaining: rem, period, resetAt };
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

// { limits: { minute, hour, month } } — só teto, sem consumo: mostra o limite.
export const parseHybridAnalysis = (body) => quota({ limit: body?.limits?.month, period: 'month' });

// { limit_interval, limit_scan } ou { limits: [{ limit, used }] } conforme o plano.
export const parseMetaDefender = (body) => {
    const first = Array.isArray(body?.limits) ? body.limits[0] : null;
    if (first) return quota({ used: first.used, limit: first.limit, period: 'day' });
    return quota({ limit: body?.limit_scan, period: 'day' });
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
    {
        name: 'Hybrid Analysis', env: 'HYBRID_ANALYSIS_API_KEY', parse: parseHybridAnalysis,
        request: (key) => ['https://www.hybrid-analysis.com/api/v2/key/current', { 'api-key': key, 'user-agent': 'Falcon Sandbox' }],
    },
    {
        name: 'MetaDefender', env: 'METADEFENDER_API_KEY', parse: parseMetaDefender,
        request: (key) => [`https://api.metadefender.com/v4/apikey/${encodeURIComponent(key)}`, { apikey: key }],
    },
];

export const HEADER_QUOTA_VENDORS = ['AbuseIPDB'];

/**
 * Lê a cota das bases que expõem, com cache curto: a faixa recarrega a cada
 * busca e sem cache um lote grande viraria uma consulta de cota por IOC.
 */
export function createQuotaReader({ getKeys, fetchImpl = fetch, ttlMs = QUOTA_TTL_MS, timeoutMs = 8000, now = () => Date.now() }) {
    let cache = null;         // { at, items }
    const fromHeaders = {};   // { [vendor]: { item, at } }

    const fetchOne = async (source) => {
        const key = (getKeys(source.env) || [])[0];
        if (!key) return { name: source.name, state: 'unconfigured' };
        try {
            const [url, headers] = source.request(key);
            const response = await fetchImpl(url, {
                headers: { Accept: 'application/json', ...headers },
                signal: AbortSignal.timeout(timeoutMs),
            });
            if (!response.ok) return { name: source.name, state: 'error', error: `HTTP ${response.status}` };
            return { name: source.name, ...source.parse(await response.json()) };
        } catch (error) {
            return { name: source.name, state: 'error', error: error.message || 'falha ao ler cota' };
        }
    };

    const headerItem = (name) => {
        const hit = fromHeaders[name];
        if (!hit) return { name, state: 'pending' };
        return { name, ...hit.item, at: hit.at };
    };

    return {
        /** Guarda a cota que veio de carona numa consulta normal do provedor. */
        record(name, headers) {
            try { fromHeaders[name] = { item: parseRateLimitHeaders(headers), at: new Date(now()).toISOString() }; }
            catch { /* provedor não mandou header desta vez: mantém o último */ }
        },
        async read() {
            if (!cache || now() - cache.at >= ttlMs) {
                cache = { at: now(), items: await Promise.all(QUOTA_SOURCES.map(fetchOne)) };
            }
            return [
                ...cache.items,
                ...HEADER_QUOTA_VENDORS.map(headerItem),
                ...NO_QUOTA_VENDORS.map((name) => ({ name, state: 'none' })),
            ];
        },
    };
}
