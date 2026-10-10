// Vigilância de marca no urlscan.io: domínio recém-criado que carrega a marca
// da organização no nome é candidato a phishing antes de a campanha começar.
//
// A regra que não pode ser quebrada: aqui só se BUSCA no que o urlscan já
// varreu, nunca se submete scan. Submeter publica a URL no urlscan — URL de
// cliente virando scan público seria vazamento nosso. Por isso o único endpoint
// que este módulo conhece é o de busca, e há teste guardando isso.
//
// A forma é a mesma do exposureWatchlist.js: funções puras aqui, I/O injetado,
// store em arquivo, e o tick de 15 minutos do index.js acorda quem venceu.

import { createHash } from 'node:crypto';

export const PHISH_LIMITS = {
    brandsPerProfile: 8,
    termMin: 4,
    termMax: 40,
    // Achados novos por perfil. Dispensado e confirmado não contam: um é a
    // lista de falso positivo que filtra as rodadas seguintes, o outro é o
    // resultado do trabalho.
    newHitsPerProfile: 200,
    triagedPerProfile: 500,
    hitRetentionDays: 14,
    searchSize: 100,
    // De hora em hora: página de phishing vive horas, não dias.
    runIntervalMs: 60 * 60 * 1000,
    // Corte de idade do domínio. Acima disto não é "recém-criado" e a busca
    // vira caça a menção de marca, que é outro problema.
    maxApexAgeDays: 30,
    // Janela fixa em vez de "desde a última rodada": se o servidor ficar horas
    // fora do ar, a rodada seguinte recupera sozinha, e a deduplicação por
    // domínio garante que repetir a janela não gera achado repetido.
    windowHours: 24,
};

export const HIT_STATUS = ['new', 'confirmed', 'dismissed'];

export const createPhishError = (status, publicMessage) =>
    Object.assign(new Error(publicMessage), { status, publicMessage });

const SEARCH_ENDPOINT = 'https://urlscan.io/api/v1/search/';

// Termo de busca é o rótulo da marca, não a URL: tira esquema, www, caminho e
// TLD. "https://bancoxpto.com.br/login" e "bancoxpto" são o mesmo termo.
export function normalizeBrandTerm(raw) {
    const text = String(raw || '').trim().toLowerCase()
        .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
        .replace(/^www\./, '')
        .split(/[/?#]/)[0];
    // Domínio vira o rótulo: bancoxpto.com.br → bancoxpto. Nome composto com
    // ponto mas sem TLD conhecido é raro o bastante para tratar igual.
    const label = text.includes('.') ? text.split('.')[0] : text;
    if (!/^[a-z0-9][a-z0-9-]*$/.test(label)) return null;
    if (label.length < PHISH_LIMITS.termMin || label.length > PHISH_LIMITS.termMax) return null;
    return label;
}

export function normalizeBrands(input) {
    const list = Array.isArray(input) ? input : [];
    const terms = [];
    for (const raw of list) {
        const term = normalizeBrandTerm(raw);
        if (!term || terms.includes(term)) continue;
        terms.push(term);
    }
    if (terms.length > PHISH_LIMITS.brandsPerProfile) {
        throw createPhishError(400, `no máximo ${PHISH_LIMITS.brandsPerProfile} marcas por perfil`);
    }
    return terms;
}

// Uma busca por perfil, não uma por marca: o OR das marcas cabe numa query só e
// a cota (1000 buscas/dia) deixa de depender de quantas marcas foram cadastradas.
export function buildQuery(terms, options = {}) {
    const list = normalizeBrands(terms);
    if (!list.length) throw createPhishError(400, 'nenhuma marca para vigiar');
    const maxAge = options.maxApexAgeDays ?? PHISH_LIMITS.maxApexAgeDays;
    const hours = options.windowHours ?? PHISH_LIMITS.windowHours;
    const domains = list.map((term) => `*${term}*`).join(' OR ');
    return `page.domain:(${domains}) AND page.apexDomainAgeDays:<${maxAge} AND date:>now-${hours}h`;
}

// Motivos são códigos, não frases: a tela é bilíngue e quem traduz é ela.
export function scoreHit(hit) {
    const reasons = [];
    let score = 0;

    const age = Number(hit.apexAgeDays);
    if (Number.isFinite(age)) {
        if (age <= 2) { score += 40; reasons.push('fresh-domain'); }
        else if (age <= 7) { score += 25; reasons.push('young-domain'); }
        else { score += 10; reasons.push('recent-domain'); }
    }

    // Marca colada em outra palavra é a assinatura do typosquat:
    // "adobe-bancochile-bing.com.ph" x "bancochile.cl".
    const label = String(hit.apexDomain || '').split('.')[0];
    if (hit.term && label && label !== hit.term) { score += 30; reasons.push('brand-glued'); }

    // O próprio urlscan pescou o domínio no Certificate Transparency por parecer
    // suspeito — é sinal independente do nosso.
    if (hit.source === 'certstream-suspicious') { score += 20; reasons.push('certstream'); }

    // Página no ar responde por si: domínio parqueado não engana ninguém.
    if (String(hit.pageStatus || '') === '200' && hit.title) { score += 10; reasons.push('live-page'); }

    return { score: Math.min(score, 100), reasons };
}

const hitId = (profileId, apexDomain) => `${profileId}:${apexDomain}`;

export function hitFromResult(result, { profileId, ownerId, terms, now }) {
    const page = result?.page || {};
    const task = result?.task || {};
    const apexDomain = String(page.apexDomain || task.apexDomain || '').toLowerCase();
    if (!apexDomain) return null;

    const seenAt = task.time || now;
    const term = (terms || []).find((value) => apexDomain.includes(value)) || null;
    const base = {
        id: hitId(profileId, apexDomain),
        profileId,
        ownerId,
        apexDomain,
        domain: String(page.domain || task.domain || apexDomain).toLowerCase(),
        url: task.url || '',
        term,
        apexAgeDays: Number.isFinite(Number(page.apexDomainAgeDays)) ? Number(page.apexDomainAgeDays) : null,
        title: page.title || '',
        pageStatus: page.status || '',
        country: page.country || '',
        asn: page.asnname || '',
        ip: page.ip || '',
        source: task.source || '',
        scanUrl: task.uuid ? `https://urlscan.io/result/${task.uuid}/` : (result?.result || ''),
        screenshot: result?.screenshot || '',
        firstSeen: seenAt,
        lastSeen: seenAt,
        status: 'new',
        // Preenchido por recheckHitsDns, independente do urlscan reescanear ou
        // não — resolução DNS direta contra os nameservers, não um dado que o
        // urlscan já trouxe. Começa vazio: o achado pode ser mais novo que a
        // primeira rodada de recheck.
        dns: { checkedAt: null, a: [], aaaa: [], mx: [], ns: [], events: [] },
    };
    return { ...base, ...scoreHit(base) };
}

/**
 * Junta o que a rodada achou com o que já estava gravado.
 *
 * A chave é o domínio apex, não o scan: o urlscan re-escaneia o mesmo domínio
 * várias vezes por dia e, se a chave fosse o scan, o mesmo phishing voltaria à
 * lista de novos a cada rodada. Re-scan só empurra `lastSeen`.
 *
 * Triagem manda sobre a rodada: domínio dispensado nunca volta a aparecer como
 * novo, e confirmado não é rebaixado.
 */
export function mergeHits(existing, incoming) {
    const byId = new Map((Array.isArray(existing) ? existing : []).map((hit) => [hit.id, hit]));
    const added = [];

    for (const hit of incoming || []) {
        if (!hit) continue;
        const current = byId.get(hit.id);
        if (!current) {
            byId.set(hit.id, hit);
            added.push(hit);
            continue;
        }
        byId.set(hit.id, {
            ...current,
            lastSeen: hit.lastSeen > current.lastSeen ? hit.lastSeen : current.lastSeen,
            // O scan mais recente vale para o que muda no tempo; a triagem e o
            // primeiro avistamento são nossos e ficam.
            title: hit.title || current.title,
            pageStatus: hit.pageStatus || current.pageStatus,
            scanUrl: hit.scanUrl || current.scanUrl,
            screenshot: hit.screenshot || current.screenshot,
            score: Math.max(current.score, hit.score),
            reasons: [...new Set([...(current.reasons || []), ...(hit.reasons || [])])],
        });
    }

    return { hits: [...byId.values()], added };
}

// Novo envelhece e sai; dispensado é a lista de falso positivo que faz a rodada
// seguinte valer a pena; confirmado é o resultado do trabalho e não expira.
export function applyRetention(hits, { profileId, now = new Date() } = {}) {
    const cutoff = now.getTime() - PHISH_LIMITS.hitRetentionDays * 86400000;
    const ofProfile = (hit) => !profileId || hit.profileId === profileId;
    const kept = [];
    const fresh = [];
    const triaged = [];

    for (const hit of hits || []) {
        if (!ofProfile(hit)) { kept.push(hit); continue; }
        if (hit.status === 'new') {
            if (new Date(hit.lastSeen).getTime() >= cutoff) fresh.push(hit);
        } else {
            triaged.push(hit);
        }
    }

    const bySeen = (a, b) => String(b.lastSeen).localeCompare(String(a.lastSeen));
    return [
        ...kept,
        ...fresh.sort((a, b) => b.score - a.score || bySeen(a, b)).slice(0, PHISH_LIMITS.newHitsPerProfile),
        ...triaged.sort(bySeen).slice(0, PHISH_LIMITS.triagedPerProfile),
    ];
}

// ─── Resolução DNS contínua ─────────────────────────────────────────────────
// Descoberta (acima) é o urlscan achando o domínio; isto é nosso, independente
// de o urlscan reescanear ou não. Um domínio pode ficar dias parqueado e virar
// A+MX de uma hora pra outra — sem checar isto direto contra os nameservers,
// ninguém percebe até o urlscan resolver revisitar por conta própria, o que
// pode nunca acontecer pra um domínio que não gerou tráfego novo.
//
// Três sinais, cada um mais forte que o anterior:
//   went-live      — não resolvia nada, passou a ter A/AAAA (infra sendo montada)
//   mx-appeared    — passou a aceitar e-mail (pronto pra campanha por e-mail,
//                    não só página fake)
//   infra-changed  — já resolvia e trocou de IP ou de nameserver (o atacante
//                    mudou de casa depois de já estar no ar)

const dnsHasAny = (d) => Boolean(d && ((d.a || []).length || (d.aaaa || []).length));

const sameSet = (a, b) => {
    const sa = new Set(a || []);
    const sb = new Set(b || []);
    if (sa.size !== sb.size) return false;
    for (const value of sa) if (!sb.has(value)) return false;
    return true;
};

/**
 * Resolve os quatro tipos de registro que decidem os três sinais acima.
 * Resolvers entram por parâmetro (mesmo molde de createUrlscanSearch): o
 * teste não toca a rede, e index.js injeta dns.promises.* de verdade.
 * Uma falha de tipo específico (ex: domínio sem MX) não derruba os outros —
 * um domínio sem registro nenhum não é erro, é o estado "ainda não resolve".
 */
export function createDnsResolver({ resolve4, resolve6, resolveMx, resolveNs }) {
    const safe = async (fn, domain) => {
        try { return await fn(domain); } catch { return []; }
    };
    return async function resolveDomainDns(domain) {
        const [a, aaaa, mx, ns] = await Promise.all([
            safe(resolve4, domain),
            safe(resolve6, domain),
            safe(resolveMx, domain),
            safe(resolveNs, domain),
        ]);
        return { a, aaaa, ns, mx: mx.map((record) => record?.exchange).filter(Boolean) };
    };
}

/**
 * Compara o estado novo com o gravado e decide quais sinais dispararam.
 * Puro: quem resolve o DNS de verdade é resolveDomainDns, isto só compara.
 */
export function markHitDns(hit, resolved, { at } = {}) {
    const prev = hit.dns || { checkedAt: null, a: [], aaaa: [], mx: [], ns: [], events: [] };
    const next = {
        checkedAt: at,
        a: resolved.a || [], aaaa: resolved.aaaa || [], mx: resolved.mx || [], ns: resolved.ns || [],
        events: [...(prev.events || [])],
    };

    const newReasons = [];
    let scoreBump = 0;

    if (!dnsHasAny(prev) && dnsHasAny(next)) {
        next.events.push({ at, kind: 'went-live' });
        newReasons.push('dns-went-live');
        scoreBump += 25;
    }
    if (!(prev.mx || []).length && next.mx.length) {
        next.events.push({ at, kind: 'mx-appeared' });
        newReasons.push('dns-mx-appeared');
        scoreBump += 20;
    }
    // Só conta troca de infra depois de já estar no ar — a primeira vez que A/NS
    // aparece já é 'went-live' acima, não uma "mudança" de algo que não existia.
    if (dnsHasAny(prev) && dnsHasAny(next) && (!sameSet(prev.a, next.a) || !sameSet(prev.ns, next.ns))) {
        next.events.push({ at, kind: 'infra-changed' });
        newReasons.push('dns-infra-changed');
        scoreBump += 15;
    }

    if (!newReasons.length) return { ...hit, dns: next };
    return {
        ...hit,
        dns: next,
        score: Math.min(100, hit.score + scoreBump),
        reasons: [...new Set([...(hit.reasons || []), ...newReasons])],
    };
}

// Mesma cadência da descoberta: recheck de hora em hora é o suficiente pra
// pegar a infra subindo sem martelar os nameservers de domínio nenhum.
export async function recheckHitsDns({ store, resolveDns, now = new Date(), intervalMs = PHISH_LIMITS.runIntervalMs }) {
    const cutoff = now.getTime() - intervalMs;
    const nowIso = now.toISOString();
    let checked = 0;
    let changed = 0;

    for (const hit of store.allActive()) {
        const checkedAt = hit.dns?.checkedAt ? new Date(hit.dns.checkedAt).getTime() : 0;
        if (checkedAt > cutoff) continue;
        checked += 1;

        let resolved;
        try {
            resolved = await resolveDns(hit.apexDomain);
        } catch {
            resolved = { a: [], aaaa: [], mx: [], ns: [] };
        }

        const updated = markHitDns(hit, resolved, { at: nowIso });
        if (updated.dns.events.length > (hit.dns?.events?.length || 0)) changed += 1;
        store.updateHit(hit.id, updated);
    }

    return { checked, changed };
}

export function selectDueProfiles(profiles, runs = {}, now = new Date()) {
    const cutoff = now.getTime() - PHISH_LIMITS.runIntervalMs;
    return (Array.isArray(profiles) ? profiles : []).filter((profile) => {
        if (!profile || !(profile.brands || []).length) return false;
        const last = runs[profile.id]?.lastRunAt;
        if (!last) return true;
        const at = new Date(last).getTime();
        return !Number.isFinite(at) || at <= cutoff;
    });
}

/**
 * O único caminho deste módulo até a rede, e ele só sabe buscar.
 *
 * Não existe função de submissão aqui de propósito: submeter um scan publica a
 * URL no urlscan, e nenhuma URL de cliente pode virar scan público por conta de
 * uma varredura nossa.
 */
export function createUrlscanSearch({ apiKey, fetchImpl = fetch, timeoutMs = 15000 }) {
    return async function search(query, size = PHISH_LIMITS.searchSize) {
        const url = new URL(SEARCH_ENDPOINT);
        url.searchParams.set('q', query);
        url.searchParams.set('size', String(size));

        const response = await fetchImpl(url.toString(), {
            headers: { 'API-Key': apiKey, Accept: 'application/json' },
            signal: AbortSignal.timeout(timeoutMs),
        });
        if (response.status === 429) throw createPhishError(429, 'cota do urlscan esgotada');
        if (!response.ok) throw createPhishError(502, `urlscan respondeu ${response.status}`);
        const body = await response.json();
        return Array.isArray(body?.results) ? body.results : [];
    };
}

// A chave pessoal vence a da plataforma. O grupo acompanha a chave efetiva,
// inclusive quando duas contas usam a mesma credencial, sem expor seu valor.
export function createOwnerUrlscanClient({ getUserApiKey, platformApiKey, fetchImpl = fetch }) {
    return (ownerId) => {
        const apiKey = getUserApiKey(ownerId) || platformApiKey;
        if (!apiKey) return { search: null, quotaGroup: null };
        return {
            search: createUrlscanSearch({ apiKey, fetchImpl }),
            quotaGroup: createHash('sha256').update(apiKey).digest('hex'),
        };
    };
}

export async function runProfileWatch({ store, profile, search, now = new Date() }) {
    const terms = normalizeBrands(profile.brands);
    if (!terms.length) throw createPhishError(400, 'perfil sem marcas para vigiar');

    const startedAt = now.toISOString();
    try {
        const results = await search(buildQuery(terms));
        const incoming = [];
        for (const result of results) {
            const hit = hitFromResult(result, { profileId: profile.id, ownerId: profile.ownerId, terms, now: startedAt });
            if (hit) incoming.push(hit);
        }
        const added = store.absorb(profile.id, incoming, now);
        store.recordRun(profile.id, { lastRunAt: startedAt, lastStatus: 'success', lastError: null, lastFound: added });
        return { found: added, scanned: incoming.length };
    } catch (error) {
        store.recordRun(profile.id, {
            lastRunAt: startedAt,
            lastStatus: 'error',
            lastError: error.publicMessage || 'falha ao consultar o urlscan',
            lastFound: 0,
        });
        throw error;
    }
}

export async function runDuePhishWatch({ store, profiles, now = new Date(), runOne, quotaGroupFor = () => 'shared' }) {
    const due = selectDueProfiles(profiles, store.runs(), now);
    const result = { attempted: 0, completed: 0, failed: 0 };
    const exhausted = new Set();
    for (const profile of due) {
        const quotaGroup = quotaGroupFor(profile);
        if (exhausted.has(quotaGroup)) continue;
        result.attempted += 1;
        try {
            await runOne(profile);
            result.completed += 1;
        } catch (error) {
            result.failed += 1;
            console.error('phishing watch scheduled run failed:', error.message || error);
            // Para apenas os perfis que compartilham a credencial esgotada.
            // Outras contas com BYOK ainda podem executar nesta rodada.
            if (error.status === 429) exhausted.add(quotaGroup);
        }
    }
    return result;
}

export function createPhishWatchStore({ filePath, readFileSync, writeJsonAtomic }) {
    let state = { hits: [], runs: {} };
    try {
        const parsed = JSON.parse(readFileSync(filePath, 'utf8'));
        if (parsed && typeof parsed === 'object') {
            state = {
                hits: Array.isArray(parsed.hits) ? parsed.hits.filter((hit) => hit && hit.id && hit.profileId) : [],
                runs: parsed.runs && typeof parsed.runs === 'object' ? parsed.runs : {},
            };
        }
    } catch { /* store vazio: a vigilância recomeça, a tela não cai */ }

    const save = () => writeJsonAtomic(filePath, state);

    return {
        runs: () => state.runs,
        runOf: (profileId) => state.runs[profileId] || null,
        list(ownerId, { profileId, status } = {}) {
            return state.hits
                .filter((hit) => hit.ownerId === ownerId)
                .filter((hit) => !profileId || hit.profileId === profileId)
                .filter((hit) => !status || hit.status === status)
                .sort((a, b) => b.score - a.score || String(b.lastSeen).localeCompare(String(a.lastSeen)));
        },
        absorb(profileId, incoming, now = new Date()) {
            // Dispensado é allowlist: o domínio continua gravado justamente para
            // a rodada seguinte não trazê-lo de volta como novidade.
            const dismissed = new Set(state.hits
                .filter((hit) => hit.profileId === profileId && hit.status === 'dismissed')
                .map((hit) => hit.id));
            const fresh = incoming.filter((hit) => !dismissed.has(hit.id));
            const { hits, added } = mergeHits(state.hits, fresh);
            state.hits = applyRetention(hits, { profileId, now });
            save();
            return added.length;
        },
        setStatus(ownerId, hitId, status, now = new Date().toISOString()) {
            if (!HIT_STATUS.includes(status)) throw createPhishError(400, 'estado inválido');
            const hit = state.hits.find((item) => item.id === hitId && item.ownerId === ownerId);
            if (!hit) throw createPhishError(404, 'achado não encontrado');
            hit.status = status;
            hit.triagedAt = now;
            save();
            return hit;
        },
        recordRun(profileId, run) {
            state.runs[profileId] = { ...(state.runs[profileId] || {}), ...run };
            save();
            return state.runs[profileId];
        },
        // Todo dono, todo perfil — o recheck de DNS não filtra por quem está
        // olhando a tela, roda em cima de tudo que ainda pode virar phishing de
        // verdade. Dispensado sai porque já é falso positivo confirmado: não há
        // porquê continuar gastando consulta DNS nele.
        allActive() {
            return state.hits.filter((hit) => hit.status !== 'dismissed');
        },
        updateHit(hitId, updated) {
            const idx = state.hits.findIndex((item) => item.id === hitId);
            if (idx === -1) return null;
            state.hits[idx] = updated;
            save();
            return updated;
        },
        dropProfile(profileId) {
            state.hits = state.hits.filter((hit) => hit.profileId !== profileId);
            delete state.runs[profileId];
            save();
        },
    };
}
