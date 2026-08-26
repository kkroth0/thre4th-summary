import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

import {
    PHISH_LIMITS, buildQuery, normalizeBrandTerm, normalizeBrands, scoreHit, hitFromResult,
    mergeHits, applyRetention, selectDueProfiles, createUrlscanSearch, createPhishWatchStore,
    runProfileWatch, runDuePhishWatch,
} from '../phishingWatch.js';

const FIXTURE = JSON.parse(fs.readFileSync(new URL('./fixtures/urlscanSearch.json', import.meta.url), 'utf8'));
const NOW = new Date('2026-08-26T00:00:00Z');

const memoryStore = () => {
    let saved = null;
    const store = createPhishWatchStore({
        filePath: '/dev/null',
        readFileSync: () => { throw new Error('vazio'); },
        writeJsonAtomic: (_path, value) => { saved = value; },
    });
    return { store, saved: () => saved };
};

const profile = (over = {}) => ({ id: 'p1', ownerId: 'u1', name: 'Cliente', brands: ['bancochile'], ...over });

// ─── Termos ─────────────────────────────────────────────────────────────────

test('domínio digitado vira o rótulo da marca', () => {
    assert.equal(normalizeBrandTerm('bancoxpto.com.br'), 'bancoxpto');
    assert.equal(normalizeBrandTerm('https://www.bancoxpto.com.br/login'), 'bancoxpto');
    assert.equal(normalizeBrandTerm('  BancoXPTO  '), 'bancoxpto');
});

// `*pix*` casa com "pixel", "pixar" e mais meio dicionário: termo curto não
// vigia marca nenhuma, só enche a tela.
test('termo curto demais, longo demais ou com caractere estranho é recusado', () => {
    assert.equal(normalizeBrandTerm('pix'), null);
    assert.equal(normalizeBrandTerm('a'.repeat(PHISH_LIMITS.termMax + 1)), null);
    assert.equal(normalizeBrandTerm('banco xpto'), null);
    assert.equal(normalizeBrandTerm('-banco'), null);
    assert.equal(normalizeBrandTerm(''), null);
});

test('marcas repetidas e inválidas caem, e o limite por perfil é respeitado', () => {
    assert.deepEqual(normalizeBrands(['BancoXPTO', 'bancoxpto.com.br', 'pix', 'xptobank']), ['bancoxpto', 'xptobank']);
    assert.throws(
        () => normalizeBrands(Array.from({ length: PHISH_LIMITS.brandsPerProfile + 1 }, (_, i) => `marca${i}`)),
        /no máximo/,
    );
});

// ─── Query ──────────────────────────────────────────────────────────────────

// Uma busca por perfil, não uma por marca: a cota de 1000/dia não pode depender
// de quantas marcas o cliente cadastrou.
test('as marcas viram uma query só, com corte de idade e janela', () => {
    const query = buildQuery(['bancoxpto', 'xptobank']);
    assert.equal(
        query,
        'page.domain:(*bancoxpto* OR *xptobank*) AND page.apexDomainAgeDays:<30 AND date:>now-24h',
    );
});

test('perfil sem marca não vira query', () => {
    assert.throws(() => buildQuery([]), /nenhuma marca/);
    assert.throws(() => buildQuery(['pix']), /nenhuma marca/);
});

// ─── Score ──────────────────────────────────────────────────────────────────

test('domínio de hoje com a marca colada em outra palavra pontua alto', () => {
    const { score, reasons } = scoreHit({
        apexDomain: 'adobe-bancochile-bing.com.ph', term: 'bancochile',
        apexAgeDays: 0, source: 'certstream-suspicious', pageStatus: '200', title: 'Redirecting...',
    });
    assert.ok(score >= 90, `score baixo demais: ${score}`);
    assert.deepEqual(reasons, ['fresh-domain', 'brand-glued', 'certstream', 'live-page']);
});

test('o domínio legítimo da marca não ganha o sinal de typosquat', () => {
    const { reasons } = scoreHit({ apexDomain: 'bancochile.cl', term: 'bancochile', apexAgeDays: 400 });
    assert.ok(!reasons.includes('brand-glued'));
    assert.deepEqual(reasons, ['recent-domain']);
});

// ─── Resultado do urlscan → achado ──────────────────────────────────────────

test('o resultado real do urlscan vira achado com a marca que casou', () => {
    const hit = hitFromResult(FIXTURE.results[0], {
        profileId: 'p1', ownerId: 'u1', terms: ['bancochile'], now: NOW.toISOString(),
    });
    assert.equal(hit.apexDomain, 'adobe-bancochile-bing.com.ph');
    assert.equal(hit.term, 'bancochile');
    assert.equal(hit.apexAgeDays, 0);
    assert.equal(hit.status, 'new');
    assert.match(hit.scanUrl, /^https:\/\/urlscan\.io\/result\//);
    assert.ok(hit.score > 0);
});

test('resultado sem domínio não vira achado', () => {
    assert.equal(hitFromResult({ page: {}, task: {} }, { profileId: 'p1', ownerId: 'u1', terms: [], now: NOW.toISOString() }), null);
});

// ─── Deduplicação e triagem ─────────────────────────────────────────────────

// O urlscan re-escaneia o mesmo domínio várias vezes por dia. Se a chave fosse
// o scan, o mesmo phishing voltaria para a lista de novos a cada rodada.
test('o mesmo domínio reaparecendo atualiza o achado em vez de criar outro', () => {
    const first = { id: 'p1:mau.com', profileId: 'p1', apexDomain: 'mau.com', status: 'new', score: 60, reasons: ['fresh-domain'], firstSeen: '2026-08-25T10:00:00Z', lastSeen: '2026-08-25T10:00:00Z', title: '' };
    const again = { ...first, lastSeen: '2026-08-25T18:00:00Z', score: 80, reasons: ['live-page'], title: 'Login' };

    const { hits, added } = mergeHits([first], [again]);
    assert.equal(hits.length, 1);
    assert.equal(added.length, 0, 'o re-scan contou como achado novo');
    assert.equal(hits[0].firstSeen, '2026-08-25T10:00:00Z', 'o primeiro avistamento é nosso e não muda');
    assert.equal(hits[0].lastSeen, '2026-08-25T18:00:00Z');
    assert.equal(hits[0].score, 80);
    assert.deepEqual(hits[0].reasons, ['fresh-domain', 'live-page']);
});

test('dispensar tira o falso positivo das rodadas seguintes', () => {
    const { store } = memoryStore();
    const results = FIXTURE.results.slice(0, 1);
    const incoming = results.map((r) => hitFromResult(r, { profileId: 'p1', ownerId: 'u1', terms: ['bancochile'], now: NOW.toISOString() }));

    assert.equal(store.absorb('p1', incoming, NOW), 1);
    store.setStatus('u1', incoming[0].id, 'dismissed');

    assert.equal(store.absorb('p1', incoming, NOW), 0, 'o dispensado voltou como novidade');
    assert.equal(store.list('u1', { profileId: 'p1', status: 'new' }).length, 0);
    assert.equal(store.list('u1', { profileId: 'p1', status: 'dismissed' })[0].status, 'dismissed');
});

test('achado de um dono não aparece para outro', () => {
    const { store } = memoryStore();
    store.absorb('p1', [hitFromResult(FIXTURE.results[0], { profileId: 'p1', ownerId: 'u1', terms: ['bancochile'], now: NOW.toISOString() })], NOW);
    assert.equal(store.list('u2').length, 0);
    assert.throws(() => store.setStatus('u2', 'p1:adobe-bancochile-bing.com.ph', 'confirmed'), /não encontrado/);
});

// ─── Retenção ───────────────────────────────────────────────────────────────

test('novo expira, confirmado e dispensado ficam', () => {
    const old = (id, status) => ({ id, profileId: 'p1', status, score: 50, lastSeen: '2026-07-01T00:00:00Z' });
    const kept = applyRetention([
        old('p1:velho', 'new'),
        old('p1:confirmado', 'confirmed'),
        old('p1:dispensado', 'dismissed'),
        { ...old('p1:recente', 'new'), lastSeen: '2026-08-25T00:00:00Z' },
    ], { profileId: 'p1', now: NOW });

    assert.deepEqual(kept.map((hit) => hit.id).sort(), ['p1:confirmado', 'p1:dispensado', 'p1:recente']);
});

test('a retenção de um perfil não toca nos achados de outro', () => {
    const kept = applyRetention([
        { id: 'p2:velho', profileId: 'p2', status: 'new', score: 10, lastSeen: '2026-01-01T00:00:00Z' },
    ], { profileId: 'p1', now: NOW });
    assert.equal(kept.length, 1);
});

// ─── Agendamento ────────────────────────────────────────────────────────────

test('vence de hora em hora, e perfil sem marca nunca roda', () => {
    const runs = {
        p1: { lastRunAt: '2026-08-25T22:00:00Z' },
        p2: { lastRunAt: '2026-08-25T23:59:00Z' },
    };
    const due = selectDueProfiles([
        profile({ id: 'p1' }),
        profile({ id: 'p2' }),
        profile({ id: 'p3' }),
        profile({ id: 'p4', brands: [] }),
    ], runs, NOW);

    assert.deepEqual(due.map((p) => p.id), ['p1', 'p3'], 'p2 rodou agora há pouco, p4 não tem marca');
});

// ─── Rede ───────────────────────────────────────────────────────────────────

// A regra que não pode ser quebrada: este módulo só sabe BUSCAR. Submeter um
// scan publicaria a URL do cliente no urlscan.
test('o único endpoint tocado é o de busca, com a chave no cabeçalho', async () => {
    const calls = [];
    const search = createUrlscanSearch({
        apiKey: 'chave',
        fetchImpl: async (url, init) => {
            calls.push({ url, init });
            return { ok: true, status: 200, json: async () => FIXTURE };
        },
    });

    const results = await search('page.domain:(*bancochile*)');
    assert.equal(results.length, FIXTURE.results.length);
    assert.equal(calls.length, 1);
    const { url, init } = calls[0];
    assert.ok(url.startsWith('https://urlscan.io/api/v1/search/'), url);
    assert.ok(!/\/scan\//.test(url), 'submissão de scan é proibida aqui');
    assert.equal(init.headers['API-Key'], 'chave');
});

test('cota estourada e erro do urlscan viram erro tratado', async () => {
    const status = (code) => createUrlscanSearch({ apiKey: 'k', fetchImpl: async () => ({ ok: false, status: code, json: async () => ({}) }) });
    await assert.rejects(status(429)('q'), /cota do urlscan/);
    await assert.rejects(status(500)('q'), /urlscan respondeu 500/);
});

// ─── Rodada ─────────────────────────────────────────────────────────────────

test('a rodada grava os achados e o estado da execução', async () => {
    const { store } = memoryStore();
    const result = await runProfileWatch({
        store, profile: profile(), now: NOW,
        search: async () => FIXTURE.results,
    });

    assert.equal(result.found, store.list('u1', { profileId: 'p1' }).length);
    assert.equal(store.runOf('p1').lastStatus, 'success');
    assert.equal(store.runOf('p1').lastRunAt, NOW.toISOString());
});

test('falha na busca registra o erro e não apaga o que já foi achado', async () => {
    const { store } = memoryStore();
    await runProfileWatch({ store, profile: profile(), now: NOW, search: async () => FIXTURE.results });
    const before = store.list('u1', { profileId: 'p1' }).length;

    await assert.rejects(runProfileWatch({
        store, profile: profile(), now: new Date('2026-08-26T02:00:00Z'),
        search: async () => { throw Object.assign(new Error('x'), { status: 502, publicMessage: 'urlscan respondeu 500' }); },
    }));

    assert.equal(store.list('u1', { profileId: 'p1' }).length, before);
    assert.equal(store.runOf('p1').lastStatus, 'error');
    assert.equal(store.runOf('p1').lastError, 'urlscan respondeu 500');
});

// Cota é do dia inteiro: insistir nos outros perfis só queima o que sobrou.
test('429 interrompe a rodada em vez de varrer o resto dos perfis', async () => {
    const { store } = memoryStore();
    const seen = [];
    const outcome = await runDuePhishWatch({
        store,
        profiles: [profile({ id: 'p1' }), profile({ id: 'p2' }), profile({ id: 'p3' })],
        now: NOW,
        runOne: async (p) => {
            seen.push(p.id);
            throw Object.assign(new Error('cota'), { status: 429, publicMessage: 'cota do urlscan esgotada' });
        },
    });

    assert.deepEqual(seen, ['p1']);
    assert.equal(outcome.attempted, 1);
    assert.equal(outcome.failed, 1);
});

test('perfil que falha não derruba os outros', async () => {
    const { store } = memoryStore();
    const outcome = await runDuePhishWatch({
        store,
        profiles: [profile({ id: 'p1' }), profile({ id: 'p2' })],
        now: NOW,
        runOne: async (p) => { if (p.id === 'p1') throw Object.assign(new Error('x'), { status: 502 }); },
    });

    assert.equal(outcome.attempted, 2);
    assert.equal(outcome.completed, 1);
    assert.equal(outcome.failed, 1);
});
