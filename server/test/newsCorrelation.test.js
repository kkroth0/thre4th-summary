import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { mergeIntoStories, CORRELATION_VERSION, compareNewsSources } from '../newsStories.js';
import { auditCorrelations } from '../correlationAudit.js';
import { correlateNewsFeed } from '../newsCorrelation.js';
import { createStoryStore } from '../newsStoryStore.js';

const fixture = JSON.parse(fs.readFileSync(new URL('./fixtures/news-correlation-2026-10-09.json', import.meta.url), 'utf8'));
const now = new Date(fixture.evaluationAt);
const article = (link, extra = {}) => ({ link: `https://test.example/${link}`, source: link, title: 'Citrix NetScaler emergency patch', pubDate: now.toISOString(), cves: [], actors: [], malware: [], campaigns: [], ...extra });

test('61 publicações reais: todos os 18 pares do mesmo evento e nenhum dos 1812 pares diferentes se misturam', () => {
    const stories = mergeIntoStories([], fixture.items, now);
    const audit = auditCorrelations(fixture.items, stories);
    assert.equal(audit.truePositive, 18);
    assert.equal(audit.falsePositive, 0, JSON.stringify(audit.falseMerges));
    assert.equal(audit.falseNegative, 0, JSON.stringify(audit.missedPairs));
    assert.deepEqual(audit.duplicateLinks, []);
    assert.deepEqual(audit.unassigned, []);
    assert.deepEqual(mergeIntoStories(stories, fixture.items, now), stories, 'refresh com as mesmas publicações é idempotente');
    assert.deepEqual(mergeIntoStories([], [...fixture.items].reverse(), now), stories, 'ordem de coleta não muda os eventos');
});

test('artigo sem CVE não vira ponte entre duas falhas, em qualquer ordem de chegada', () => {
    const papers = [article('a', { cves: ['CVE-2026-11111'] }), article('b', { cves: ['CVE-2026-22222'] }), article('c')];
    for (const order of [[0, 1, 2], [2, 0, 1], [1, 2, 0]]) {
        let stories = [];
        for (const index of order) stories = mergeIntoStories(stories, [papers[index]], now);
        const owners = new Map(stories.flatMap((story) => story.sources.map((source) => [source.link, story.id])));
        assert.notEqual(owners.get(papers[0].link), owners.get(papers[1].link));
        assert.equal(stories.flatMap((story) => story.sources).length, 3);
    }
});

test('fornecedor e produto compartilhados não provam evento sem CVE/contexto específico', () => {
    const vendors = [{ id: 'citrix', name: 'Citrix', matched: 'Citrix' }];
    const stories = mergeIntoStories([], [article('a', { vendors, cves: ['CVE-2026-11111'] }), article('b', { vendors })], now);
    assert.equal(stories.length, 2);
});

test('migração automática desfaz card legado e mantém IDs sem aliases concorrentes', () => {
    const a = article('a', { cves: ['CVE-2026-11111'] });
    const b = article('b', { cves: ['CVE-2026-22222'] });
    const singletons = mergeIntoStories([], [a, b], now);
    const legacy = { ...singletons[0], correlationVersion: 2, cves: [...a.cves, ...b.cves], sources: singletons.flatMap((story) => story.sources), aliases: [singletons[1].id, 'old-shared-link'] };
    const migrated = mergeIntoStories([legacy], [], now);
    assert.equal(migrated.length, 2);
    assert.ok(migrated.every((story) => story.correlationVersion === CORRELATION_VERSION));
    const references = migrated.flatMap((story) => [story.id, ...story.aliases]);
    assert.equal(new Set(references).size, references.length);
    assert.ok(references.includes('old-shared-link'));
    assert.deepEqual(mergeIntoStories(migrated, [], now), migrated);
});

test('nova evidência da mesma URL pode separar um membro de um evento existente', () => {
    const a = article('a', { cves: ['CVE-2026-11111'] });
    const b = article('b', { cves: ['CVE-2026-11111'] });
    const original = mergeIntoStories([], [a, b], now);
    original[0].aliases.push('old-share');
    const changed = mergeIntoStories(original, [{ ...a, cves: ['CVE-2026-22222'] }], now);
    assert.equal(changed.length, 2);
    assert.equal(changed.flatMap((story) => story.sources).length, 2);
    assert.equal(new Set(changed.map((story) => story.id)).size, 2);
    assert.ok(changed.every((story) => !story.aliases.some((id) => changed.some((other) => other !== story && other.id === id))));
    assert.equal(changed.filter((story) => story.aliases.includes('old-share')).length, 1);
});

test('atualizar a fonte que sustentava o merge reavalia também as fontes restantes', () => {
    const left = article('left', { title: 'Unrelated research alpha', cves: ['CVE-2026-11111'], pubDate: '2026-10-07T10:00:00Z' });
    const right = article('right', { title: 'Unrelated research beta', cves: ['CVE-2026-22222'], pubDate: '2026-10-07T11:00:00Z' });
    const bridge = article('bridge', { title: 'Research links two exploits', cves: ['CVE-2026-11111', 'CVE-2026-22222'] });
    const original = mergeIntoStories([], [left, right, bridge], now);
    assert.equal(original.length, 1);
    const separated = mergeIntoStories(original, [{ ...bridge, cves: ['CVE-2026-33333'] }], now);
    assert.equal(separated.length, 3);
    const references = separated.flatMap((story) => [story.id, ...story.aliases]);
    assert.equal(new Set(references).size, references.length);
});

test('CVE de contexto histórico não une a notícia principal à falha antiga', () => {
    const a = article('a', { cves: ['CVE-2026-11111', 'CVE-2026-22222'], topicCves: ['CVE-2026-11111'] });
    const b = article('b', { cves: ['CVE-2026-22222'] });
    assert.equal(mergeIntoStories([], [a, b], now).length, 2);
});

test('técnica comum e palavra genérica não são prova; decisão registra a regra', () => {
    const a = article('a', { title: 'Alleged KillSec ransomware mastermind arrested', ttps: ['T1486'] });
    const b = article('b', { title: 'Alleged Qilin ransomware member arrested', ttps: ['T1486'] });
    assert.equal(compareNewsSources(a, b).sameEvent, false);
    const c = { ...a, cves: ['CVE-2026-11111'] }, d = { ...b, cves: ['CVE-2026-11111'] };
    assert.deepEqual(compareNewsSources(c, d), { sameEvent: true, rule: 'shared-cve', evidence: ['CVE-2026-11111'] });
});

test('erro de persistência não publica itens parcialmente correlacionados e próximo ciclo recupera', () => {
    let written = [];
    let fail = true;
    const store = createStoryStore({ filePath: 'unused', readFileSync: () => JSON.stringify(written), writeJsonAtomic: (_, value) => {
        if (fail) throw new Error('disk full');
        written = value;
    } });
    const items = [article('a'), article('b')];
    assert.throws(() => correlateNewsFeed(items, store, now), /disk full/);
    assert.deepEqual(store.all(), []);
    assert.ok(items.every((item) => !item.storyId));
    fail = false;
    const first = correlateNewsFeed(items, store, now);
    const second = correlateNewsFeed(items, store, now);
    assert.deepEqual(second.items, first.items);
    assert.equal(second.stats.unassigned, 0);
});

test('publicação duplicada no histórico interrompe publicação em vez de ocultar a inconsistência', () => {
    const one = mergeIntoStories([], [article('a')], now)[0];
    const store = { all: () => [one, { ...one, id: 'other', aliases: [] }], save: () => assert.fail('estado inválido não deve ser salvo') };
    assert.throws(() => correlateNewsFeed([article('a')], store, now), /multiple events/);
});

test('auditoria sem rótulos não inventa métricas e identifica publicações perdidas/duplicadas', () => {
    const items = [article('a'), article('b')];
    const report = auditCorrelations(items, [{ id: 'one', sources: [items[0]] }, { id: 'two', sources: [items[0]] }]);
    assert.equal(report.precision, null);
    assert.equal(report.recall, null);
    assert.deepEqual(report.duplicateLinks, [items[0].link]);
    assert.deepEqual(report.unassigned, [items[1].link]);
});
