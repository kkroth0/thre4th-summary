import test from 'node:test';
import assert from 'node:assert/strict';
import { mergeIntoStories, rareTerms, STORY_RETENTION_DAYS } from '../newsStories.js';

const NOW = new Date('2026-08-12T12:00:00Z');
const daysBefore = (n) => new Date(NOW.getTime() - n * 86400000).toISOString();

const item = (over = {}) => ({
    title: 'Untitled', description: '', link: `https://x.example/${Math.random()}`,
    source: 'Feed', pubDate: NOW.toISOString(), score: 50, severity: 'High',
    cves: [], actors: [], categories: [], primaryCategory: null, ...over,
});

test('termos raros descartam stopwords e vocabulário comum de segurança', () => {
    assert.deepEqual(rareTerms('New Oracle EBS vulnerability exploited by researchers'), ['oracle']);
    assert.deepEqual(rareTerms('Cl0p exploits Oracle EBS zero-day'), ['cl0p', 'oracle']);
});

test('CVE em comum une, mesmo com títulos sem palavra em comum', () => {
    const stories = mergeIntoStories([], [
        item({ title: 'Cl0p exploits Oracle EBS', link: 'https://a.example/1', cves: ['CVE-2025-61882'] }),
        item({ title: 'Emergency fix shipped for ERP suite', link: 'https://b.example/2', cves: ['CVE-2025-61882'] }),
    ], NOW);
    assert.equal(stories.length, 1);
    assert.equal(stories[0].sources.length, 2);
});

test('ator em comum une quando há também um termo raro em comum', () => {
    const cl0p = [{ id: 'a1', name: 'Cl0p', matched: 'Cl0p', via: 'context' }];
    const stories = mergeIntoStories([], [
        item({ title: 'Cl0p claims Oracle intrusion', link: 'https://a.example/1', actors: cl0p }),
        item({ title: 'Oracle victims listed by the gang', link: 'https://b.example/2', actors: cl0p }),
    ], NOW);
    assert.equal(stories.length, 1);
});

test('ator em comum sem termo raro em comum não une', () => {
    const cl0p = [{ id: 'a1', name: 'Cl0p', matched: 'Cl0p', via: 'context' }];
    const stories = mergeIntoStories([], [
        item({ title: 'Cl0p claims Oracle intrusion', link: 'https://a.example/1', actors: cl0p }),
        item({ title: 'Cl0p adds Fortra victims', link: 'https://b.example/2', actors: cl0p }),
    ], NOW);
    assert.equal(stories.length, 2);
});

// rareTerms deixa {cl0p, oracle} nos dois títulos: 'exploits', 'flaw', 'abused',
// 'ransomware' e 'zero-day' são vocabulário comum e não contam.
test('Jaccard alto dos termos raros une', () => {
    const stories = mergeIntoStories([], [
        item({ title: 'Cl0p exploits Oracle EBS zero-day', link: 'https://a.example/1' }),
        item({ title: 'Oracle EBS flaw abused by Cl0p ransomware', link: 'https://b.example/2' }),
    ], NOW);
    assert.equal(stories.length, 1);
});

test('Jaccard exige pelo menos dois termos raros de cada lado', () => {
    const stories = mergeIntoStories([], [
        item({ title: 'Oracle patched', link: 'https://a.example/1' }),
        item({ title: 'Oracle updated', link: 'https://b.example/2' }),
    ], NOW);
    assert.equal(stories.length, 2, 'um termo raro de cada lado não é evidência');
});

test('história em silêncio há mais de 14 dias não recebe item novo', () => {
    const old = mergeIntoStories([], [item({ title: 'Cl0p exploits Oracle EBS', link: 'https://a.example/1', cves: ['CVE-1'], pubDate: daysBefore(20) })], new Date(NOW.getTime() - 20 * 86400000));
    const merged = mergeIntoStories(old, [item({ title: 'Cl0p exploits Oracle EBS again', link: 'https://b.example/2', cves: ['CVE-1'] })], NOW);
    assert.equal(merged.length, 2);
});

// A ponte precisa de evidência real dos dois lados: CVE com a primeira
// história, e ator MAIS um termo raro (oracle) com a segunda. Só o nome do
// ator em comum não une — é o que o teste anterior garante.
test('um item que faz a ponte funde duas histórias e mantém o id da mais antiga', () => {
    const seed = mergeIntoStories([], [
        item({ title: 'Oracle EBS emergency patch published', link: 'https://a.example/1', cves: ['CVE-1'], pubDate: daysBefore(3) }),
        item({ title: 'Cl0p leak site lists Oracle victims', link: 'https://b.example/2', actors: [{ id: 'a1', name: 'Cl0p', matched: 'Cl0p', via: 'context' }], pubDate: daysBefore(2) }),
    ], NOW);
    assert.equal(seed.length, 2);
    const oldestId = seed.find((s) => s.sources[0].link === 'https://a.example/1').id;

    const bridged = mergeIntoStories(seed, [item({
        title: 'Cl0p behind the Oracle EBS attacks', link: 'https://c.example/3',
        cves: ['CVE-1'], actors: [{ id: 'a1', name: 'Cl0p', matched: 'Cl0p', via: 'context' }],
    })], NOW);
    assert.equal(bridged.length, 1);
    assert.equal(bridged[0].id, oldestId, 'links já compartilhados continuam valendo');
    assert.equal(bridged[0].sources.length, 3);
});

test('o mesmo link não entra duas vezes', () => {
    const one = mergeIntoStories([], [item({ title: 'Cl0p exploits Oracle EBS', link: 'https://a.example/1', cves: ['CVE-1'] })], NOW);
    const twice = mergeIntoStories(one, [item({ title: 'Cl0p exploits Oracle EBS', link: 'https://a.example/1', cves: ['CVE-1'] })], NOW);
    assert.equal(twice[0].sources.length, 1);
});

test('a história herda título e score do item de maior score', () => {
    const stories = mergeIntoStories([], [
        item({ title: 'Minor writeup', link: 'https://a.example/1', cves: ['CVE-1'], score: 40 }),
        item({ title: 'CISA issues emergency directive', link: 'https://b.example/2', cves: ['CVE-1'], score: 90 }),
    ], NOW);
    assert.equal(stories[0].title, 'CISA issues emergency directive');
    assert.equal(stories[0].score, 90);
});

test('histórias além da retenção são podadas', () => {
    const long = STORY_RETENTION_DAYS + 5;
    const ancient = mergeIntoStories([], [item({ title: 'Old story about Fortra GoAnywhere', link: 'https://a.example/1', pubDate: daysBefore(long) })], new Date(NOW.getTime() - long * 86400000));
    assert.equal(ancient.length, 1, 'a história existia antes da poda');
    assert.equal(mergeIntoStories(ancient, [], NOW).length, 0);
});

test('determinismo: a mesma entrada duas vezes dá a mesma saída', () => {
    const input = [
        item({ title: 'Cl0p exploits Oracle EBS zero-day', link: 'https://a.example/1' }),
        item({ title: 'Oracle EBS flaw abused by Cl0p ransomware', link: 'https://b.example/2' }),
    ];
    assert.deepEqual(mergeIntoStories([], input, NOW), mergeIntoStories([], input, NOW));
});

test('entrada vazia devolve o estado intacto', () => {
    assert.deepEqual(mergeIntoStories([], [], NOW), []);
    assert.deepEqual(mergeIntoStories(null, null, NOW), []);
});
