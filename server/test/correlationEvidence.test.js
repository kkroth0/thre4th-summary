import test from 'node:test';
import assert from 'node:assert/strict';
import { explainCorrelation } from '../correlationEvidence.js';

test('atribuição compartilhada usa apenas os artigos que realmente citaram a entidade', () => {
    const actor = { id: 'a1', name: 'APT29' };
    const evidence = explainCorrelation({
        actors: [actor], malware: [], campaigns: [],
        sources: [
            { link: 'https://a.example/1', title: 'A', actors: [actor] },
            { link: 'https://a.example/2', title: 'B', actors: [actor] },
            { link: 'https://a.example/3', title: 'C', actors: [] },
        ],
    });
    const hit = evidence.find((entry) => entry.type === 'actor');
    assert.deepEqual(hit.sourceLinks, ['https://a.example/1', 'https://a.example/2']);
});

const src = (over = {}) => ({
    link: `https://x.example/${Math.random()}`, source: 'Feed', title: 'Untitled',
    pubDate: '2026-08-11T12:00:00Z', score: 50, severity: 'High', cves: [], iocs: null, ...over,
});

const story = (over = {}) => ({
    id: 's1', title: 'Untitled', firstSeen: '2026-08-11T12:00:00Z', lastSeen: '2026-08-11T12:00:00Z',
    cves: [], actors: [], malware: [], campaigns: [], categories: [], primaryCategory: null, score: 50, sources: [], ...over,
});

test('história de uma fonte só não tem nada pra correlacionar', () => {
    assert.deepEqual(explainCorrelation(story({ sources: [src()] })), []);
    assert.deepEqual(explainCorrelation(null), []);
    assert.deepEqual(explainCorrelation(story({ sources: [] })), []);
});

test('CVE em >=2 fontes aparece; CVE em só 1 fonte nunca aparece', () => {
    const s = story({
        sources: [
            src({ link: 'https://a.example/1', cves: ['CVE-2026-1', 'CVE-2026-2'] }),
            src({ link: 'https://b.example/2', cves: ['CVE-2026-1'] }),
        ],
    });
    const evidence = explainCorrelation(s);
    assert.deepEqual(
        evidence.filter((e) => e.type === 'cve'),
        [{ type: 'cve', value: 'CVE-2026-1', sourceLinks: ['https://a.example/1', 'https://b.example/2'] }],
    );
});

test('IOC compartilhado aparece com o tipo certo, e só quando >=2 fontes', () => {
    const s = story({
        sources: [
            src({ link: 'https://a.example/1', iocs: { hashes: ['abc'], domains: ['evil.example'], ips: ['1.2.3.4'], urls: [] } }),
            src({ link: 'https://b.example/2', iocs: { hashes: ['abc'], domains: ['evil.example'], ips: [], urls: [] } }),
        ],
    });
    const evidence = explainCorrelation(s);
    assert.ok(evidence.some((e) => e.type === 'ioc-hash' && e.value === 'abc' && e.sourceLinks.length === 2));
    assert.ok(evidence.some((e) => e.type === 'ioc-domain' && e.value === 'evil.example' && e.sourceLinks.length === 2));
    assert.ok(!evidence.some((e) => e.type === 'ioc-ip'), 'IP de uma fonte só não é evidência');
});

test('entidades sem atribuição por fonte não são tratadas como compartilhadas', () => {
    const s = story({
        actors: [{ id: 'a1', name: 'Cl0p', matched: 'Cl0p' }],
        malware: [{ id: 'm1', name: 'LummaC2', matched: 'LummaC2' }],
        sources: [src({ link: 'https://a.example/1' }), src({ link: 'https://b.example/2' })],
    });
    const evidence = explainCorrelation(s);
    assert.ok(!evidence.some((e) => e.type === 'actor'));
    assert.ok(!evidence.some((e) => e.type === 'malware'));
});

test('campanha compartilhada aparece com o nome legível e a contagem real de fontes', () => {
    const s = story({
        campaigns: [{ id: 'c1', name: 'Operation Dream Job', matched: 'Operation Dream Job' }],
        sources: [
            src({ link: 'https://a.example/1', campaigns: ['c1'] }),
            src({ link: 'https://b.example/2', campaigns: ['c1'] }),
        ],
    });
    const evidence = explainCorrelation(s);
    assert.ok(evidence.some((e) => e.type === 'campaign' && e.value === 'Operation Dream Job' && e.sourceLinks.length === 2));
});

test('campanha mencionada por só uma fonte não é evidência de correlação', () => {
    const s = story({
        campaigns: [{ id: 'c1', name: 'Operation Dream Job', matched: 'Operation Dream Job' }],
        sources: [
            src({ link: 'https://a.example/1', campaigns: ['c1'] }),
            src({ link: 'https://b.example/2', campaigns: [] }),
        ],
    });
    const evidence = explainCorrelation(s);
    assert.ok(!evidence.some((e) => e.type === 'campaign'));
});

test('TTP compartilhado por >=2 fontes aparece; por só 1 fonte não aparece', () => {
    const s = story({
        sources: [
            src({ link: 'https://a.example/1', ttps: ['T1566', 'T1486'] }),
            src({ link: 'https://b.example/2', ttps: ['T1566'] }),
        ],
    });
    const evidence = explainCorrelation(s);
    assert.ok(evidence.some((e) => e.type === 'ttp' && e.value === 'T1566' && e.sourceLinks.length === 2));
    assert.ok(!evidence.some((e) => e.type === 'ttp' && e.value === 'T1486'));
});

test('termo raro compartilhado aparece quando não há entidade/CVE/IOC em comum (match por Jaccard puro)', () => {
    const s = story({
        sources: [
            src({ link: 'https://thn.example/1', title: 'SilkParasite Espionage Campaign Targets Central Asian Governments with RATs' }),
            src({ link: 'https://dr.example/2', title: 'SilkParasite Threatens Central Asian Orgs With Flurry of RATs' }),
        ],
    });
    const evidence = explainCorrelation(s);
    assert.ok(evidence.some((e) => e.type === 'rare-term' && e.value === 'silkparasite'));
});

test('termo raro que é o próprio nome de ator/malware não duplica como rare-term', () => {
    const s = story({
        actors: [{ id: 'a1', name: 'Cl0p', matched: 'Cl0p' }],
        sources: [
            src({ link: 'https://a.example/1', title: 'Cl0p claims Oracle intrusion' }),
            src({ link: 'https://b.example/2', title: 'Oracle victims listed by Cl0p' }),
        ],
    });
    const evidence = explainCorrelation(s);
    assert.ok(!evidence.some((e) => e.type === 'rare-term' && e.value === 'cl0p'), 'cl0p já tem chip de ator, não precisa duplicar');
    assert.ok(evidence.some((e) => e.type === 'rare-term' && e.value === 'oracle'), 'oracle não é nome de entidade e deve aparecer');
});
