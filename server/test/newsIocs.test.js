import test from 'node:test';
import assert from 'node:assert/strict';
import { extractIOCs } from '../ctiIntel.js';
import { findMentions, harvestResearchIocs, isResearchItem, refangQuery } from '../newsIocs.js';

const item = (over = {}) => ({
    title: 'Kimwolf v7', link: `https://unit42.paloaltonetworks.com/${Math.random()}`,
    pubDate: '2026-08-26T00:00:00Z', layer: 3, ...over,
});

const extract = (t) => extractIOCs(t, { plaintext: true });

test('só a camada de pesquisa é buscada — notícia geral não paga o fetch', async () => {
    const buscados = [];
    const items = [item(), item({ layer: 2 }), item({ layer: 1 }), item({ layer: 3 })];
    const r = await harvestResearchIocs(items, {
        fetchText: async (url) => { buscados.push(url); return 'C2 at 193.143.1[.]131'; },
        extract,
    });
    assert.equal(buscados.length, 2);
    assert.equal(r.colhidos, 2);
    assert.deepEqual(items[0].iocs.ips, ['193.143.1.131']);
    assert.equal(items[1].iocs, undefined, 'layer 2 fica sem colheita');
    assert.ok(isResearchItem(items[3]) && !isResearchItem(items[2]));
});

// Artigo que não carrega for a do ar não pode derrubar o refresh inteiro: feed
// sem IOC é feed; feed que não chega é feed quebrado.
test('artigo que falha não contamina os outros', async () => {
    const items = [item({ link: 'https://ok.example/1' }), item({ link: 'https://ruim.example/2' })];
    const r = await harvestResearchIocs(items, {
        fetchText: async (url) => {
            if (url.includes('ruim')) throw new Error('403');
            return 'hash e9a56961980031a45e578472836576da874512bff50ca3d491fc72e52f7cc7c2';
        },
        extract,
    });
    assert.equal(r.colhidos, 1);
    assert.equal(r.falhas, 1);
    assert.equal(items[0].iocs.hashes.length, 1);
});

test('o teto corta o artigo mais velho, não o mais novo', async () => {
    const items = [
        item({ pubDate: '2026-01-01T00:00:00Z', title: 'velho' }),
        item({ pubDate: '2026-08-26T00:00:00Z', title: 'novo' }),
    ];
    const r = await harvestResearchIocs(items, {
        fetchText: async () => 'C2 at 193.143.1[.]131', extract, maxFetches: 1,
    });
    assert.equal(r.candidatos, 2);
    assert.equal(r.buscados, 1);
    assert.equal(items[1].iocs.ips.length, 1, 'o novo foi colhido');
    assert.equal(items[0].iocs, undefined, 'o velho ficou para o próximo refresh');
});

test('item que já tem IOC não é buscado de novo', async () => {
    let chamadas = 0;
    const items = [item({ iocs: { ips: ['1.2.3.4'], domains: [], hashes: [], urls: [] } })];
    await harvestResearchIocs(items, { fetchText: async () => { chamadas++; return 'x'; }, extract });
    assert.equal(chamadas, 0);
});

// O achado que a planilha quer: não "o IP existe", e sim "saiu no Unit 42,
// atribuído ao FunkSec".
const stories = [{
    id: 'st1', title: 'Kimwolf botnet', actors: [{ id: 'G1', name: 'FunkSec' }], categories: ['Malware'],
    sources: [{
        source: 'Palo Alto Unit 42', link: 'https://unit42.paloaltonetworks.com/kimwolf/',
        title: 'Kimwolf v7', pubDate: '2026-08-26T00:00:00Z',
        iocs: { ips: ['212.193.31.119'], domains: ['evil.example.com'], hashes: [], urls: ['http://evil.example.com/a'] },
    }],
}];

test('a menção volta com o artigo e o ator que a matéria atribuiu', () => {
    const [m] = findMentions(stories, '212.193.31.119');
    assert.equal(m.source, 'Palo Alto Unit 42');
    assert.deepEqual(m.actors, ['FunkSec']);
    assert.equal(m.link, 'https://unit42.paloaltonetworks.com/kimwolf/');
});

test('a consulta pode chegar defangada, como o analista copia do relatório', () => {
    assert.equal(refangQuery('212.193.31[.]119'), '212.193.31.119');
    assert.equal(findMentions(stories, '212.193.31[.]119').length, 1);
    assert.equal(findMentions(stories, 'EVIL.EXAMPLE.COM').length, 1);
});

test('indicador que ninguém citou devolve vazio, não um match frouxo', () => {
    assert.deepEqual(findMentions(stories, '212.193.31.11'), [], 'prefixo não é menção');
    assert.deepEqual(findMentions(stories, '8.8.8.8'), []);
    assert.deepEqual(findMentions(stories, ''), []);
});

// Observado no primeiro deploy: 40 buscas simultâneas no boot degradavam o
// resto da API — chamadas à OTX de 0,5s passavam de 15s e morriam no timeout.
test('a colheita busca em lotes, não tudo de uma vez', async () => {
    let emVoo = 0, pico = 0;
    const items = Array.from({ length: 12 }, (_, i) => item({ link: `https://x.example/${i}` }));

    await harvestResearchIocs(items, {
        fetchText: async () => {
            emVoo += 1; pico = Math.max(pico, emVoo);
            await new Promise((r) => setImmediate(r));
            emVoo -= 1;
            return 'C2 at 193.143.1[.]131';
        },
        extract,
        concurrency: 4,
    });

    assert.equal(pico, 4, `pico de ${pico} buscas simultâneas`);
    assert.equal(items.filter((i) => i.iocs).length, 12, 'todos foram colhidos mesmo em lotes');
});
