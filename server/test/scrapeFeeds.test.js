import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SCRAPE_SOURCES, collectScraped, parseListing, publishedTime } from '../scrapeFeeds.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => fs.readFileSync(path.join(here, 'fixtures', name), 'utf8');
const sourceNamed = (name) => SCRAPE_SOURCES.find((source) => source.source === name);

test('o catálogo tem as três páginas, com as duas da Claroty datadas', () => {
    assert.equal(SCRAPE_SOURCES.length, 3);
    assert.equal(sourceNamed('Claroty Team82').datedItems, true);
    assert.equal(sourceNamed('Claroty Team82 White Papers').datedItems, true);
    assert.equal(sourceNamed('Nozomi Networks Blog').datedItems, false);
});

test('parseListing extrai título e link absoluto da Claroty', () => {
    const items = parseListing(fixture('claroty-research.html'), sourceNamed('Claroty Team82'));
    assert.ok(items.length >= 5, `esperava vários itens, veio ${items.length}`);
    for (const item of items) {
        assert.ok(item.link.startsWith('https://claroty.com/team82/research/'), item.link);
        assert.ok(item.title.length > 10, item.title);
        assert.equal(item.source, 'Claroty Team82');
        assert.equal(item.layer, 3);
    }
    assert.equal(new Set(items.map((item) => item.link)).size, items.length, 'sem link repetido');
});

// As duas abas moram na mesma URL base e diferem só pela query — se o seletor
// pegasse a página inteira, elas trariam a mesma coisa.
test('as duas abas da Claroty trazem conjuntos diferentes', () => {
    const research = parseListing(fixture('claroty-research.html'), sourceNamed('Claroty Team82'));
    const papers = parseListing(fixture('claroty-white-papers.html'), sourceNamed('Claroty Team82 White Papers'));
    assert.ok(papers.every((item) => item.link.includes('/white-papers/')));
    assert.equal(research.filter((item) => item.link.includes('/white-papers/')).length, 0);
});

test('parseListing extrai o blog da Nozomi', () => {
    const items = parseListing(fixture('nozomi-blog.html'), sourceNamed('Nozomi Networks Blog'));
    assert.ok(items.length >= 20, `esperava vários posts, veio ${items.length}`);
    for (const item of items) assert.ok(item.link.startsWith('https://www.nozominetworks.com/blog/'), item.link);
});

test('publishedTime lê a meta do post', () => {
    assert.equal(
        publishedTime('<meta property="article:published_time" content="2026-06-09T16:00:00+00:00">'),
        '2026-06-09T16:00:00.000Z',
    );
    assert.equal(publishedTime('<html><body>sem data</body></html>'), null);
});

const listingHtml = (slugs) =>
    `<main>${slugs.map((slug) => `<a href="/blog/${slug}"><h2>Post do blog sobre ${slug}</h2></a>`).join('')}</main>`;

const nozomi = () => ({ ...sourceNamed('Nozomi Networks Blog') });
const now = new Date('2026-08-17T12:00:00.000Z');

// Uma fonte sem data confiável não pode ser retroativa sem inventar quando as
// coisas aconteceram — então a primeira rodada só semeia.
test('partida a frio semeia em silêncio', async () => {
    const result = await collectScraped({
        sources: [nozomi()],
        fetchText: async () => listingHtml(['a', 'b', 'c']),
        seen: {},
        now,
        maxNew: 10,
    });
    assert.deepEqual(result.items, []);
    assert.equal(Object.keys(result.seen).length, 3);
});

test('a segunda rodada emite só o que apareceu depois', async () => {
    const first = await collectScraped({ sources: [nozomi()], fetchText: async () => listingHtml(['a', 'b']), seen: {}, now, maxNew: 10 });
    const later = new Date('2026-08-18T12:00:00.000Z');
    const second = await collectScraped({
        sources: [nozomi()],
        fetchText: async () => listingHtml(['a', 'b', 'c']),
        seen: first.seen,
        now: later,
        maxNew: 10,
    });
    assert.deepEqual(second.items.map((item) => item.link), ['https://www.nozominetworks.com/blog/c']);
    assert.equal(second.items[0].pubDate, later.toISOString());
});

test('maxNew limita quantos novos entram por rodada', async () => {
    const first = await collectScraped({ sources: [nozomi()], fetchText: async () => listingHtml(['a']), seen: {}, now, maxNew: 10 });
    const second = await collectScraped({
        sources: [nozomi()],
        fetchText: async () => listingHtml(['a', 'b', 'c', 'd']),
        seen: first.seen,
        now,
        maxNew: 2,
    });
    assert.equal(second.items.length, 2);
    assert.equal(second.seen['https://www.nozominetworks.com/blog/d'], undefined);
    const third = await collectScraped({ sources: [nozomi()], fetchText: async () => listingHtml(['a', 'b', 'c', 'd']), seen: second.seen, now, maxNew: 2 });
    assert.deepEqual(third.items.map((item) => item.link), ['https://www.nozominetworks.com/blog/d']);
});

test('fonte datada mantém backlog na partida a frio e escoa no ciclo seguinte', async () => {
    const source = nozomi();
    source.datedItems = true;
    const fetchText = async (url) => url === source.url ? listingHtml(['a', 'b', 'c']) : '<meta property="article:published_time" content="2026-08-16T12:00:00Z">';
    const first = await collectScraped({ sources: [source], fetchText, now, maxNew: 1 });
    assert.equal(first.items.length, 1);
    assert.equal(Object.keys(first.seen).length, 1);
    const next = await collectScraped({ sources: [source], fetchText, seen: first.seen, now, maxNew: 2 });
    assert.equal(next.items.length, 2);
    assert.ok(next.items.every((item) => !item.dateInferred));
});

test('HTML de bloqueio não é registrado como coleta vazia bem-sucedida', async () => {
    const result = await collectScraped({ sources: [nozomi()], fetchText: async () => '<html>Access denied</html>', now });
    assert.equal(result.errors.length, 1);
    assert.deepEqual(result.seen, {});
});

// Fonte datada emite já na primeira rodada, porque a data é real e não first-seen.
test('fonte datada busca a data do post e emite na partida a frio', async () => {
    const source = { ...sourceNamed('Claroty Team82') };
    const result = await collectScraped({
        sources: [source],
        fetchText: async (url) => (
            url.includes('?')
                ? '<main><a href="/team82/research/algo"><h2>Um estudo sobre CLPs</h2></a></main>'
                : '<meta property="article:published_time" content="2026-06-09T16:00:00+00:00">'
        ),
        seen: {},
        now,
        maxNew: 10,
    });
    assert.equal(result.items.length, 1);
    assert.equal(result.items[0].pubDate, '2026-06-09T16:00:00.000Z');
});

test('fonte que quebra não derruba as outras', async () => {
    const result = await collectScraped({
        sources: [nozomi(), { ...sourceNamed('Claroty Team82') }],
        fetchText: async (url) => {
            if (url.includes('claroty')) throw new Error('502');
            return listingHtml(['a']);
        },
        seen: { 'https://www.nozominetworks.com/blog/a': '2026-08-01T00:00:00.000Z' },
        now,
        maxNew: 10,
    });
    assert.deepEqual(result.items, [], 'a Nozomi já conhecia o link, a Claroty falhou');
    assert.ok(result.errors.some((error) => error.source === 'Claroty Team82'));
});
