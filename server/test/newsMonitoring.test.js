import test from 'node:test';
import assert from 'node:assert/strict';
import { createNewsMonitoringStore, normalizeNewsMonitoring, filterMonitoredNews, filterMonitoredStories } from '../newsMonitoring.js';
import { enrichFeedItems } from '../feedEnrichment.js';
import { mergeIntoStories } from '../newsStories.js';

const selected = (vendorIds = ['fortinet']) => ({ mode: 'selected', vendorIds });
const publication = (link, vendorIds, over = {}) => ({ link, title: 'Investigação técnica', vendors: vendorIds.map((id) => ({ id })), ...over });

test('novo alias passa pela extração e seleção sem juntar falhas distintas do produto', () => {
    const now = new Date('2026-10-09T12:00:00Z');
    const items = enrichFeedItems([
        { title: 'MegaRAC SP-X CVE-2026-11111 authentication bypass', link: 'https://example.com/a' },
        { title: 'MegaRAC SP-X CVE-2026-22222 command injection', link: 'https://example.com/b' },
        { title: 'FortiGate CVE-2026-33333', link: 'https://example.com/c' },
    ].map((item) => ({ ...item, description: '', source: 'Advisory', pubDate: now.toISOString() })), {
        actors: () => [], malware: () => [], campaigns: () => [], seller: () => null, categorize: () => ['Vulnerabilities'],
    });
    const stories = mergeIntoStories([], items, now);
    assert.equal(stories.length, 3);
    assert.deepEqual(filterMonitoredNews(items, selected(['american-megatrends']), stories).map((item) => item.link), ['https://example.com/a', 'https://example.com/b']);
    assert.deepEqual(filterMonitoredNews(items, selected(['fortinet']), stories).map((item) => item.link), ['https://example.com/c']);
});
const memory = () => {
    let persisted;
    let fail = false;
    const open = () => createNewsMonitoringStore({ filePath: 'preferences.json',
        readFileSync: () => { if (!persisted) throw new Error('missing'); return persisted; },
        writeJsonAtomic: (_, value) => { if (fail) throw new Error('disk full'); persisted = JSON.stringify(value); },
    });
    return { open, fail: () => { fail = true; } };
};

test('preferências são persistidas por conta e não mudam outra conta', () => {
    const storage = memory();
    const store = storage.open();
    assert.deepEqual(store.get('a'), { mode: 'all', vendorIds: [], updatedAt: null });
    store.set('a', selected(['fortinet', 'cisco', 'fortinet']), '2026-10-09');
    assert.deepEqual(storage.open().get('a').vendorIds, ['cisco', 'fortinet']);
    assert.equal(store.get('b').mode, 'all');
    store.get('a').vendorIds.push('microsoft');
    assert.deepEqual(store.get('a').vendorIds, ['cisco', 'fortinet']);
});

test('falha na escrita não altera a preferência salva', () => {
    const storage = memory();
    const store = storage.open();
    store.set('a', selected());
    storage.fail();
    assert.throws(() => store.set('a', selected(['cisco'])), /disk full/);
    assert.deepEqual(store.get('a').vendorIds, ['fortinet']);
});

test('entrada inválida é rejeitada e seleção vazia é distinta de todas', () => {
    for (const input of [null, [], {}, { mode: 'wrong', vendorIds: [] }, selected(['nonexistent']), selected([1]), { mode: 'all', vendorIds: 'fortinet' }]) {
        assert.throws(() => normalizeNewsMonitoring(input), { status: 400 });
    }
    assert.deepEqual(normalizeNewsMonitoring(selected([])), { mode: 'selected', vendorIds: [] });
    assert.deepEqual(normalizeNewsMonitoring({ mode: 'all', vendorIds: [] }), { mode: 'all', vendorIds: [] });
});

test('default, seleção vazia e troca de fornecedor têm resultados explícitos', () => {
    const items = [publication('a', ['fortinet']), publication('b', ['cisco']), publication('c', [])];
    assert.equal(filterMonitoredNews(items, { mode: 'all', vendorIds: [] }).length, 3);
    assert.deepEqual(filterMonitoredNews(items, selected([])), []);
    assert.deepEqual(filterMonitoredNews(items, selected()).map((item) => item.link), ['a']);
    assert.deepEqual(filterMonitoredNews(items, selected(['cisco'])).map((item) => item.link), ['b']);
    assert.equal(items.length, 3, 'a filtragem não altera o feed compartilhado');
});

test('um card relevante mantém cobertura sem fornecedor nas outras fontes', () => {
    const items = [publication('a', ['fortinet'], { storyId: 'event-a' }), publication('b', [], { storyId: 'event-a' }), publication('c', ['cisco'], { storyId: 'event-b' })];
    assert.deepEqual(filterMonitoredNews(items, selected()).map((item) => item.link), ['a', 'b']);
});

test('evidência do histórico e aliases mantêm follow-ups e IDs da história', () => {
    const stories = [{ id: 'canonical-event', aliases: ['old-event'], sources: [publication('a', ['fortinet'])] },
        { id: 'other', sources: [publication('b', ['cisco'])] }];
    const items = [publication('c', [], { storyId: 'old-event' }), publication('d', [], { storyId: 'canonical-event' }), publication('e', [], { storyId: 'other' })];
    assert.deepEqual(filterMonitoredNews(items, selected(), stories).map((item) => item.link), ['c', 'd']);
    assert.equal(filterMonitoredStories(stories, selected())[0].id, 'canonical-event');
    assert.equal(filterMonitoredStories(stories, selected([])).length, 0);
});

test('publicações antigas reconhecem aliases e assets sem confundir fonte com alvo', () => {
    const items = [{ link: 'a', title: 'Correção no FortiGate' }, { link: 'b', title: 'Análise', assets: ['Fortinet'] }, { link: 'c', title: 'Análise de outra plataforma', source: 'Fortinet' }];
    assert.deepEqual(filterMonitoredNews(items, selected()).map((item) => item.link), ['a', 'b']);
    assert.deepEqual(filterMonitoredNews([{ title: 'Fortinet', vendors: [] }], selected()), [], 'extração existente é autoritativa');
});

test('store corrompido ou entrada de outra conta não quebra a leitura', () => {
    for (const contents of ['invalid json', '[]', JSON.stringify({ a: { mode: 'selected', vendorIds: ['fortinet', 'removed-vendor'] }, b: { mode: 'bad' } })]) {
        const store = createNewsMonitoringStore({ filePath: 'p', readFileSync: () => contents, writeJsonAtomic: () => {} });
        assert.equal(store.get('b').mode, 'all');
        if (contents.startsWith('{')) assert.deepEqual(store.get('a').vendorIds, ['fortinet']);
    }
});
