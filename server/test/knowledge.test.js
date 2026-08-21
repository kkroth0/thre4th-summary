import test from 'node:test';
import assert from 'node:assert/strict';
import { KNOWLEDGE_CAP, addKnowledgeItem, normalizeKnowledgeInput } from '../knowledge.js';

const now = '2026-08-01T04:00:00.000Z';

test('normaliza o item e extrai refs do título', () => {
    const item = normalizeKnowledgeInput({
        title: '  Certighost   (CVE-2026-54121)  abusa de T1003.006  ',
        url: 'https://thehackernews.com/2026/07/certighost.html',
        source: 'The Hacker News',
        publishedAt: '2026-07-30T10:00:00.000Z',
    }, now);

    assert.equal(item.title, 'Certighost (CVE-2026-54121) abusa de T1003.006');
    assert.equal(item.host, 'thehackernews.com');
    assert.equal(item.savedAt, now);
    assert.deepEqual(item.techniques, ['T1003.006']);
    assert.deepEqual(item.cves, ['CVE-2026-54121']);
    assert.match(item.id, /^[0-9a-f]{12}$/);
});

test('une os CVEs que a tela de origem já trazia com os do título', () => {
    const item = normalizeKnowledgeInput({
        title: 'Falha explora CVE-2026-1111',
        url: 'https://example.com/a',
        cves: ['cve-2026-2222', 'CVE-2026-1111'],
    }, now);
    assert.deepEqual(item.cves, ['CVE-2026-1111', 'CVE-2026-2222']);
});

test('rejeita url ausente ou impossível de parsear', () => {
    assert.throws(() => normalizeKnowledgeInput({ title: 'x' }, now), /url obrigatória/);
    assert.throws(() => normalizeKnowledgeInput({ url: 'nao-e-url' }, now), /url inválida/);
});

test('cai para a url quando não vem título, e descarta data inválida', () => {
    const item = normalizeKnowledgeInput({ url: 'https://example.com/a', publishedAt: 'ontem' }, now);
    assert.equal(item.title, 'https://example.com/a');
    assert.equal(item.publishedAt, '');
});

test('troca caractere de controle por espaço e colapsa a sobra', () => {
    const item = normalizeKnowledgeInput({
        title: 'linha1\nlinha2\ttab nulo   e   espacos',
        url: 'https://example.com/a',
    }, now);
    assert.equal(item.title, 'linha1 linha2 tab nulo e espacos');
});

test('corta campos longos no limite', () => {
    const item = normalizeKnowledgeInput({
        title: 'a'.repeat(400),
        url: 'https://example.com/a',
        source: 'b'.repeat(200),
    }, now);
    assert.equal(item.title.length, 300);
    assert.equal(item.source.length, 120);
});

test('salvar a mesma url de novo não duplica e sobe pro topo', () => {
    const antigo = normalizeKnowledgeInput({ url: 'https://example.com/a', title: 'v1' }, now);
    const outro = normalizeKnowledgeInput({ url: 'https://example.com/b', title: 'outro' }, now);
    const novo = normalizeKnowledgeInput({ url: 'https://example.com/a', title: 'v2' }, now);

    const list = addKnowledgeItem(addKnowledgeItem([antigo], outro), novo);
    assert.deepEqual(list.map((k) => k.title), ['v2', 'outro']);
});

test('respeita o teto por usuário descartando o mais antigo', () => {
    let list = [];
    for (let i = 0; i < KNOWLEDGE_CAP + 5; i += 1) {
        list = addKnowledgeItem(list, normalizeKnowledgeInput({ url: `https://example.com/${i}` }, now));
    }
    assert.equal(list.length, KNOWLEDGE_CAP);
    assert.equal(list[0].url, `https://example.com/${KNOWLEDGE_CAP + 4}`);
});

test('seguir guarda a cobertura e quantos veículos havia no clique', () => {
    const item = normalizeKnowledgeInput({
        title: 'Falha em gateway VPN',
        url: 'https://vendor.example/post',
        storyId: 'A1B2C3D4E5F6',
        sourceCount: 3,
    });

    assert.equal(item.storyId, 'a1b2c3d4e5f6');
    assert.equal(item.followedSourceCount, 3);
});

test('storyId inválido não vira follow — o item ainda salva', () => {
    // Sem id de cobertura o item continua sendo uma fonte guardada; só não
    // acompanha crescimento. Um id inventado não pode virar chave de lookup.
    for (const storyId of ['../../etc/passwd', 'zzz', '', 'a1b2c3d4e5f6a']) {
        const item = normalizeKnowledgeInput({ title: 'T', url: 'https://a.example/1', storyId });
        assert.equal(item.storyId, '', `storyId rejeitado: ${storyId}`);
    }
});

test('sourceCount inválido ou absurdo não entra', () => {
    for (const sourceCount of [0, -3, 2.5, '4', null, 5000]) {
        const item = normalizeKnowledgeInput({ title: 'T', url: 'https://a.example/1', sourceCount });
        assert.ok(item.followedSourceCount === 0 || item.followedSourceCount === 100,
            `sourceCount tratado: ${sourceCount} -> ${item.followedSourceCount}`);
    }
});
