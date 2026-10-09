import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createNewsArchiveStore } from '../newsArchiveStore.js';

const writeJsonAtomic = (filePath, value) => fs.writeFileSync(filePath, JSON.stringify(value));
const tempFile = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'news-archive-')), '.news-archive.json');

const row = (over = {}) => ({
    link: 'https://a.example/1', title: 'T', source: 'Feed', pubDate: '2026-08-01T00:00:00.000Z',
    categories: ['Ransomware'], primaryCategory: 'Ransomware', ...over,
});

test('reenriquecimento atualiza evidências e classificação preservando archivedAt', () => {
    const store = createNewsArchiveStore({ filePath: tempFile(), readFileSync: fs.readFileSync, writeJsonAtomic });
    store.add([row({ contentHash: 'before', storyId: 'old' })]);
    const archivedAt = store.all()[0].archivedAt;
    store.add([row({ contentHash: 'after', storyId: 'event', cves: ['CVE-2026-12345'], categories: ['Vulnerabilities'] })]);
    assert.equal(store.size(), 1);
    assert.equal(store.all()[0].contentHash, 'after');
    assert.equal(store.all()[0].archivedAt, archivedAt);
    assert.deepEqual(store.list({ category: 'Vulnerabilities' })[0].cves, ['CVE-2026-12345']);
});

test('arquivo ausente vira store vazio', () => {
    const store = createNewsArchiveStore({ filePath: tempFile(), readFileSync: fs.readFileSync, writeJsonAtomic });
    assert.deepEqual(store.all(), []);
    assert.equal(store.size(), 0);
});

test('arquivo corrompido vira store vazio em vez de derrubar o servidor', () => {
    const filePath = tempFile();
    fs.writeFileSync(filePath, '{ not json');
    const store = createNewsArchiveStore({ filePath, readFileSync: fs.readFileSync, writeJsonAtomic });
    assert.deepEqual(store.all(), []);
});

test('add grava e recarrega', () => {
    const filePath = tempFile();
    createNewsArchiveStore({ filePath, readFileSync: fs.readFileSync, writeJsonAtomic }).add([row()]);
    const reloaded = createNewsArchiveStore({ filePath, readFileSync: fs.readFileSync, writeJsonAtomic });
    assert.equal(reloaded.size(), 1);
    assert.equal(reloaded.all()[0].title, 'T');
});

test('add não duplica por link, e devolve quantos de fato entraram', () => {
    const store = createNewsArchiveStore({ filePath: tempFile(), readFileSync: fs.readFileSync, writeJsonAtomic });
    assert.equal(store.add([row({ link: 'https://a.example/1' })]), 1);
    assert.equal(store.add([row({ link: 'https://a.example/1', title: 'Outro título, mesmo link' })]), 0, 'link repetido não entra de novo');
    assert.equal(store.size(), 1);
    assert.equal(store.all()[0].title, 'Outro título, mesmo link', 'atualiza a publicação existente');
});

test('add ignora item sem link, sem quebrar os outros', () => {
    const store = createNewsArchiveStore({ filePath: tempFile(), readFileSync: fs.readFileSync, writeJsonAtomic });
    assert.equal(store.add([null, {}, row({ link: 'https://a.example/1' })]), 1);
    assert.equal(store.size(), 1);
});

test('list filtra por categoria, fonte e janela de datas', () => {
    const store = createNewsArchiveStore({ filePath: tempFile(), readFileSync: fs.readFileSync, writeJsonAtomic });
    store.add([
        row({ link: 'https://a.example/1', source: 'Feed A', categories: ['Ransomware'], pubDate: '2026-08-01T00:00:00.000Z' }),
        row({ link: 'https://a.example/2', source: 'Feed B', categories: ['Phishing'], pubDate: '2026-08-15T00:00:00.000Z' }),
        row({ link: 'https://a.example/3', source: 'Feed A', categories: ['Phishing'], pubDate: '2026-09-01T00:00:00.000Z' }),
    ]);
    assert.deepEqual(store.list({ category: 'Phishing' }).map((r) => r.link), ['https://a.example/3', 'https://a.example/2']);
    assert.deepEqual(store.list({ source: 'Feed A' }).map((r) => r.link), ['https://a.example/3', 'https://a.example/1']);
    assert.deepEqual(store.list({ from: '2026-08-10' }).map((r) => r.link), ['https://a.example/3', 'https://a.example/2']);
    assert.deepEqual(store.list({ to: '2026-08-10' }).map((r) => r.link), ['https://a.example/1']);
    assert.equal(store.list({ limit: 1 }).length, 1);
});

test('list ordena do mais recente pro mais antigo', () => {
    const store = createNewsArchiveStore({ filePath: tempFile(), readFileSync: fs.readFileSync, writeJsonAtomic });
    store.add([
        row({ link: 'https://a.example/old', pubDate: '2026-08-01T00:00:00.000Z' }),
        row({ link: 'https://a.example/new', pubDate: '2026-09-01T00:00:00.000Z' }),
    ]);
    assert.deepEqual(store.list().map((r) => r.link), ['https://a.example/new', 'https://a.example/old']);
});

// Mesma garantia de newsStoryStore: se a escrita falhar, a memória não pode
// avançar, senão um restart reprocessa o lote e ele falta pra sempre (o link
// já estaria em `seen` sem nunca ter ido pro disco).
test('add não avança o estado em memória quando a escrita falha', () => {
    const filePath = tempFile();
    const store = createNewsArchiveStore({ filePath, readFileSync: fs.readFileSync, writeJsonAtomic });
    store.add([row({ link: 'https://a.example/1' })]);

    const failingWrite = () => { throw new Error('disk full'); };
    const failingStore = createNewsArchiveStore({ filePath, readFileSync: fs.readFileSync, writeJsonAtomic: failingWrite });
    assert.throws(() => failingStore.add([row({ link: 'https://a.example/2' })]));
    assert.deepEqual(failingStore.all().map((r) => r.link), ['https://a.example/1']);
});

test('add com lista vazia ou só duplicados não escreve no disco', () => {
    const filePath = tempFile();
    const store = createNewsArchiveStore({ filePath, readFileSync: fs.readFileSync, writeJsonAtomic });
    store.add([row({ link: 'https://a.example/1' })]);

    let wrote = false;
    const trackingStore = createNewsArchiveStore({
        filePath, readFileSync: fs.readFileSync,
        writeJsonAtomic: (...args) => { wrote = true; writeJsonAtomic(...args); },
    });
    assert.equal(trackingStore.add([row({ link: 'https://a.example/1' })]), 0);
    assert.equal(wrote, false, 'nada novo não deveria tocar o disco');
});
