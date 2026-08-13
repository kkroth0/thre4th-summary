import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createStoryStore } from '../newsStoryStore.js';

const writeJsonAtomic = (filePath, value) => fs.writeFileSync(filePath, JSON.stringify(value));
const tempFile = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'news-stories-')), '.news-stories.json');

const story = (over = {}) => ({
    id: 'abc123', title: 'T', firstSeen: '2026-08-01T00:00:00.000Z', lastSeen: '2026-08-10T00:00:00.000Z',
    cves: [], actors: [], categories: ['Ransomware'], primaryCategory: 'Ransomware', score: 50, sources: [], ...over,
});

test('arquivo ausente vira store vazio', () => {
    const store = createStoryStore({ filePath: tempFile(), readFileSync: fs.readFileSync, writeJsonAtomic });
    assert.deepEqual(store.all(), []);
});

test('arquivo corrompido vira store vazio em vez de derrubar o servidor', () => {
    const filePath = tempFile();
    fs.writeFileSync(filePath, '{ not json');
    const store = createStoryStore({ filePath, readFileSync: fs.readFileSync, writeJsonAtomic });
    assert.deepEqual(store.all(), []);
});

test('save persiste e recarrega', () => {
    const filePath = tempFile();
    createStoryStore({ filePath, readFileSync: fs.readFileSync, writeJsonAtomic }).save([story()]);
    const reloaded = createStoryStore({ filePath, readFileSync: fs.readFileSync, writeJsonAtomic });
    assert.equal(reloaded.all().length, 1);
    assert.equal(reloaded.get('abc123').title, 'T');
});

test('list filtra por categoria, ator e janela de dias', () => {
    const store = createStoryStore({ filePath: tempFile(), readFileSync: fs.readFileSync, writeJsonAtomic });
    store.save([
        story({ id: 'r1', categories: ['Ransomware'], actors: [{ id: 'a1', name: 'Cl0p' }], lastSeen: '2026-08-11T00:00:00.000Z' }),
        story({ id: 'v1', categories: ['Vulnerabilities'], actors: [], lastSeen: '2026-08-11T00:00:00.000Z' }),
        story({ id: 'old', categories: ['Ransomware'], actors: [], lastSeen: '2026-05-01T00:00:00.000Z' }),
    ]);
    const now = new Date('2026-08-12T00:00:00.000Z');
    assert.deepEqual(store.list({ category: 'Ransomware', now }).map((s) => s.id), ['r1', 'old']);
    assert.deepEqual(store.list({ actor: 'a1', now }).map((s) => s.id), ['r1']);
    assert.deepEqual(store.list({ days: 7, now }).map((s) => s.id).sort(), ['r1', 'v1']);
    assert.equal(store.list({ limit: 1, now }).length, 1);
});

// Fix 5: if the disk write throws, in-memory state must not have advanced —
// otherwise a restart rewinds to the old file while callers this process saw
// the new state, and the gap re-merges into duplicate stories.
test('save não avança o estado em memória quando a escrita falha', () => {
    const filePath = tempFile();
    const store = createStoryStore({ filePath, readFileSync: fs.readFileSync, writeJsonAtomic });
    store.save([story({ id: 'first' })]);

    const failingWrite = () => { throw new Error('disk full'); };
    const failingStore = createStoryStore({ filePath, readFileSync: fs.readFileSync, writeJsonAtomic: failingWrite });
    assert.throws(() => failingStore.save([story({ id: 'second' })]));
    assert.deepEqual(failingStore.all().map((s) => s.id), ['first'], 'in-memory state stays at the last successful write');
});

test('get devolve null para id desconhecido', () => {
    const store = createStoryStore({ filePath: tempFile(), readFileSync: fs.readFileSync, writeJsonAtomic });
    assert.equal(store.get('nope'), null);
});
