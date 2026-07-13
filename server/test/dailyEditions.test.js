import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
    buildDeterministicNarrative,
    buildEditionEvents,
    createEditionGenerator,
    createEditionStore,
    getCompletedDate,
    getDateWindow,
    selectDailyEdition,
    validateNarrative,
} from '../dailyEditions.js';

const writeJsonAtomic = (filePath, value) => fs.writeFileSync(filePath, JSON.stringify(value));
const tempStore = () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'daily-editions-'));
    return { dir, filePath: path.join(dir, '.daily-summaries.json') };
};

test('uses the previous completed Recife calendar day', () => {
    assert.equal(getCompletedDate(new Date('2026-07-13T02:59:59Z')), '2026-07-11');
    assert.equal(getCompletedDate(new Date('2026-07-13T03:00:00Z')), '2026-07-12');
    assert.deepEqual(getDateWindow('2026-07-12'), {
        windowStart: '2026-07-12T03:00:00.000Z',
        windowEnd: '2026-07-13T03:00:00.000Z',
    });
});

test('rejects invalid calendar dates', () => {
    assert.throws(() => getDateWindow('2026-02-30'), /invalid date/i);
    assert.throws(() => getDateWindow('12-07-2026'), /invalid date/i);
});

test('includes only events inside the selected Recife day', () => {
    const feed = [
        { title: 'before advisory', source: 'CISA', pubDate: '2026-07-12T02:59:59.999Z' },
        { title: 'inside advisory', source: 'CISA', pubDate: '2026-07-12T03:00:00.000Z', severity: 'Critical', cves: ['CVE-2026-1000'] },
        { title: 'next advisory', source: 'CISA', pubDate: '2026-07-13T03:00:00.000Z' },
    ];
    const victims = [
        { name: 'before victim', group: 'alpha', discovered: '2026-07-12T02:59:59.999Z' },
        { name: 'inside victim', group: 'anubis', discovered: '2026-07-13T02:59:59.999Z', countryName: 'Brazil' },
    ];

    const events = buildEditionEvents({ feed, victims, date: '2026-07-12' });

    assert.deepEqual(events.map((event) => event.title), ['inside advisory', 'inside victim']);
    assert.equal(events[0].priority, 'critical');
    assert.equal(events[0].category, 'vulnerability');
    assert.equal(events[1].category, 'ransomware');
});

test('builds a calm deterministic narrative for an empty day', () => {
    assert.deepEqual(buildDeterministicNarrative([]), {
        title: 'Nenhum sinal prioritario no dia',
        summary: ['Nenhum evento de alta prioridade foi registrado nas fontes monitoradas.'],
        attentionTopics: [],
    });
});

test('builds deterministic topics backed by existing event IDs', () => {
    const events = buildEditionEvents({
        date: '2026-07-12',
        feed: [
            { title: 'Critical KEV advisory', source: 'CISA', pubDate: '2026-07-12T12:00:00Z', severity: 'Critical', kev: true, cves: ['CVE-2026-1000'] },
        ],
        victims: [
            { name: 'Acme', group: 'anubis', discovered: '2026-07-12T13:00:00Z', countryName: 'Brazil' },
        ],
    });

    const narrative = buildDeterministicNarrative(events);

    assert.ok(narrative.summary.some((line) => line.includes('exploracao ativa')));
    assert.ok(narrative.summary.some((line) => line.includes('ransomware')));
    assert.ok(narrative.attentionTopics.length >= 2);
    assert.ok(narrative.attentionTopics.every((topic) => topic.eventIds.every((id) => events.some((event) => event.id === id))));
});

test('validates a grounded AI narrative', () => {
    const events = buildEditionEvents({
        date: '2026-07-12',
        feed: [{ title: 'CVE advisory', source: 'CISA', pubDate: '2026-07-12T12:00:00Z', cves: ['CVE-2026-1000'], severity: 'Critical' }],
    });
    const value = {
        title: 'Prioridade para CVE-2026-1000',
        summary: ['A CVE-2026-1000 concentrou a prioridade do dia.', 'A fonte classificou o advisory como critico.', 'A equipe deve validar a exposicao.'],
        attentionTopics: [
            { title: 'Vulnerabilidade critica', assessment: 'O advisory exige avaliacao.', eventIds: [events[0].id] },
            { title: 'Acao recomendada', assessment: 'A exposicao deve ser validada.', recommendedAction: 'Validar ativos afetados.', eventIds: [events[0].id] },
        ],
    };

    assert.deepEqual(validateNarrative(value, events), value);
});

test('rejects unknown events and unsupported CVEs in AI output', () => {
    const events = buildEditionEvents({
        date: '2026-07-12',
        feed: [{ title: 'Known advisory', source: 'CISA', pubDate: '2026-07-12T12:00:00Z', cves: ['CVE-2026-1000'] }],
    });
    const base = {
        title: 'Resumo do dia',
        summary: ['Primeiro fato registrado.', 'Segundo fato registrado.', 'Terceiro fato registrado.'],
        attentionTopics: [
            { title: 'Tema', assessment: 'Avaliacao factual.', eventIds: [events[0].id] },
            { title: 'Prioridade', assessment: 'Acao factual.', eventIds: [events[0].id] },
        ],
    };

    assert.throws(() => validateNarrative({ ...base, attentionTopics: [{ ...base.attentionTopics[0], eventIds: ['missing'] }, base.attentionTopics[1]] }, events), /unknown event/i);
    assert.throws(() => validateNarrative({ ...base, summary: ['CVE-2026-9999 apareceu.', ...base.summary.slice(1)] }, events), /unsupported identifier/i);
});

test('persists immutable editions and reloads date history', () => {
    const { dir, filePath } = tempStore();
    try {
        const store = createEditionStore({ filePath, writeJsonAtomic });
        const first = { date: '2026-07-11', narrative: { title: 'first' } };
        const second = { date: '2026-07-12', narrative: { title: 'second' } };
        store.save(first);
        store.save(second);
        store.save({ ...first, narrative: { title: 'replacement' } });

        const reloaded = createEditionStore({ filePath, writeJsonAtomic });
        assert.deepEqual(reloaded.listDates(), ['2026-07-12', '2026-07-11']);
        assert.equal(reloaded.get('2026-07-11').narrative.title, 'first');
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

test('deduplicates concurrent generation and saves validated AI output', async () => {
    const { dir, filePath } = tempStore();
    try {
        const store = createEditionStore({ filePath, writeJsonAtomic });
        let sourceCalls = 0;
        const generator = createEditionGenerator({
            store,
            now: () => new Date('2026-07-13T04:00:00Z'),
            getSourceData: async () => {
                sourceCalls += 1;
                return { feed: [{ title: 'Advisory', source: 'CISA', pubDate: '2026-07-12T12:00:00Z', severity: 'Critical' }], victims: [] };
            },
            requestNarrative: async (events) => ({
                title: 'Prioridade de correcao',
                summary: ['Um advisory critico foi publicado.', 'A exposicao deve ser validada.', 'A correcao merece prioridade.'],
                attentionTopics: [
                    { title: 'Vulnerabilidade critica', assessment: 'O evento exige avaliacao.', eventIds: [events[0].id] },
                    { title: 'Prioridade operacional', assessment: 'A exposicao deve ser validada.', eventIds: [events[0].id] },
                ],
            }),
        });

        const [first, second] = await Promise.all([generator.generate('2026-07-12'), generator.generate('2026-07-12')]);
        assert.equal(sourceCalls, 1);
        assert.deepEqual(first, second);
        assert.equal(first.narrativeSource, 'openrouter');
        assert.deepEqual(store.listDates(), ['2026-07-12']);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

test('saves a deterministic edition when AI generation fails', async () => {
    const { dir, filePath } = tempStore();
    try {
        const store = createEditionStore({ filePath, writeJsonAtomic });
        const generator = createEditionGenerator({
            store,
            now: () => new Date('2026-07-13T04:00:00Z'),
            getSourceData: async () => ({ feed: [], victims: [] }),
            requestNarrative: async () => { throw new Error('timeout'); },
        });

        const edition = await generator.generate('2026-07-12');
        assert.equal(edition.narrativeSource, 'deterministic');
        assert.equal(edition.narrative.title, 'Nenhum sinal prioritario no dia');
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

test('selects the completed edition or a saved historical date', async () => {
    const saved = { date: '2026-07-11' };
    const generated = { date: '2026-07-12' };
    const store = {
        get: (date) => date === saved.date ? saved : null,
        listDates: () => [generated.date, saved.date],
    };
    const calls = [];
    const generator = { generate: async (date) => { calls.push(date); return generated; } };
    const now = new Date('2026-07-13T12:00:00Z');

    assert.deepEqual(await selectDailyEdition({ store, generator, now }), {
        edition: generated,
        availableDates: [generated.date, saved.date],
    });
    assert.deepEqual(await selectDailyEdition({ date: saved.date, store, generator, now }), {
        edition: saved,
        availableDates: [generated.date, saved.date],
    });
    assert.deepEqual(calls, [generated.date]);
});

test('rejects malformed, future, and unavailable historical edition dates', async () => {
    const store = { get: () => null, listDates: () => [] };
    const generator = { generate: async () => assert.fail('historical requests must not generate') };
    const now = new Date('2026-07-13T12:00:00Z');

    await assert.rejects(() => selectDailyEdition({ date: 'not-a-date', store, generator, now }), (error) => error.status === 400);
    await assert.rejects(() => selectDailyEdition({ date: '2026-07-13', store, generator, now }), (error) => error.status === 400);
    await assert.rejects(() => selectDailyEdition({ date: '2026-07-10', store, generator, now }), (error) => error.status === 404);
});
