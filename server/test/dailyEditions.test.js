import test from 'node:test';
import assert from 'node:assert/strict';

import {
    buildDeterministicNarrative,
    buildEditionEvents,
    getCompletedDate,
    getDateWindow,
} from '../dailyEditions.js';

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
