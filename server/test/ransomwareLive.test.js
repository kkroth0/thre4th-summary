import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
    asArray,
    buildThreatMapResponse,
    normalizeVictim,
    ransomwareLiveRequestOptions,
} from '../ransomwareLive.js';

const NOW = Date.parse('2026-07-13T12:00:00.000Z');
const hoursAgo = (hours) => new Date(NOW - hours * 60 * 60 * 1000).toISOString();

test('normalizes Ransomware.live Pro victims without losing enrichment fields', () => {
    const victim = normalizeVictim({
        id: 'victim-123',
        victim: 'Acme Payments',
        domain: 'acme.example',
        group: 'qilin',
        country: 'br',
        activity: 'Financial Services',
        attackdate: '2026-07-12T08:00:00.000Z',
        discovered: '2026-07-13T09:00:00.000Z',
        screenshot: 'https://example.com/shot.png',
        permalink: 'https://ransomware.live/victim/acme',
        infostealer: true,
        press: ['https://news.example/acme'],
        description: 'N/A',
    }, 'ransomware.live Pro');

    assert.equal(victim.id, 'victim-123');
    assert.equal(victim.name, 'Acme Payments');
    assert.equal(victim.website, 'acme.example');
    assert.equal(victim.group, 'qilin');
    assert.equal(victim.country, 'BR');
    assert.equal(victim.countryName, 'Brazil');
    assert.equal(victim.sector, 'Financial Services');
    assert.equal(victim.published, '2026-07-12T08:00:00.000Z');
    assert.equal(victim.discovered, '2026-07-13T09:00:00.000Z');
    assert.equal(victim.description, '');
    assert.equal(victim.permalink, 'https://ransomware.live/victim/acme');
    assert.equal(victim.infostealer, true);
    assert.deepEqual(victim.press, ['https://news.example/acme']);
    assert.equal(victim.source, 'ransomware.live Pro');
});

test('selects Pro endpoint when API key is configured', () => {
    const pro = ransomwareLiveRequestOptions('secret-value');
    assert.equal(pro.source, 'ransomware.live Pro');
    assert.match(pro.url, /api-pro\.ransomware\.live\/victims\/recent$/);
    assert.equal(pro.options.headers['X-API-KEY'], 'secret-value');
    assert.equal(pro.options.params.order, 'discovered');

    const publicApi = ransomwareLiveRequestOptions('');
    assert.equal(publicApi.source, 'ransomware.live');
    assert.match(publicApi.url, /api\.ransomware\.live\/v2\/recentvictims$/);
    assert.equal(publicApi.options.headers, undefined);
});

test('accepts the Ransomware.live Pro victims envelope', () => {
    const proEnvelope = {
        client: 'client@example.test',
        count: 1,
        order: 'discovered',
        victims: [
            { victim: 'Envelope Victim', group: 'qilin', country: 'US', activity: 'Technology', discovered: hoursAgo(2) },
        ],
    };

    assert.equal(asArray(proEnvelope).length, 1);

    const response = buildThreatMapResponse(proEnvelope, {
        days: 1,
        generatedAt: new Date(NOW).toISOString(),
        now: NOW,
        source: 'ransomware.live Pro',
    });

    assert.equal(response.totalVictims, 1);
    assert.equal(response.victims[0].name, 'Envelope Victim');
    assert.equal(response.victims[0].source, 'ransomware.live Pro');
});

test('builds current threat-map windows, deltas, timeline, and insights', () => {
    const victims = [
        normalizeVictim({ victim: 'BR Bank', group: 'qilin', country: 'BR', activity: 'Financial Services', discovered: hoursAgo(4) }),
        normalizeVictim({ victim: 'US Hospital', group: 'dragonforce', country: 'US', activity: 'Healthcare', discovered: hoursAgo(30) }),
        normalizeVictim({ victim: 'MX Retail', group: 'qilin', country: 'MX', activity: 'Retail', discovered: hoursAgo(100) }),
        normalizeVictim({ victim: 'DE Factory', group: 'lockbit', country: 'DE', activity: 'Manufacturing', discovered: hoursAgo(190) }),
    ];

    const response = buildThreatMapResponse(victims, {
        days: 3,
        generatedAt: new Date(NOW).toISOString(),
        now: NOW,
        source: 'ransomware.live Pro',
    });

    assert.equal(response.windowDays, 3);
    assert.equal(response.source, 'ransomware.live Pro');
    assert.equal(response.victims.length, 2);
    assert.equal(response.activeGroups, 2);
    assert.equal(response.topCountry.countryName, 'Brazil');
    assert.equal(response.sectors[0].name, 'Financial Services');
    assert.equal(response.delta.previousVictims, 1);
    assert.equal(response.delta.victims, 1);
    assert.equal(response.latam.victims, 1);
    assert.equal(response.windows.find((w) => w.key === '24h').totalVictims, 1);
    assert.equal(response.windows.find((w) => w.key === '7d').totalVictims, 3);
    assert.ok(response.timeline.length > 0);
    assert.ok(response.timeline.some((bucket) => bucket.count > 0));
    assert.ok(response.insights.some((insight) => insight.kind === 'volume'));
    assert.ok(response.insights.some((insight) => insight.kind === 'top-group'));
});
