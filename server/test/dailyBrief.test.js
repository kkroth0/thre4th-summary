import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildDailyBrief,
  buildExecutiveSummary,
  buildFeedGroups,
} from '../dailyBrief.js';

const now = new Date('2026-07-13T12:00:00.000Z').getTime();
const countBy = (arr, fn) => {
  const map = new Map();
  for (const item of arr) {
    const key = fn(item) || 'Unknown';
    map.set(key, (map.get(key) || 0) + 1);
  }
  return [...map.entries()].map(([name, count]) => ({ name, count }));
};

const feed = [
  {
    title: 'CVE-2026-1111 exploited in the wild',
    link: 'https://example.com/kev',
    source: 'CISA Advisories',
    pubDate: '2026-07-13T08:00:00.000Z',
    score: 95,
    severity: 'Critical',
    cves: ['CVE-2026-1111'],
    kev: true,
    reasons: ['CISA KEV - Actively Exploited (CVE-2026-1111)'],
  },
  {
    title: 'Critical firewall advisory',
    link: 'https://example.com/critical',
    source: 'Vendor PSIRT',
    pubDate: '2026-07-13T07:00:00.000Z',
    score: 82,
    severity: 'Critical',
    cves: ['CVE-2026-2222'],
    reasons: ['CVSS Critical (9.8)'],
  },
  {
    title: 'Low priority product update',
    link: 'https://example.com/low',
    source: 'Vendor Blog',
    pubDate: '2026-07-13T06:00:00.000Z',
    score: 15,
    severity: 'Low',
    cves: [],
    reasons: [],
  },
  {
    title: 'Old advisory outside the window',
    link: 'https://example.com/old',
    source: 'Vendor Blog',
    pubDate: '2026-07-10T06:00:00.000Z',
    score: 100,
    severity: 'Critical',
    cves: ['CVE-2026-9999'],
    kev: true,
    reasons: ['old'],
  },
];

const victims = [
  {
    name: 'Example SA',
    group: 'LockExample',
    country: 'BR',
    countryName: 'Brazil',
    sector: 'Manufacturing',
    discovered: '2026-07-13T03:00:00.000Z',
    source: 'ransomware.live',
  },
];

test('buildExecutiveSummary creates deterministic bullets for strong signals', () => {
  const bullets = buildExecutiveSummary({
    kev: [feed[0]],
    critical: [feed[0], feed[1]],
    victims,
    latamVictims: victims,
    cves: ['CVE-2026-1111', 'CVE-2026-2222'],
    highSignal: [feed[0], feed[1]],
  });

  assert.ok(bullets.length >= 3);
  assert.ok(bullets.some((text) => text.includes('1 KEV')));
  assert.ok(bullets.some((text) => text.includes('2 advisories criticos')));
  assert.ok(bullets.some((text) => text.includes('1 vitima de ransomware')));
});

test('buildFeedGroups separates KEV, critical, ransomware and other items', () => {
  const groups = buildFeedGroups({ recent: feed.slice(0, 3), victims });
  assert.deepEqual(groups.map((g) => g.key), ['kev', 'critical', 'ransomware', 'other']);
  assert.equal(groups.find((g) => g.key === 'kev').items.length, 1);
  assert.equal(groups.find((g) => g.key === 'critical').items.length, 1);
  assert.equal(groups.find((g) => g.key === 'ransomware').items.length, 1);
  assert.equal(groups.find((g) => g.key === 'other').items.length, 1);
});

test('buildDailyBrief filters the last 36 hours and returns the new contract', () => {
  const windowVictims = [
    ...victims,
    {
      name: 'Example US',
      group: 'LockExample',
      country: 'US',
      countryName: 'United States',
      sector: 'Technology',
      discovered: '2026-07-12T00:30:00.000Z',
      source: 'ransomware.live',
    },
    {
      name: 'Old Victim',
      group: 'OldGroup',
      country: 'BR',
      countryName: 'Brazil',
      sector: 'Retail',
      discovered: '2026-07-11T23:00:00.000Z',
      source: 'ransomware.live',
    },
  ];
  const brief = buildDailyBrief({
    feed,
    victims: windowVictims,
    now,
    countBy,
    latamCountries: new Set(['BR']),
  });

  assert.equal(brief.windowHours, 36);
  assert.equal(brief.summary.totalAdvisories, 3);
  assert.equal(brief.summary.kev, 1);
  assert.equal(brief.summary.critical, 2);
  assert.equal(brief.summary.cves, 2);
  assert.equal(brief.summary.ransomwareVictims, 2);
  assert.equal(brief.summary.latamVictims, 1);
  assert.ok(Array.isArray(brief.executiveSummary));
  assert.ok(Array.isArray(brief.feedGroups));
  assert.equal(brief.highlights.some((item) => item.link === 'https://example.com/old'), false);
});
