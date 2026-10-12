import test from 'node:test';
import assert from 'node:assert/strict';
import { actorPublications, buildActorActivity, buildActorEvidence } from '../actorEvidence.js';
const now = Date.parse('2026-10-12T12:00:00Z'); const hash = 'a'.repeat(64);
const row = (extra = {}) => ({ link: 'https://lab.example/report', title: 'Report', pubDate: '2026-10-01T00:00:00Z', source: 'Lab', actors: [{ id: 'G1', name: 'Actor One' }], iocs: { ips: ['1.1.1.1'], domains: ['c2.example.com'], hashes: [hash, 'b'.repeat(32)] }, ...extra });
test('actor evidence uses article attribution and deduplicates indicators and publications', () => {
    const publications = actorPublications([row()], [{ id: 'story', actors: [{ id: 'G2' }], sources: [row(), row({ link: 'https://other.example/post', actors: [] })] }]);
    const data = buildActorEvidence(publications, 'G1', { now });
    assert.deepEqual(data.counts, { ips: 1, domains: 1, hashes: 1, posts: 1 }); assert.equal(data.indicators[0].evidence[0].link, row().link);
    assert.equal(buildActorEvidence(publications, 'G2', { now }).publications.length, 0, 'does not inherit the story actor into another source');
    assert.deepEqual(buildActorActivity(publications, { now }).G1, { ips: 1, domains: 1, hashes: 1, posts: 1, latest: row().pubDate });
});
test('time range excludes old, invalid and future publications; entire archive is explicit', () => {
    const rows = [row({ pubDate: '2025-01-01' }), row({ pubDate: 'invalid' }), row({ pubDate: '2027-01-01' })];
    assert.equal(buildActorEvidence(rows, 'G1', { now }).counts.posts, 0);
    assert.equal(buildActorEvidence(rows, 'G1', { now, days: 0 }).counts.posts, 1);
});
