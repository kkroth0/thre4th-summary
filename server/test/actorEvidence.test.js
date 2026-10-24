import test from 'node:test';
import assert from 'node:assert/strict';
import { actorPublications, buildActorActivity, buildActorEvidence } from '../actorEvidence.js';
const now = Date.parse('2026-10-12T12:00:00Z'); const hash = 'a'.repeat(64);
const row = (extra = {}) => ({ link: 'https://lab.example/report', title: 'Report', pubDate: '2026-10-01T00:00:00Z', source: 'Lab', actors: [{ id: 'G1', name: 'Actor One' }], iocs: { ips: ['1.1.1.1'], domains: ['c2.example.com'], hashes: [hash, 'b'.repeat(32)] }, ...extra });

test('tracking parameters and section fragments do not multiply publications, while distinct victim claims survive',()=>{
  const rows=actorPublications([row(),row({link:'https://lab.example/report?utm_source=feed#iocs'})],[]);
  assert.equal(rows.length,1);
  const claims=actorPublications([row({link:'https://cti.example/posts#claim-one'}),row({link:'https://cti.example/posts#claim-two'})],[]);
  assert.equal(claims.length,2);
});
test('actor evidence uses article attribution and deduplicates indicators and publications', () => {
    const publications = actorPublications([row()], [{ id: 'story', actors: [{ id: 'G2' }], sources: [row(), row({ link: 'https://other.example/post', actors: [] })] }]);
    const data = buildActorEvidence(publications, 'G1', { now });
    assert.deepEqual(data.counts, { ips: 1, domains: 1, hashes: 1, posts: 1 }); assert.equal(data.indicators[0].evidence[0].link, row().link);
    assert.equal(buildActorEvidence(publications, 'G2', { now }).publications.length, 0, 'does not inherit the story actor into another source');
    assert.deepEqual(buildActorActivity(publications, { now }).G1, { ips: 1, domains: 1, hashes: 1, posts: 1, latest: row().pubDate });
});

test('story overlays preserve archived summaries, publication precision and relevance context',()=>{
    const archived=row({description:'Archived summary',publicationTimeKnown:false,kev:true,sectors:['Energy']});
    const [merged]=actorPublications([archived],[{id:'story',sources:[{link:archived.link,title:'Updated title',score:90,publicationTimeKnown:undefined,actors:[]}]}]);
    assert.equal(merged.description,'Archived summary');assert.equal(merged.publicationTimeKnown,false);assert.equal(merged.kev,true);assert.deepEqual(merged.sectors,['Energy']);assert.deepEqual(merged.actors,[]);assert.equal(merged.title,'Updated title');
});
test('time range excludes old, invalid and future publications; entire archive is explicit', () => {
    const rows = [row({ pubDate: '2025-01-01' }), row({ pubDate: 'invalid' }), row({ pubDate: '2027-01-01' })];
    assert.equal(buildActorEvidence(rows, 'G1', { now }).counts.posts, 0);
    assert.equal(buildActorEvidence(rows, 'G1', { now, days: 0 }).counts.posts, 1);
});
