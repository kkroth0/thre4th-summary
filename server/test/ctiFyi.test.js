import test from 'node:test';
import assert from 'node:assert/strict';
import { createCtiFyi, normalizeCtiPost, normalizeCtiGroups, mergeCtiActors, attachRansomwareActors, mergeRansomwareVictims, ctiPublications, ctiDate } from '../ctiFyi.js';
import { buildThreatMapResponse, normalizeVictim } from '../ransomwareLive.js';
import { buildActorEvidence } from '../actorEvidence.js';
const NOW = Date.parse('2026-10-14T21:00:00Z');
const post = (changes = {}) => ({ post_title: 'ACME Inc.', group_name: 'akira', discovered: '2026-10-14 12:30:00.123456', post_url: 'http://example.onion/#box_v27', enriched_metadata: { canonical_name: 'ACME', domain: 'acme.com', country_iso: 'BR', industry_sector: 'Manufacturing', summary: 'Source metadata', is_toxic: false }, ...changes });
const groups = () => normalizeCtiGroups({ results: [{ name: 'akira', post_count: 7, profile: { description: 'Source automated profile', aliases: ['Megazord'], ttps: ['T1486: Data Encrypted for Impact', 'TA0040: Impact', 'T1059.001: PowerShell'], references: ['javascript:alert(1)', 'https://www.cisa.gov/example'] } }, { name: 'legacy', profile: ['https://research.example/report'] }] });

test('CTI timestamps remain UTC, discovery does not become publication, victim domains are not malicious indicators', () => {
  assert.equal(ctiDate('2026-10-14 12:30:00.123456'), '2026-10-14T12:30:00.123Z'); assert.equal(ctiDate('not a date'), null);
  const row = normalizeCtiPost(post()); assert.equal(row.published, null); assert.equal(row.discovered, '2026-10-14T12:30:00.123Z');
  assert.equal(row.domainRole, 'victim'); assert.equal(row.claimStatus, 'unverified'); assert.equal(row.website, 'acme.com');
  assert.equal(normalizeVictim(row).published, null); assert.equal(normalizeCtiPost(post({ discovered: null })), null);
  assert.equal(normalizeCtiPost(post({ post_title: 'Renamed company' })).id, row.id);
  assert.notEqual(normalizeCtiPost(post({ post_url: 'http://example.onion/#box_v28' })).id, row.id);
  assert.notEqual(normalizeCtiPost(post({ post_url: '', post_title: 'A' })).id, normalizeCtiPost(post({ post_url: '', post_title: 'B' })).id);
});
test('group dossiers merge aliases into existing actors, keep MITRE evidence and ignore tactic IDs as techniques', () => {
  const existing = [{ id: 'ransomware:akira', name: 'Akira', aliases: [], techniques: [{ id: 'T1486', name: 'Authoritative MITRE name', url: 'https://attack.mitre.org/techniques/T1486/' }] }];
  const actors = mergeCtiActors(existing, groups());
  assert.equal(actors.length, 2); assert.equal(existing[0].ctiFyi, undefined); assert.deepEqual(actors[0].aliases, ['Megazord']);
  assert.equal(actors[0].techniques.find(row => row.id === 'T1486').name, 'Authoritative MITRE name');
  assert.ok(actors[0].techniques.some(row => row.id === 'T1059.001')); assert.ok(actors[0].techniques.every(row => !row.id.startsWith('TA')));
  assert.ok(actors[1].refs.includes('https://research.example/report')); assert.ok(actors[0].refs.every(url => url.startsWith('https://')));
  const victims = attachRansomwareActors([normalizeCtiPost(post())], actors); assert.equal(victims[0].actorId, 'ransomware:akira');
  const publications = ctiPublications(victims, actors); assert.equal(publications.length, 1); assert.equal(publications[0].iocs.domains.length, 0);
  const evidence = buildActorEvidence(publications, 'ransomware:akira', { now: NOW }); assert.equal(evidence.counts.posts, 1); assert.equal(evidence.counts.domains, 0); assert.equal(evidence.counts.ips, 0);
});
test('deduplication combines corroborating sources via actor aliases without collapsing separate claims or re-extortion', () => {
  const actors = mergeCtiActors([{ id: 'akira', name: 'Akira', aliases: ['Megazord'] }], groups());
  const primary = attachRansomwareActors([normalizeVictim({ name: 'ACME', website: 'https://www.acme.com/', group: 'Megazord', discovered: '2026-10-14T12:00:00Z' })], actors);
  const secondary = attachRansomwareActors([normalizeCtiPost(post()), normalizeCtiPost(post({ post_url: 'http://example.onion/#second' })), normalizeCtiPost(post({ discovered: '2026-08-14 12:30:00', post_url: 'http://example.onion/#older' }))], actors);
  const merged = mergeRansomwareVictims(primary, secondary); assert.equal(merged.length, 3); assert.deepEqual(merged[0].sources, ['ransomware.live', 'CTI.fyi']);
  const dashboard = buildThreatMapResponse(merged, { days: 7, now: NOW }); assert.equal(dashboard.victims.length, 2); assert.ok(dashboard.victims[0].actorId); assert.ok(dashboard.victims.some(row => row.ctiFyi));
});
test('ransomware group total is not capped by the top twelve chart rows',()=>{
  const rows=Array.from({length:15},(_,n)=>normalizeCtiPost(post({group_name:'group-'+n,post_url:'http://example.onion/#'+n})));
  const map=buildThreatMapResponse(rows,{days:7,now:NOW});assert.equal(map.groups.length,12);assert.equal(map.activeGroups,15);
});
test('multiple source group aliases retain all claim links on one established actor',()=>{
  const groups=normalizeCtiGroups({results:[{name:'akira',profile:{aliases:['Megazord']}},{name:'Akira ransomware',profile:{aliases:['Akira']}}]});
  const actors=mergeCtiActors([{id:'akira',name:'Akira',aliases:[]}],groups);assert.equal(actors.length,1);
  const rows=ctiPublications([normalizeCtiPost(post()),normalizeCtiPost(post({group_name:'Akira ransomware',post_url:'http://example.onion/#second'}))],actors);
  assert.equal(rows.length,2);assert.ok(rows.every(row=>row.actors[0].id==='akira'));assert.notEqual(rows[0].link,rows[1].link);
});
test('shared collector persists updates, removes quarantined claims, caches and resumes after restart', async () => {
  let clock = NOW, calls = 0, saved, changed = false;
  const http = { get: async url => { calls++; return { headers: { 'x-ratelimit-remaining': '58', 'x-ratelimit-reset': String((clock + 60000) / 1000) }, data: url.endsWith('/groups') ? { results: [{ name: 'akira' }] } : { count: 1, results: [post(changed ? { enriched_metadata: { is_toxic: true } } : {})] } }; } };
  const api = createCtiFyi({ http, now: () => clock, save: data => { saved = structuredClone(data); } });
  await Promise.all([api.refresh(), api.refresh()]); assert.equal(calls, 2); assert.equal(api.victims().length, 1); assert.equal(api.status().status, 'ready');
  assert.equal(api.status().rateLimit.remaining, 58); await api.refresh(); assert.equal(calls, 2);
  clock += 3600001; changed = true; await api.refresh(); assert.equal(api.victims().length, 0); assert.equal(api.status().rateLimit.remaining, 58);
  const restarted = createCtiFyi({ http, now: () => clock, read: () => saved }); assert.equal(restarted.status().groups, 1); await restarted.refresh(); assert.equal(calls, 4);
});
test('pagination is bounded, cursors survive errors, and rate limits cause backoff while saved evidence stays usable', async () => {
  let calls = 0, clock = NOW, saved;
  const api = createCtiFyi({ now: () => clock, save: data => { saved = structuredClone(data); }, http: { get: async url => {
    calls++; if (url.endsWith('/groups')) return { data: { results: [] } };
    return { data: { count: 4000, results: Array.from({ length: 500 }, (_, n) => post({ post_url: `http://example.onion/#${calls}-${n}` })) } };
  } } });
  await api.refresh(); assert.equal(calls, 5); assert.equal(api.victims().length, 2000); assert.equal(api.status().partial, true); assert.equal(saved.cursor.offset, 2000);
  clock += 15 * 60000 + 1;
  const broken = createCtiFyi({ now: () => clock, read: () => saved, http: { get: async () => { throw { response: { status: 429, headers: { 'retry-after': '120' } } }; } } });
  await broken.refresh(); assert.equal(broken.status().status, 'stale'); assert.equal(broken.victims().length, 2000); assert.equal(broken.status().nextAt, clock + 120000);
});
