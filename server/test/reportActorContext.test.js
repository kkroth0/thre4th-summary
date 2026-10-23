import test from 'node:test';
import assert from 'node:assert/strict';
import { createReportActorContext, parseMalpediaActor } from '../reportActorContext.js';

const url = 'https://malpedia.caad.fkie.fraunhofer.de/actor/storm-0940';
const html = '<h2>Storm-0940 <a>Back</a></h2><p>aka: CovertNetwork-1658, ORB07</p><p>Actor active since at least 2021, with a close operational relationship.</p><hr><form>Unrelated text</form>';
const actor = { id: 'storm', name: 'Storm-0940', aliases: ['ORB07'], country: 'China', source: 'misp', refs: ['https://microsoft.com/report'], techniques: [{ id: 'T1078' }], software: [] };
test('Malpedia body is isolated from forms and its names remain source claims', () => {
  const value = parseMalpediaActor(html, url);
  assert.equal(value.name, actor.name);
  assert.deepEqual(value.aliases, ['CovertNetwork-1658', 'ORB07']);
  assert.equal(value.description.includes('Unrelated'), false);
});
test('report actor snapshot reuses catalog, caches reads and includes only source-article IOCs', async () => {
  let calls = 0;
  const build = createReportActorContext({ http: { get: async request => { assert.equal(request, url); calls++; return { data: html }; } } });
  const job = { title: 'Storm-0940 campaign', urls: ['https://lab.example/report'] };
  const actors = [actor];
  const items = [{ link: job.urls[0], actors: [{ id: actor.id }], iocs: { ips: ['45.148.10.95'] } }, { link: 'https://lab.example/history', actors: [{ id: actor.id }], iocs: { ips: ['45.148.10.96'] } }];
  const snapshots = await Promise.all([build(job, { actors, items }), build(job, { actors, items })]);
  assert.equal(calls, 1);
  const value = snapshots[0];
  assert.deepEqual(value.iocs.map(row => row.valor), ['45.148.10.95']);
  assert.deepEqual(value.profiles[0].aliases, ['ORB07']);
  assert.deepEqual(value.profiles[0].sourceClaims[0].aliases, ['CovertNetwork-1658', 'ORB07']);
  assert.ok(value.profiles[0].references.some(row => row.source === 'Malpedia'));
  await build(job, { actors, items }); assert.equal(calls, 1);
});
test('provider unavailable is cached and cannot suppress local catalog context', async () => {
  let calls = 0;
  const build = createReportActorContext({ http: { get: async () => { calls++; throw Error('unavailable'); } } });
  const args = { actors: [actor] };
  const value = await build({ title: 'Storm-0940 campaign' }, args);
  assert.equal(value.profiles[0].id, actor.id);
  await build({ title: 'Storm-0940 campaign' }, args);
  assert.equal(calls, 1);
});
