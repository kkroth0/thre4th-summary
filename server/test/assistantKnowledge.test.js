import test from 'node:test';
import assert from 'node:assert/strict';
import { createKnowledgeAssistant, parseAssistantQuery, createAssistantGenerator } from '../assistantKnowledge.js';
const time = Date.parse('2026-10-15T12:00:00Z');
const news = (extra = {}) => ({ title: 'Mirai targets routers', description: 'Researchers report Mirai malware. CVE-2026-12345.', pubDate: '2026-10-15T09:00:00Z', link: 'https://research.example/report', score: 80, cves: ['CVE-2026-12345'], malware: [{ id: 'mirai', name: 'Mirai' }], ...extra });
function assistant(extra = {}) {
  return createKnowledgeAssistant({ getNews: () => [news()], getRevision: () => '1', now: () => time,
    getIoc: () => null, getEntities: () => [], getEntityEvidence: () => ({}), getCve: async () => null, getStatus: () => ({ publications: 1, indicators: 0, evidence: 0 }), ...extra });
}
test('commands and natural queries use bounded local intents', () => {
  assert.deepEqual(parseAssistantQuery('/briefing semana'), { kind: 'briefing', query: '', days: 7 });
  assert.equal(parseAssistantQuery('me dê um briefing').kind, 'briefing');
  assert.equal(parseAssistantQuery('CVE-2026-12345').kind, 'cve');
  assert.equal(parseAssistantQuery('8.8.8.8').kind, 'ioc');
  assert.equal(parseAssistantQuery('/ator@mybot Lazarus').query, 'Lazarus');
  assert.equal(parseAssistantQuery('/delete all').kind, 'help');
  assert.equal(parseAssistantQuery('Quais as notícias sobre Mirai?').kind, 'search');
});
test('briefings exclude future and old items, deduplicate events and rank KEV before equal severity', async () => {
  const rows = [news({ storyId: 'one' }), news({ title: 'Duplicate', link: 'https://other.example/dup', storyId: 'one', score: 70 }),
    news({ title: 'Exploited vulnerability', link: 'https://research.example/kev', kev: true, score: 60 }), news({ title: 'Future', link: 'https://research.example/future', pubDate: '2026-10-16' }),
    news({ title: 'Old', link: 'https://research.example/old', pubDate: '2026-10-01' })];
  const result = await assistant({ getNews: () => rows }).answer('owner', '/briefing');
  assert.ok(result.text.indexOf('Exploited vulnerability') < result.text.indexOf('Mirai targets'));
  assert.doesNotMatch(result.text, /Duplicate|Future|Old/); assert.equal(result.aiUsed, false);
});
test('natural malware panorama counts distinct publications and events with bounded source-backed output', async () => {
  const service = assistant({ getNews: () => [news({ storyId: 'one' }), news({ storyId: 'one', link: 'https://research.example/copy' }),
    news({ storyId: 'two', link: 'https://research.example/new', malware: [{ id: 'mirai', name: 'Mirai' }, { id: 'mirai', name: 'Mirai' }], pubDate: '2026-10-15T11:00:00Z' })] });
  const result = await service.answer('me', 'Quais malwares mais aparecem nas notícias da semana?');
  assert.match(result.text, /Mirai · 2 eventos \/ 3 publicações/); assert.match(result.text, /11:00:00/); assert.equal(result.aiUsed, false);
});
test('news queries single-flight AI, cache per owner and invalidate on dataset revision', async () => {
  let calls = 0, revision = 1, claims = 0;
  const service = assistant({ getRevision: () => revision, generate: async () => { calls++; await new Promise(resolve => setTimeout(resolve, 5)); return { bullets: [{ text: 'Mirai reportado por pesquisadores.', sources: ['N1'] }] }; } });
  const opts = { aiEnabled: true, claimAi: () => { claims++; return true; } };
  const results = await Promise.all([service.answer('one', '/buscar Mirai', opts), service.answer('one', '/buscar Mirai', opts)]);
  assert.equal(calls, 1); assert.equal(claims, 1); assert.ok(results.every(row => row.aiUsed));
  assert.equal((await service.answer('one', '/buscar Mirai', opts)).cacheHit, true);
  await service.answer('two', '/buscar Mirai', opts); assert.equal(calls, 2);
  revision++; await service.answer('one', '/buscar Mirai', opts); assert.equal(calls, 3);
});
test('unknown source IDs, invented CVEs and AI failures fall back to local evidence', async () => {
  for (const generate of [async () => ({ bullets: [{ text: 'Unsupported claim', sources: ['N9'] }] }),
    async () => ({ bullets: [{ text: 'CVE-1999-99999 was exploited', sources: ['N1'] }] }),
    async () => ({ bullets: [{ text: 'This campaign uses 4.3.2.1 for C2.', sources: ['N1'] }] }), async () => { throw Error('provider down'); }]) {
    const result = await assistant({ generate }).answer('me', '/briefing', { aiEnabled: true, claimAi: () => true });
    assert.equal(result.aiUsed, false); assert.equal(result.aiFallback, true); assert.match(result.text, /Mirai targets/); assert.doesNotMatch(result.text, /CVE-1999-99999|Unsupported claim/);
  }
});
test('unavailable AI budget leaves a local response and makes no provider call', async () => {
  const result = await assistant({ generate: () => { throw Error('must not call'); } }).answer('me', '/briefing', { aiEnabled: true, claimAi: () => false });
  assert.equal(result.aiUsed, false); assert.match(result.text, /Resumo local/);
});
test('IOC, actor and malware queries preserve owner scope and never send private context to AI', async () => {
  const scopes = [];
  const service = assistant({
    getIoc: (owner, value) => { scopes.push([owner, value]); return { total: 1, evidence: [{ title: 'Private investigation', provider: 'OTX', entities: [{ name: 'Actor A' }] }] }; },
    getEntities: (owner, kind) => { scopes.push([owner, kind]); return [{ id: 'one', name: kind === 'actor' ? 'Actor A' : 'Mirai' }]; },
    getEntityEvidence: (owner, kind, id) => { scopes.push([owner, kind, id]); return { counts: { ips: 2, domains: 3, hashes: 4, posts: 5 }, publications: [] }; },
    generate: () => { throw Error('private context must not be sent'); },
  });
  for (const query of ['/ioc 8.8.8.8', '/ator Actor A', '/malware Mirai']) assert.equal((await service.answer('private-owner', query, { aiEnabled: true, claimAi: () => true })).aiUsed, false);
  assert.ok(scopes.every(row => row[0] === 'private-owner'));
  assert.match((await service.answer('private-owner', '/ioc 8.8.8.8')).text, /Private investigation/);
});
test('no match is not a clean verdict and missing terms cannot enumerate all IOC evidence', async () => {
  assert.match((await assistant().answer('me', '/ioc 9.9.9.9')).text, /não significa.*seguro/);
  assert.match((await assistant().answer('me', '/ator')).text, /Informe o termo/);
});
test('generator caps context and response, uses fixed endpoint, no tools and bounded timeout', async () => {
  let request;
  const generate = createAssistantGenerator({ http: { post: async (...args) => { request = args; return { data: { choices: [{ message: { content: '{"bullets":[]}' } }] } }; } }, getKey: () => 'unit-test-only', model: 'test/model' });
  await generate({ question: 'x'.repeat(1000), evidence: [{ id: 'N1', title: 'public only' }] });
  assert.equal(request[0], 'https://openrouter.ai/api/v1/chat/completions'); assert.equal(request[1].max_tokens, 950);
  assert.equal(request[1].tools, undefined); assert.equal(request[2].timeout, 25000);
  assert.equal(JSON.parse(request[1].messages[1].content).question.length, 500);
});
