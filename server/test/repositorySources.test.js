import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRepositoryResolver, REPOSITORY_SOURCES, repositoryIocs } from '../repositorySources.js';
import { createFeedCollector } from '../feedCollector.js';
import { enrichFeedItems } from '../feedEnrichment.js';
import { prepareFeedJobDocuments } from '../feedJobDocuments.js';

const NOW = new Date('2026-10-13T12:00:00Z');
const revision = 'a'.repeat(40), blob = 'b'.repeat(40);
const sample = fs.readFileSync(new URL('./fixtures/c2agent-indicators.txt', import.meta.url), 'utf8');
const memory = () => { const data = new Map(); return { get:key => data.get(key), set:(key,value) => data.set(key,value) }; };

test('C2Agent preserves all 25 agent and 7 stager hashes, excluding legitimate MCP services', () => {
  const iocs = repositoryIocs(sample, '2026-10-09-C2Agent-malware.txt');
  const expected = [...sample.matchAll(/\b[a-f0-9]{64}\b/g)].map(match => match[0]);
  assert.equal(expected.length,32);
  assert.deepEqual(iocs.hashes, expected);
  assert.ok(iocs.domains.includes('agent.x90.dev'));
  assert.ok(iocs.urls.includes('https://agent.x90.dev/data/copilot.txt'));
  assert.ok(!JSON.stringify(iocs).includes('firecrawl'));
});

test('CSV selects indicator columns, parses quotes, ignores references and benign services', () => {
  const csv = '\uFEFFType,Indicator,Context\r\nDomain,attacker[.]xyz,"See https://unit42.paloaltonetworks.com/report, details"\r\nURL,hxxps://payload[.]xyz/drop,malicious\r\nDomain,mcp.firecrawl[.]dev,legitimate service abused\r\n';
  assert.deepEqual(repositoryIocs(csv,'report-ioc-network.csv'), { ips:[],hashes:[],domains:['attacker.xyz','payload.xyz'],urls:['https://payload.xyz/drop'] });
  assert.equal(repositoryIocs('Field,Value\nSource,https://research.example.com','campaign-metadata.csv').urls.length,0);
});

test('repositories are incremental, pin files to commit SHA and resume deferred reports with cached tree', async () => {
  const cache = memory(), calls = [];
  const feed = REPOSITORY_SOURCES[0];
  const paths = ['2026-10-09-C2Agent-malware.txt','2026-10-08-Another-malware.txt'];
  const request = async url => {
    calls.push(url);
    if (url.endsWith('/commits/main')) return { status:200,headers:{etag:'head'},data:{sha:revision} };
    if (url.includes('/git/trees/')) return { status:200,data:{tree:[...paths.map(path => ({path,type:'blob',mode:'100644',sha:blob,size:10000})),{path:'payload.exe',type:'blob',sha:blob,size:32}]} };
    assert.ok(url.startsWith(`https://raw.githubusercontent.com/${feed.repo}/${revision}/`));
    return {status:200,data:sample};
  };
  const collector = createFeedCollector({ cache, now:()=>NOW, resolve:createRepositoryResolver({request,now:()=>NOW,maxReports:1}), parse:()=>{throw Error('not RSS');} });
  const first = await collector.collect([feed]);
  assert.equal(first.items.length,1);
  assert.equal(first.items[0].iocs.hashes.length,32);
  assert.equal(first.health.get(feed.url).method,'github');
  const second = await collector.collect([feed]);
  assert.equal(second.items.length,2);
  assert.equal(calls.length,4);
  await collector.collect([feed]); assert.equal(calls.length,4);
  const enriched = enrichFeedItems(second.items,{ actors:()=>[],malware:()=>[],campaigns:()=>[],seller:()=>null,categorize:()=>({categories:['Malware'],primary:'Malware'}) });
  assert.equal(enriched[0].iocs.hashes.length,32);
  assert.ok(!JSON.stringify(enriched[0].iocs).includes('firecrawl'));
});

test('cached repository indicators survive outages, and unknown repositories are rejected', async () => {
  const feed=REPOSITORY_SOURCES[0], cache=memory();
  cache.set(feed.url,{items:[{link:feed.url+'/blob/main/report.txt',pubDate:NOW.toISOString(),iocs:{hashes:[blob]}}]});
  const collector=createFeedCollector({cache,now:()=>NOW,resolve:createRepositoryResolver({request:async()=>{throw Error('quota');},now:()=>NOW})});
  const result=await collector.collect([feed]);
  assert.equal(result.items.length,1); assert.equal(result.health.get(feed.url).status,'stale');
  await assert.rejects(createRepositoryResolver()({url:'https://evil.example',repo:'other/repo'}),/Unknown/);
});

test('cached article text avoids rescraping and keeps indicators beyond text limit', () => {
  const articleCache=memory(),rssCache=memory(); const link='https://lab.example/report';
  articleCache.set(link,{text:'a'.repeat(70000),collectedAt:NOW.toISOString()});
  const items=[{link,title:'C2Agent',iocs:{hashes:['c'.repeat(64)]}}];
  const docs=prepareFeedJobDocuments([link,'https://lab.example/unknown'],{items,articleCache,rssCache});
  assert.equal(docs.length,1); assert.equal(docs[0].text.length,64000); assert.ok(docs[0].iocText.includes('c'.repeat(64)));
});

test('Wolf reports use commit dates for historical backfill, keeping old evidence dates', async () => {
  const feed=REPOSITORY_SOURCES[1],cache=memory();
  const request=async url => {
    if(url.endsWith('/commits/main')) return {status:200,data:{sha:revision}};
    if(url.includes('/git/trees/')) return {status:200,data:{tree:[{path:'threat-intelligence/report/report-network.csv',type:'blob',mode:'100644',sha:blob,size:100}]}};
    if(url.includes('/commits?')) return {status:200,data:[{commit:{committer:{date:'2026-06-01T10:00:00Z'}}}]};
    return {status:200,data:'Type,Indicator,Context\nDomain,payload[.]xyz,malware'};
  };
  const result=await createFeedCollector({cache,now:()=>NOW,resolve:createRepositoryResolver({request,now:()=>NOW})}).collect([feed]);
  assert.equal(result.items.length,1); assert.equal(result.items[0].pubDate,'2026-06-01T10:00:00.000Z');
  assert.deepEqual(result.items[0].iocs.domains,['payload.xyz']);
});
