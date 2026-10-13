import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createIocIntelligence,normalizeIndicator } from '../iocIntelligence.js';
import { createIntelligenceCollector,sourceObservations } from '../intelligenceSources.js';
import { buildActorEvidence } from '../actorEvidence.js';
import { correlateMalware } from '../malwareCatalog.js';
const now=()=>Date.parse('2026-10-13T12:00:00Z');
const actor={id:'G0032',name:'Lazarus'};
const matchActors=text=>/lazarus/i.test(text)?[actor]:[];
const matchMalware=text=>/vidar/i.test(text)?[{id:'win.vidar',name:'Vidar'}]:[];
const tf={query_status:'ok',data:[{id:'123',ioc:'46.101.130.1:443',ioc_type:'ip:port',malware:'win.vidar',malware_printable:'Vidar',first_seen:'2026-10-12 12:00:00 UTC',tags:['Lazarus'],reporter:'AnotherActor'}]};

test('evidence pagination preserves every record and excludes other accounts',async()=>{
  const store=createIocIntelligence({now});
  await store.ingest(Array.from({length:205},(_,i)=>({value:'46.101.130.1',provider:'news',externalId:String(i)})));
  await store.ingest([{value:'46.101.130.1',scope:'other',provider:'OTX',externalId:'private'}]);
  assert.equal(store.detail('46.101.130.1','me').total,205);
  assert.equal(store.detail('46.101.130.1','me',{offset:200}).evidence.length,5);
  assert.equal(store.detail('46.101.130.1','me',{offset:205}).evidence.length,0);
  store.close();
});

test('one IOC correlates news, OTX, ThreatFox and AbuseIPDB, surviving a restart',async()=>{
  const filePath=path.join(fs.mkdtempSync(path.join(os.tmpdir(),'ioc-store-test-')),'iocs.sqlite');
  let store=createIocIntelligence({filePath,now});
  const row={link:'https://lab.example/report',title:'Lazarus deploys Vidar',pubDate:'2026-10-12T10:00:00Z',actors:[actor],malware:[{id:'win.vidar',name:'Vidar'}],iocs:{ips:['46.101.130.1']}};
  await store.ingestNews([row]);
  await store.ingest(sourceObservations('ThreatFox',tf,{matchActors,matchMalware}));
  await store.ingest(sourceObservations('OTX',{results:[{id:'pulse1',public:true,name:'Lazarus Vidar campaign',modified:'2026-10-12T09:00:00Z',indicators:[{type:'IPv4',indicator:'46.101.130.1'}]}]},{matchActors,matchMalware}));
  await store.ingest(sourceObservations('AbuseIPDB',{data:[{ipAddress:'46.101.130.1',abuseConfidenceScore:95,lastReportedAt:'2026-10-12T11:00:00Z'}]}));
  await store.ingest(sourceObservations('ThreatFox',tf,{matchActors,matchMalware}));
  assert.equal(store.list().total,1);assert.equal(store.detail('46.101.130.1').evidence.length,4);
  assert.equal(store.detail('46.101.130.1').evidence.find(row=>row.provider==='AbuseIPDB').entities.length,0);
  assert.ok(store.detail('46.101.130.1').evidence.some(row=>row.entities.some(entity=>entity.id===actor.id)));
  assert.ok(!JSON.stringify(store.detail('46.101.130.1')).includes('AnotherActor'),'reporter is not an actor');
  store.close();store=createIocIntelligence({filePath,now});
  assert.equal(store.list({actor:actor.id}).total,1);
  const evidence=buildActorEvidence(store.publications({kind:'actor',id:actor.id}),actor.id,{now:now()});
  assert.equal(evidence.counts.ips,1);assert.equal(evidence.counts.posts,2);
  const malware=correlateMalware([{id:'win.vidar',name:'Vidar',aliases:[],references:[]}],store.publications());
  assert.equal(malware.get('win.vidar').ips.size,1);
  store.close();
});

test('private account observations and private OTX pulses never leak into shared results',async()=>{
  const store=createIocIntelligence({now});
  await store.ingest([{value:'secret.example.com',scope:'user1',provider:'OTX',externalId:'private'}]);
  assert.equal(store.list().total,0);assert.equal(store.list({owner:'user2'}).total,0);assert.equal(store.list({owner:'user1'}).total,1);
  assert.equal(store.detail('secret.example.com','user2'),null);
  assert.equal(store.exportRows({owner:'user2',from:'2026-01-01T00:00:00Z',to:'2026-12-31T23:59:59Z'}).length,0);
  assert.equal(store.exportRows({owner:'user1',from:'2026-01-01T00:00:00Z',to:'2026-12-31T23:59:59Z'}).length,1);
  assert.equal(sourceObservations('OTX',{results:[{id:'private',public:false,indicators:[{indicator:'46.101.130.1'}]}]}).length,0);
  assert.equal(sourceObservations('OTX',{results:[{id:'unknown-visibility',indicators:[{indicator:'46.101.130.1'}]}]}).length,0);
  store.close();
});

test('normalization rejects internal/malformed indicators and accepts defanged domains and IPv6',()=>{
  assert.equal(normalizeIndicator('10.0.0.1'),null);assert.equal(normalizeIndicator('file:///etc/passwd'),null);
  assert.equal(normalizeIndicator('https://user:password@evil.com'),null);
  assert.equal(normalizeIndicator('https://10.0.0.1/payload'),null);
  assert.deepEqual(normalizeIndicator('agent.x90[.]dev'),{type:'domain',value:'agent.x90.dev'});
  assert.equal(normalizeIndicator('2606:4700:4700::1111').type,'ip');
  assert.equal(normalizeIndicator('2606:4700:4700:0:0:0:0:1111').value,'2606:4700:4700::1111');
  assert.equal(normalizeIndicator('bücher.de').value,'xn--bcher-kva.de');
  assert.equal(normalizeIndicator('46.101.130.1:443','ip:port').value,'46.101.130.1');
});

test('URLhaus lookup preserves the queried indicator and family evidence',()=>{
  const rows=sourceObservations('URLhaus',{query_status:'ok',urls:[{tags:['Vidar']}],urlhaus_reference:'https://urlhaus.abuse.ch/host/evil.example.org/'},{query:'evil.example.org',scope:'me',matchMalware});
  assert.equal(rows[0].value,'evil.example.org');assert.equal(rows[0].malwares[0].id,'win.vidar');
});

test('explicit OTX adversaries and family labels retain source provenance even before catalogue registration',()=>{
  const rows=sourceObservations('OTX',{results:[{id:'p1',public:true,adversary:'UNC999999',malware_families:['UnknownAgent'],indicators:[{indicator:'46.101.130.1',type:'IPv4'}]}]});
  assert.equal(rows[0].actors[0].name,'UNC999999');assert.equal(rows[0].malwares[0].name,'UnknownAgent');
  assert.equal(rows[0].relation,'mentioned-by-source');
});

test('VirusTotal labels and Shodan CVEs contribute supported relationships, preserving complete lookup payloads',async()=>{
  const store=createIocIntelligence({now});
  const payload={data:{attributes:{last_analysis_date:now()/1000,tags:['Vidar','Lazarus'],last_analysis_stats:{malicious:5},reputation:-20}}};
  const rows=sourceObservations('VirusTotal',payload,{query:'46.101.130.1',scope:'me',matchActors,matchMalware});
  await store.ingest(rows.map(row=>({...row,payload})));
  await store.ingest(sourceObservations('Shodan',{ports:[443],vulns:{'CVE-2026-10000':{}},last_update:'2026-10-12'},{query:'46.101.130.1',scope:'me'}));
  const details=store.detail('46.101.130.1','me');
  assert.ok(details.evidence.some(row=>row.entities.some(entity=>entity.id==='win.vidar')));
  assert.ok(details.evidence.some(row=>row.entities.some(entity=>entity.id==='CVE-2026-10000')));
  assert.deepEqual(details.evidence.find(row=>row.provider==='VirusTotal').payload,payload);
  assert.equal(store.list().total,0);store.close();
});

test('collector is single-flight, respects schedules, and resumes OTX pages without unsafe redirects',async()=>{
  const store=createIocIntelligence({now});let otxCalls=0,tfCalls=0;
  const http={post:async()=>{tfCalls++;return {data:tf};},get:async url=>{assert.ok(url.startsWith('https://otx.alienvault.com/'));otxCalls++;return {data:{results:[{id:'p'+otxCalls,name:'Lazarus',public:true,modified:'2026-10-13T10:00:00Z',indicators:[{indicator:'46.101.130.1',type:'IPv4'}]}],next:otxCalls<3?`https://otx.alienvault.com/api/v1/pulses/subscribed?page=${otxCalls+1}`:null}};}};
  const collector=createIntelligenceCollector({store,http,getKeys:id=>['otx','abuse_ch'].includes(id)?'test-key':'',matchActors,matchMalware,now});
  const first=collector.run();assert.equal(first,collector.run());await first;
  assert.equal(otxCalls,2);assert.equal(tfCalls,2,'one call each for ThreatFox and MalwareBazaar');
  await collector.run();assert.equal(otxCalls,2);assert.equal(tfCalls,2);
  assert.equal(collector.status().find(row=>row.id==='AbuseIPDB').status,'missing_key');
  store.setState('source:OTX',{...store.state('source:OTX'),nextAt:null});await collector.run();assert.equal(otxCalls,3);assert.equal(store.state('source:OTX').cursor,null);
  store.setState('source:OTX',{...store.state('source:OTX'),cursor:'https://evil.example/collect',nextAt:null});await collector.run();assert.equal(otxCalls,3);assert.equal(store.state('source:OTX').status,'error');
  assert.ok(!JSON.stringify(collector.status()).includes('credentialRevision'));store.close();
});

test('rate limits keep collected data and delay retries until reset',async()=>{
  const store=createIocIntelligence({now});let calls=0;
  const collector=createIntelligenceCollector({store,now,getKeys:id=>id==='abuseipdb'?'test-key':'',http:{get:async()=>{calls++;throw {response:{status:429,headers:{'retry-after':'86400'}}};}}});
  await store.ingest([{value:'46.101.130.1',provider:'AbuseIPDB'}]);await collector.run();await collector.run();
  assert.equal(calls,1);assert.equal(store.list().total,1);assert.equal(collector.status().find(row=>row.id==='AbuseIPDB').status,'rate_limited');store.close();
});
