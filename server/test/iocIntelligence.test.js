import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createIocIntelligence,normalizeIndicator } from '../iocIntelligence.js';
import { createIntelligenceCollector,sourceObservations,threatFoxDays } from '../intelligenceSources.js';
import { buildActorEvidence } from '../actorEvidence.js';
import { correlateMalware } from '../malwareCatalog.js';
const now=()=>Date.parse('2026-10-13T12:00:00Z');
const actor={id:'G0032',name:'Lazarus'};
const matchActors=text=>/lazarus/i.test(text)?[actor]:[];
const matchMalware=text=>/vidar/i.test(text)?[{id:'win.vidar',name:'Vidar'}]:[];
const tf={query_status:'ok',data:[{id:'123',ioc:'46.101.130.1:443',ioc_type:'ip:port',malware:'win.vidar',malware_printable:'Vidar',first_seen:'2026-10-12 12:00:00 UTC',tags:['Lazarus'],reporter:'AnotherActor'}]};

test('batched entity evidence deduplicates source observations, preserves owner scope and rejects empty ID filters', async()=>{
  const store=createIocIntelligence({now});
  await store.ingest([{value:'8.8.8.8',provider:'OTX',externalId:'shared',link:'https://otx.alienvault.com/pulse/shared',malwares:[{id:'one',name:'Mirai'},{id:'two',name:'Mirai'}]},
    {value:'9.9.9.9',provider:'OTX',externalId:'private',link:'https://otx.alienvault.com/pulse/private',scope:'other',malwares:[{id:'two',name:'Mirai'}]}]);
  const rows=store.publications({owner:'me',kind:'malware',ids:['one','two']});
  assert.equal(rows.length,1);assert.deepEqual(rows[0].iocs.ips,['8.8.8.8']);
  assert.deepEqual(store.publications({owner:'me',kind:'malware',ids:[]}),[]);
  store.news.registerEntities([{kind:'actor',id:'canonical',name:'Catalog Actor'}],'global','catalog');
  store.news.registerEntities([{kind:'actor',id:'private-actor',name:'Private Actor'}],'other','OTX');
  assert.equal(store.news.entities({owner:'me',kind:'actor',id:'canonical'})[0].catalogued,1);
  assert.equal(store.news.entities({owner:'me',kind:'actor',id:'private-actor'}).length,0);
  store.close();
});

test('evidence pagination preserves every record and excludes other accounts',async()=>{
  const store=createIocIntelligence({now});
  await store.ingest(Array.from({length:205},(_,i)=>({value:'46.101.130.1',provider:'news',externalId:String(i)})));
  await store.ingest([{value:'46.101.130.1',scope:'other',provider:'OTX',externalId:'private'}]);
  assert.equal(store.detail('46.101.130.1','me').total,205);
  assert.equal(store.detail('46.101.130.1','me',{offset:200}).evidence.length,5);
  assert.equal(store.detail('46.101.130.1','me',{offset:205}).evidence.length,0);
  store.close();
});

test('catalog correlations retain older evidence after growing beyond 10000 provider observations',async()=>{
  const store=createIocIntelligence({now});
  await store.ingest(Array.from({length:10005},(_,i)=>({value:'46.101.130.1',provider:'OTX',externalId:String(i),published:new Date(now()+i).toISOString(),link:'https://otx.alienvault.com/pulse/'+i,actors:[actor],payload:i===0?{largePayload:'not needed by catalogs'}:undefined})));
  const rows=store.publications({kind:'actor',id:actor.id});assert.equal(rows.length,10005);assert.ok(rows.some(row=>row.link.endsWith('/0')));
  assert.ok(!JSON.stringify(rows).includes('largePayload'));
  await store.ingest([{value:'46.101.130.2',scope:'other',provider:'OTX',externalId:'private',link:'https://otx.alienvault.com/pulse/private',actors:[actor]}]);
  assert.equal(store.publications({owner:'me'}).length,10005);store.close();
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

test('revised news removes stale indicators and entity links while preserving independent provider evidence',async()=>{
  const store=createIocIntelligence({now});
  const row={link:'https://lab.example/review',title:'ASUS AiCloud',pubDate:'2026-10-12',malware:[{id:'404',name:'404 Keylogger'}],iocs:{ips:['2.0.0.39','154.81.156.10']}};
  await store.ingestNews([row]);
  await store.ingest([{value:'2.0.0.39',provider:'ThreatFox',externalId:'external',malwares:[{id:'valid',name:'Reported family'}]}]);
  await store.ingestNews([{...row,malware:[],iocs:{ips:['154.81.156.10']}}]);
  assert.deepEqual(store.detail('2.0.0.39').evidence.map(item=>item.provider),['ThreatFox']);
  assert.equal(store.detail('154.81.156.10').evidence[0].entities.length,0);
  assert.equal(store.list({malware:'404'}).total,0);
  await store.ingestNews([{...row,malware:[],iocs:{ips:[]}}]);assert.equal(store.detail('154.81.156.10'),null);
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

test('inventory export keeps source-specific entities, dates and account scope in the same SQL read', async () => {
  const store = createIocIntelligence({now});
  const published = '2026-10-13T12:34:56.000Z';
  await store.ingest([
    { value:'46.101.130.1',provider:'news',externalId:'report',published,title:'Report',link:'https://lab.example/report',actors:[{id:'A',name:'Reported actor'}],malwares:[{id:'M',name:'Reported family'}],cves:[{id:'CVE-2026-12345',name:'CVE-2026-12345'}] },
    { value:'46.101.130.1',provider:'ThreatFox',externalId:'api',published,malwares:[{id:'M2',name:'API family'}] },
    { value:'46.101.130.1',provider:'OTX',scope:'owner-one',externalId:'private',published,actors:[{id:'private',name:'Private actor'}] },
    { value:'46.101.130.2',provider:'AbuseIPDB',published:'2025-01-01T00:00:00Z' },
  ]);
  const range = { from: '2026-10-13T00:00:00.000Z', to: '2026-10-13T23:59:59.999Z' };
  const rows = store.exportRows({ owner:'owner-two', ...range });
  assert.equal(rows.length, 2);
  const news = rows.find(row => row.source === 'news');
  assert.deepEqual(news.actors, ['Reported actor']); assert.deepEqual(news.malware, ['Reported family']);
  assert.deepEqual(news.cves, ['CVE-2026-12345']); assert.equal(news.date, published);
  assert.deepEqual(rows.find(row => row.source === 'ThreatFox').actors, []);
  assert.equal(store.exportRows({ owner:'owner-one', ...range }).length, 3);
  assert.ok(!JSON.stringify(rows).includes('Private actor'));
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

test('archived official repository declarations backfill malware relationships without refetching a report',async()=>{
 const store=createIocIntelligence({now});
 await store.ingestNews([{link:'https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/report.txt',title:'C2Agent',text:"A malware family we've named C2Agent.",repository:{repo:'PaloAltoNetworks/Unit42-timely-threat-intel'},pubDate:'2026-10-12',iocs:{hashes:['a'.repeat(64)]},malware:[]}]);
 assert.equal(store.families()[0].name,'C2Agent');assert.equal(store.list({malware:'reported:c2agent'}).total,1);store.close();
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
  const store=createIocIntelligence({now});let calls=0;const observed=[];
  const collector=createIntelligenceCollector({store,now,getKeys:id=>id==='abuseipdb'?'test-key':'',onQuota:(...args)=>observed.push(args),http:{get:async()=>{calls++;throw {response:{status:429,headers:{'retry-after':'86400'}}};}}});
  await store.ingest([{value:'46.101.130.1',provider:'AbuseIPDB'}]);await collector.run();await collector.run();
  assert.equal(calls,1);assert.equal(store.list().total,1);assert.equal(collector.status().find(row=>row.id==='AbuseIPDB').status,'rate_limited');
  assert.deepEqual(observed,[['AbuseIPDB',{'retry-after':'86400'},'test-key','blacklist']]);store.close();
});

test('ThreatFox uses an overlapping incremental window, bounded backlog and capacity for initial backfill',async()=>{
  assert.equal(threatFoxDays({},now()),7);
  assert.equal(threatFoxDays({lastSuccessfulAt:new Date(now()-3600000).toISOString()},now()),1);
  assert.equal(threatFoxDays({lastSuccessfulAt:new Date(now()-2*86400000).toISOString()},now()),3);
  assert.equal(threatFoxDays({lastSuccessfulAt:'2020-01-01'},now()),7);
  const store=createIocIntelligence({now});let days=[],caps=[];
  const collector=createIntelligenceCollector({store,now,getKeys:id=>id==='abuse_ch'?'test-key':'',http:{post:async(url,body,options)=>{
    if(url.includes('threatfox')){days.push(body.days);caps.push(options.maxContentLength);}return {data:tf};
  }}});
  await collector.run();store.setState('source:ThreatFox',{...store.state('source:ThreatFox'),nextAt:null});await collector.run();
  assert.deepEqual(days,[7,1]);assert.deepEqual(caps,[32000000,32000000]);store.close();
});

test('transient collector failure preserves evidence and retries with backoff before the normal interval',async()=>{
  let at=now(),calls=0;const store=createIocIntelligence({now:()=>at});
  await store.ingest([{value:'46.101.130.1',provider:'MalwareBazaar'}]);
  const collector=createIntelligenceCollector({store,now:()=>at,getKeys:id=>id==='abuse_ch'?'test-key':'',http:{post:async url=>{
    if(url.includes('mb-api')){calls++;if(calls===1)throw {response:{status:502,headers:{}}};}return {data:{query_status:'ok',data:[]}};
  }}});
  await collector.run();assert.equal(store.list().total,1);assert.equal(Date.parse(store.state('source:MalwareBazaar').nextAt),at+60000);
  await collector.run();assert.equal(calls,1);at+=60000;await collector.run();assert.equal(calls,2);assert.equal(store.state('source:MalwareBazaar').status,'ready');store.close();
});
