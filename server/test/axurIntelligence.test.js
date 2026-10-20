import test from 'node:test';
import assert from 'node:assert/strict';
import { axurObservations, createAxurImport } from '../axurIntelligence.js';
import { createIocIntelligence } from '../iocIntelligence.js';

const scope = 'owner';
const ioc = { id:'one', value:'8.8.8.8', type:'ip', source:'MalwareBazaar', createdAt:1792513501216,
  threatName:'Generic.Trojan', relatedInsights:['report'], relatedTTPs:[{code:'T1059',name:'Command execution'}] };
const insight = { id:'report', title:'Threat report', publicationDate:1792513501216, threatActors:['APT28','Unknown'], malwares:['Mirai'], vulnerabilities:[{vulnerability:'CVE-2026-12345'}], attacks:[{code:'T1059'}] };
const page = (number, iocs, total = 2) => ({ metadata:{page:number,perPage:1,offset:number-1,total}, iocs });

test('a shared report and detection label are resolved once per page without losing IOC relationships',()=>{
  let actorCalls=0,malwareCalls=0;
  const records=Array.from({length:100},(_,index)=>({...ioc,id:String(index),value:`8.8.4.${index+1}`,threatName:'Mirai'}));
  const rows=axurObservations(records,[{...insight,threatActors:['APT28']}],{scope,
    matchActors:()=>{actorCalls++;return [{id:'G0007',name:'APT28'}];},
    matchMalware:()=>{malwareCalls++;return [{id:'mirai',name:'Mirai'}];},
  });
  assert.equal(rows.length,200);assert.equal(actorCalls,1);assert.equal(malwareCalls,2);
  assert.equal(rows.filter(row=>row.actors?.[0]?.id==='G0007').length,100);
  assert.equal(rows.filter(row=>row.malwares?.[0]?.id==='mirai').length,200);
  assert.ok(rows.filter(row=>row.actors).every(row=>row.cves[0].id==='CVE-2026-12345'));
});
function fixture(t, handler, overrides = {}) {
  const store = createIocIntelligence(); t.after(() => store.close());
  const calls = [];
  const http = { get:async (url, options) => { calls.push({url,options}); return {data:await handler(url,options,calls.length)}; } };
  let clock = 1792513501216;
  const options = {store,scope,getKey:()=>'test-key',http,sleep:async()=>{},now:()=>clock,pageSize:1,...overrides};
  return {store,calls,options,importer:createAxurImport(options),advance:()=>{clock += 86400001;}};
}

test('normalizes and deduplicates, keeps contextual attribution private and preserves MITRE evidence', async t => {
  const store = createIocIntelligence();t.after(()=>store.close());
  const rows = axurObservations([{...ioc,value:'hxxps://bad[.]example.com/path?q=1'}],[insight],{scope,matchActors:()=>[{id:'G0007',name:'APT28'}]});
  await store.ingest(rows);await store.ingest(rows);
  assert.equal(store.status(scope).indicators,1);assert.equal(store.status(scope).evidence,2);
  assert.equal(store.detail('https://bad.example.com/path?q=1'),null);
  assert.equal(store.detail('https://bad.example.com/path?q=1','other'),null);
  const detail = store.detail('https://bad.example.com/path?q=1',scope);
  assert.ok(detail.evidence.some(row=>row.payload?.relatedTTPs?.[0]?.code==='T1059'));
  assert.deepEqual(detail.evidence.flatMap(row=>row.entities).filter(row=>row.kind==='actor'),[{kind:'actor',id:'G0007',name:'APT28',relation:'mentioned-with'}]);
  assert.equal(store.publications({owner:scope,kind:'actor',id:'G0007'})[0].link,'https://cti.axur.com/insight/report');
  assert.equal(store.entities('malware',scope)[0].name,'Mirai');
});

test('rejects unscoped imports, invalid indicators and generic AV family inference', () => {
  assert.throws(()=>axurObservations([ioc],[]));
  assert.throws(()=>createAxurImport({scope:'global'}));
  assert.deepEqual(axurObservations([{...ioc,value:'2.6.0.4R6_stable'}],[],{scope}),[]);
  assert.deepEqual(axurObservations([{...ioc,value:'https://user:password@bad.example.com'}],[],{scope}),[]);
  const rows = axurObservations([ioc],[],{scope});
  assert.equal(rows.length,1);assert.equal(rows[0].malwares,undefined);assert.equal(rows[0].payload.threatName,'Generic.Trojan');
});

test('uses a matched catalog alias without creating a second actor identity',()=>{
  const rows=axurObservations([ioc],[{...insight,threatActors:['Fancy Bear']}],{scope,matchActors:()=>[{id:'G0007',name:'APT28',matched:'Fancy Bear'}]});
  assert.equal(rows[1].actors[0].id,'G0007');
});

test('links an explicit unambiguous source family but never a substring of an AV detection label',()=>{
  const matchMalware=(text,options)=>options.structured?[{id:'mirai',name:'Mirai',matched:'Mirai'}]:[];
  const rows=axurObservations([{...ioc,threatName:'Mirai'}],[],{scope,matchMalware});
  assert.equal(rows[0].malwares[0].id,'mirai');assert.equal(rows[0].relation,'mentioned-by-source');
  const generic=axurObservations([{...ioc,threatName:'Generic.Mirai.Trojan'}],[],{scope,matchMalware});
  assert.equal(generic[0].malwares,undefined);
});

test('reads both GET endpoints, batches repeated insights, resumes and finishes without requesting an extra page', async t => {
  const f = fixture(t,(url,{params})=>url.endsWith('/iocs')?page(params.page,[{...ioc,id:String(params.page)}]):[insight]);
  await f.importer.run({maxPages:1});assert.equal(f.importer.status().page,2);
  const resumed = createAxurImport(f.options);
  await resumed.run({maxPages:5});assert.equal(resumed.status().status,'complete');assert.equal(resumed.status().processed,2);
  assert.equal(f.store.status(scope).indicators,1);assert.equal(f.store.status(scope).evidence,3);
  const before=f.calls.length;await resumed.run();assert.equal(f.calls.length,before);
  assert.ok(f.calls.every(call=>call.url.startsWith('https://api.axur.com/gateway/1.0/api/cyber-')&&call.options.maxRedirects===0));
  assert.deepEqual(f.calls.filter(call=>call.url.endsWith('/iocs')).map(call=>call.options.params.page),[1,2]);
});

test('replays the interrupted page after partial database commit without duplicating evidence',async t=>{
  const f = fixture(t,(url,{params})=>url.endsWith('/iocs')?page(params.page,[ioc],1):[insight]);
  const original=f.store.ingest;let fail=true;
  f.store.ingest=async rows=>{await original(rows);if(fail){fail=false;throw new Error('interrupted');}};
  await f.importer.run();assert.equal(f.importer.status().page,1);assert.equal(f.importer.status().status,'retrying');
  f.advance();await f.importer.run();assert.equal(f.importer.status().status,'complete');assert.equal(f.store.status(scope).evidence,2);
});

test('missing insights remain retryable instead of silently erasing correlations',async t=>{
  const f=fixture(t,url=>url.endsWith('/iocs')?page(1,[ioc],1):[]);
  await f.importer.run();assert.equal(f.importer.status().status,'retrying');assert.equal(f.importer.status().page,1);assert.equal(f.store.status(scope).evidence,0);
});

test('honors rate limit cooldown without persisting provider errors or credentials',async t=>{
  const f=fixture(t,()=>{throw {response:{status:429,headers:{'retry-after':'180'}},config:{headers:{Authorization:'Bearer sensitive-test-value'}}};});
  await f.importer.run();assert.equal(f.importer.status().nextAttemptAt,1792513501216+180000);
  assert.equal(f.importer.status().error,'Axur HTTP 429');assert.ok(!JSON.stringify(f.importer.status()).includes('sensitive-test-value'));
  await f.importer.run();assert.equal(f.calls.length,1);
});

test('uses a single flight for simultaneous import triggers',async t=>{
  const f=fixture(t,url=>url.endsWith('/iocs')?page(1,[ioc],1):[insight]);
  await Promise.all([f.importer.run(),f.importer.run(),f.importer.run()]);assert.equal(f.calls.length,2);
});

test('stops reads when no credential or storage reserve is available',async t=>{
  const f=fixture(t,()=>{throw new Error('must not request');},{getKey:()=>''});
  await f.importer.run();assert.equal(f.calls.length,0);
  const blocked=createAxurImport({...f.options,getKey:()=>'key',canWrite:()=>false});
  await blocked.run();assert.equal(f.calls.length,0);assert.equal(blocked.status().status,'retrying');
});

for(const [label,data]of Object.entries({ignoredPage:page(2,[ioc]),wrongSize:{...page(1,[ioc]),metadata:{page:1,perPage:50,offset:0,total:2}},empty:page(1,[]),malformed:{error:'oops'}})){
  test(`does not advance checkpoint on ${label}`,async t=>{
    const f=fixture(t,()=>data);await f.importer.run();assert.equal(f.importer.status().page,1);assert.equal(f.importer.status().status,'retrying');assert.equal(f.store.status(scope).evidence,0);
  });
}

test('detects repeated pages instead of marking an endless pagination loop successful',async t=>{
  const f=fixture(t,(url,{params})=>url.endsWith('/iocs')?page(params.page,[ioc],3):[insight]);
  await f.importer.run();assert.equal(f.importer.status().page,2);assert.equal(f.importer.status().status,'retrying');assert.equal(f.importer.status().processed,1);
});

test('timeout shrinks the request at the identical offset and persists a safe diagnostic',async t=>{
  let fail=true;
  const f=fixture(t,(_url,{params})=>{if(fail){fail=false;throw {code:'ECONNABORTED',config:{headers:{Authorization:'secret'}}};}return {metadata:{page:params.page,perPage:params.perPage,offset:(params.page-1)*params.perPage,total:125001},iocs:[{...ioc,relatedInsights:[]}]};},{pageSize:5000});
  f.store.setState('axur-import-v1:owner',{page:26,pageSize:5000,processed:125000,observations:125000,status:'running'});
  await f.importer.run();const pending=f.importer.status();
  assert.equal(pending.pageSize,1000);assert.equal(pending.page,126);assert.equal(pending.processed,125000);assert.equal(pending.failureCode,'timeout');assert.equal(pending.failureStage,'iocs');assert.ok(!JSON.stringify(pending).includes('secret'));
  f.advance();await f.importer.run();assert.equal(f.importer.status().processed,125001);assert.equal(f.importer.status().status,'complete');assert.equal(f.calls[1].options.params.page,126);
});

test('legacy generic failures resume with smaller pages without skipping or replaying previous offsets',async t=>{
  const f=fixture(t,(_url,{params})=>({metadata:{page:params.page,perPage:params.perPage,offset:(params.page-1)*params.perPage,total:275001},iocs:[{...ioc,relatedInsights:[]}]}));
  f.store.setState('axur-import-v1:owner',{page:56,pageSize:5000,processed:275000,observations:282061,status:'retrying',failures:3,error:'Importação interrompida; a página será tentada novamente.'});
  await f.importer.run();assert.equal(f.calls[0].options.params.page,276);assert.equal(f.calls[0].options.params.perPage,1000);assert.equal(f.importer.status().processed,275001);
});

test('persisted insight cache avoids repeated requests across pages and restart while retaining links',async t=>{
  const f=fixture(t,(url,{params})=>url.endsWith('/iocs')?page(params.page,[{...ioc,id:String(params.page)}]):[{...insight,iocs:[{value:'not copied'}]}]);
  await f.importer.run({maxPages:1});await createAxurImport(f.options).run();
  assert.equal(f.calls.filter(call=>!call.url.endsWith('/iocs')).length,1);assert.equal(f.importer.status().reportCacheHits,1);
  assert.equal(f.store.status(scope).evidence,3);assert.ok(!JSON.stringify(f.store.state('axur-report-v1:owner:report')).includes('not copied'));
});

test('expired or changed credentials never reuse a cached report',async t=>{
  let key='keyCase';
  const f=fixture(t,(url,{params})=>url.endsWith('/iocs')?page(params.page,[{...ioc,id:String(params.page)}],3):[insight],{getKey:()=>key});
  await f.importer.run({maxPages:1});key='keycase';await f.importer.run({maxPages:1});assert.equal(f.calls.filter(call=>!call.url.endsWith('/iocs')).length,2);
  f.advance();await f.importer.run({maxPages:1});assert.equal(f.calls.filter(call=>!call.url.endsWith('/iocs')).length,3);
});

test('missing insights and changed formats report the stage without advancing the page',async t=>{
  const f=fixture(t,url=>url.endsWith('/iocs')?page(1,[ioc],1):[]);
  await f.importer.run();assert.equal(f.importer.status().failureCode,'missing_insights');assert.equal(f.importer.status().failureStage,'insights');assert.equal(f.importer.status().page,1);
});
