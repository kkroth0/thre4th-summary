import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createAxurLookup } from '../axurLookup.js';
import { readAxur } from '../axurAccess.js';
import { createLookupCache } from '../lookupCache.js';
import { createIocIntelligence } from '../iocIntelligence.js';
import { axurObservations } from '../axurIntelligence.js';

const ioc = { id:'one', value:'94[.]154[.]43[.]158', type:'ip', description:'Observed IOC', relatedInsights:['report'], createdAt:1792513501216 };
const report = { id:'report',title:'Axur report',threatActors:['APT28'],malwares:['Mirai'],publicationDate:1792513501216,attacks:[{code:'T1059'}],vulnerabilities:[{vulnerability:'CVE-2026-12345'}] };
function setup(t, handler, extra={}) {
  const store=createIocIntelligence(), cache=createLookupCache({ttlMs:Infinity}), calls=[];
  t.after(()=>{cache.close();store.close();});
  const options={scope:'owner',getKey:()=> 'test-key',http:{get:async(url,options)=>{calls.push({url,options});return {data:await handler(url,options,calls.length)};}},cache,store,readDetail:async(params)=>store.detail(params.value,params.owner,params),...extra};
  return {store,cache,calls,options,lookup:createAxurLookup(options)};
}
const response=(rows)=>({metadata:{page:1,perPage:100,offset:0,total:rows.length},iocs:rows});

test('an imported exact match reuses private reports with no API request',async t=>{
  const f=setup(t,()=>{throw Error('must not call');});await f.store.ingest(axurObservations([ioc],[report],{scope:'owner'}));
  const value=await f.lookup('94.154.43.158');assert.equal(f.calls.length,0);assert.equal(value.cacheState,'inventory-hit');assert.equal(value.data.Relatórios,1);assert.deepEqual(value.data['Atores mencionados'],['APT28']);assert.equal(f.store.detail('94.154.43.158','other'),null);
});
test('a partial import miss searches the API, exact-matches defanged values, joins reports and persists',async t=>{
  const f=setup(t,url=>url.includes('cyber-iocs')?response([ioc,{...ioc,id:'substring',value:'94.154.43.1580'}]):[report]);
  const value=await f.lookup('94.154.43.158');assert.equal(f.calls.length,2);assert.equal(f.calls[0].options.params.content,'94.154.43.158');assert.ok(f.calls.every(c=>!c.options.method));assert.equal(value.data.Relatórios,1);assert.equal(value.rawPayload.iocs.length,1);assert.equal(f.store.detail('94.154.43.158','owner').total,2);assert.equal(f.store.detail('94.154.43.158','other'),null);assert.deepEqual(value.data['Atores mencionados'],['APT28']);
  const hit=await f.lookup('94.154.43.158');assert.equal(hit.cacheState,'inventory-hit');assert.equal(f.calls.length,2);
});
test('successful absences survive cache restart, are account isolated, and fresh forces a new lookup',async t=>{
  const folder=mkdtempSync(path.join(tmpdir(),'axur-lookup-')),filePath=path.join(folder,'cache.sqlite');let cache=createLookupCache({filePath,ttlMs:Infinity}),calls=0;
  t.after(()=>{cache.close();assert.ok(folder.startsWith(tmpdir()));rmSync(folder,{recursive:true,force:true});});
  const f=setup(t,()=>response([]),{cache,http:{get:async()=>{calls++;return {data:response([])};}}});
  assert.equal((await f.lookup('94.154.43.158')).data['Registros Axur'],0);cache.close();cache=createLookupCache({filePath,ttlMs:Infinity});
  const resumed=createAxurLookup({...f.options,cache});assert.equal((await resumed('94.154.43.158')).cacheState,'persistent-hit');assert.equal(calls,1);
  await createAxurLookup({...f.options,scope:'other',cache})('94.154.43.158');assert.equal(calls,2);await resumed('94.154.43.158',{fresh:true});assert.equal(calls,3);
});
test('authentication, timeout, invalid payload and missing reports never become cached absences',async t=>{
  for(const kind of ['auth','timeout','invalid','incomplete','reports']){
    let fail=true;const f=setup(t,url=>{if(!fail)return response([]);if(kind==='auth')throw {response:{status:403},config:{Authorization:'private-key'}};if(kind==='timeout')throw {code:'ECONNABORTED'};if(kind==='invalid')return '<html>bad gateway</html>';if(kind==='incomplete')return {metadata:{page:1,perPage:100,offset:0,total:5},iocs:[]};return url.includes('cyber-iocs')?response([ioc]):[];});
    await assert.rejects(f.lookup('94.154.43.158'),error=>!error.message.includes('private-key'));fail=false;const count=f.calls.length;await f.lookup('94.154.43.158');assert.ok(f.calls.length>count,kind);
  }
});
test('substring search results do not create an exact hit or fetch unrelated reports',async t=>{
  const f=setup(t,()=>response([{...ioc,value:'https://example.org/94.154.43.158',type:'url'}]));const value=await f.lookup('94.154.43.158');assert.equal(f.calls.length,1);assert.equal(value.data['Registros Axur'],0);assert.equal(f.store.detail('94.154.43.158','owner'),null);
});
test('search follows all pages and fetches more than 25 related reports without truncation',async t=>{
  const ids=Array.from({length:26},(_,i)=>'report-'+i), filler=Array.from({length:99},(_,i)=>({...ioc,id:'filler-'+i,value:'https://example.org/'+i,type:'url'}));
  const f=setup(t,(url,options)=>url.includes('cyber-iocs')?{metadata:{page:options.params.page,perPage:100,offset:(options.params.page-1)*100,total:101},iocs:options.params.page===1?[...filler,{...ioc,relatedInsights:ids}]:[{...ioc,id:'second',relatedInsights:[]}] } : options.params.ids.split(',').map(id=>({...report,id})));
  const value=await f.lookup('94.154.43.158');assert.equal(f.calls.length,4);assert.equal(value.data.Relatórios,26);assert.equal(value.rawPayload.iocs.length,2);assert.equal(f.calls[1].options.params.page,2);assert.equal(f.calls[2].options.params.ids.split(',').length,25);
});
test('Axur import and lookup share one serialized GET queue per account',async()=>{
  let release;const gate=new Promise(resolve=>{release=resolve;});let active=0,peak=0;
  const http={get:async()=>{peak=Math.max(peak,++active);await gate;active--;return {data:{}};}};
  const first=readAxur('serialized',http,'https://api.axur.com/one',{}),second=readAxur('serialized',http,'https://api.axur.com/two',{});await Promise.resolve();await Promise.resolve();release();await Promise.all([first,second]);assert.equal(peak,1);
});
