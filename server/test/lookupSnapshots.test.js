import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createLookupCache,canonicalLookupQuery} from '../lookupCache.js';
const request={provider:'test-provider',query:'116.179.37.176',owner:'analyst',credentials:['private-test-key']};
function fixture(){const dir=mkdtempSync(path.join(tmpdir(),'ts-snapshots-'));return{filePath:path.join(dir,'lookup.sqlite'),close(){assert.ok(path.resolve(dir).startsWith(path.resolve(tmpdir())+path.sep+'ts-snapshots-'));rmSync(dir,{recursive:true,force:true});}};}
test('permanent snapshots survive restart, memory eviction, time and credential rotation within the same owner',async()=>{
 const f=fixture();let time=0,calls=0,cache=createLookupCache({filePath:f.filePath,ttlMs:Infinity,now:()=>time,maxEntries:1});
 const load=async()=>({data:{malicious:4,call:++calls}});
 try{await cache.get(request,load);await cache.get({...request,query:'9.9.9.9'},load);assert.equal(cache.stats().entries,1);cache.close();time=100*365*86400000;cache=createLookupCache({filePath:f.filePath,ttlMs:Infinity,now:()=>time});const hit=await cache.get({...request,credentials:['new-credential']},load);assert.equal(hit.state,'persistent-hit');assert.equal(hit.value.data.call,1);assert.equal(calls,2);hit.value.data.malicious=0;assert.equal((await cache.get(request,load)).value.data.malicious,4);await cache.get({...request,owner:'other'},load);assert.equal(calls,3);assert.equal(cache.stats().storedSnapshots,3);}finally{cache.close();f.close();}
});
test('only explicit refresh calls the provider and appends history; failed refresh retains the previous snapshot',async()=>{
 const f=fixture(),cache=createLookupCache({filePath:f.filePath,ttlMs:Infinity});let calls=0;const load=async()=>({data:{revision:++calls}});
 try{await cache.get(request,load);await cache.get({...request,fresh:true},load);assert.equal(cache.stats().storedSnapshots,2);await assert.rejects(cache.get({...request,fresh:true},async()=>{throw Error('502');}));assert.equal((await cache.get(request,load)).value.data.revision,2);assert.equal(calls,2);assert.equal(cache.stats().storedSnapshots,2);}finally{cache.close();f.close();}
});
test('a completed private batch supplies a permanent snapshot without spending another upstream request',async()=>{
 const f=fixture();let archives=0,calls=0;const cache=createLookupCache({filePath:f.filePath,ttlMs:Infinity,readArchive:async query=>{assert.equal(query.owner,request.owner);archives++;return{collectedAt:'2026-10-28T13:13:19Z',value:{data:{revision:'batch'},headers:{}}};}});
 try{const first=await cache.get(request,async()=>{calls++;return{data:{revision:'upstream'}};});assert.equal(first.state,'archive-hit');assert.equal(first.collectedAt,'2026-10-28T13:13:19Z');await cache.get(request,async()=>{calls++;});assert.equal(archives,1);assert.equal(calls,0);assert.equal(cache.stats().storedSnapshots,1);}finally{cache.close();f.close();}
});
test('known 404 absences are reusable; 429 and authentication failures never become cached findings',async()=>{
 const f=fixture(),cache=createLookupCache({filePath:f.filePath,ttlMs:Infinity});let calls=0;
 try{const input={...request,provider:'virustotal'},missing=async()=>{calls++;throw{response:{status:404,data:{error:{code:'NotFoundError'}}}};};assert.equal((await cache.get(input,missing)).value.httpStatus,404);await cache.get(input,missing);assert.equal(calls,1);for(const status of [401,403,429])await assert.rejects(cache.get({...input,fresh:true},async()=>{throw{response:{status}};}));assert.equal(cache.stats().storedSnapshots,1);assert.equal((await cache.get(input,missing)).value.httpStatus,404);}finally{cache.close();f.close();}
});
test('incomplete vendor payloads are never saved forever as negative findings',async()=>{
 const f=fixture(),cache=createLookupCache({filePath:f.filePath,ttlMs:Infinity});try{for(const provider of ['virustotal','abuseipdb','otx','threatfox','urlhaus','malwarebazaar'])await assert.rejects(cache.get({...request,provider},async()=>({data:{unexpected:'schema'}})),e=>e.response.status===502);assert.equal(cache.stats().storedSnapshots,0);await cache.get({...request,provider:'threatfox'},async()=>({data:{query_status:'no_result',data:'Your search did not yield any results'}}));assert.equal(cache.stats().storedSnapshots,1);}finally{cache.close();f.close();}
});
test('cache keys normalize domains and hashes while preserving URL path case',()=>{
 assert.equal(canonicalLookupQuery('virustotal','EXAMPLE.ORG'),'example.org');assert.equal(canonicalLookupQuery('virustotal','A'.repeat(64)),'a'.repeat(64));assert.notEqual(canonicalLookupQuery('virustotal','https://example.org/A'),canonicalLookupQuery('virustotal','https://example.org/a'));assert.equal(canonicalLookupQuery('urlhaus','host=EXAMPLE.ORG'),'host=example.org');
});
