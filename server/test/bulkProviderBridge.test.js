import test from 'node:test';
import assert from 'node:assert/strict';
import {createBulkProviderBridge,BULK_PRINCIPAL} from '../bulkProviderBridge.js';
const task={owner:'analyst',login:'analyst',org_until:0,provider:'VirusTotal',query:'8.8.8.8'};
function fixture(handler){const routes=[],bridge=createBulkProviderBridge({post:(...args)=>routes.push(args)},()=>{});bridge.register('/lookup','VirusTotal',handler);return{bridge,routes};}
test('bridge uses an internal owner, preserves the original body and recognizes a missing VT indicator',async()=>{
 const body={data:{attributes:{last_analysis_stats:{malicious:3,harmless:10}}}};
 const {bridge,routes}=fixture(async(req,res)=>{assert.equal(req[BULK_PRINCIPAL].sub,'analyst');assert.deepEqual(req.headers,{});assert.equal(req.signal.aborted,false);res.json(body);});assert.equal(routes.length,1);const result=await bridge.lookup(task);assert.deepEqual(result.rawPayload,body);assert.equal(result.name,'VirusTotal');
 const absent=fixture(async(req,res)=>res.status(404).json({error:{code:'NotFoundError'}}));assert.equal((await absent.bridge.lookup(task)).data.Status,'No data');
});
test('bridge distinguishes quota, rejected credentials and malformed successful responses',async()=>{
 const retry=Date.now()+60000;
 const quota=fixture(async(req,res)=>res.status(429).json({retryAt:retry,error:'limit'}));await assert.rejects(quota.bridge.lookup(task),e=>e.status===429&&e.retryAt===retry);
 const auth=fixture(async(req,res)=>res.json({query_status:'invalid_auth_key'}));await assert.rejects(auth.bridge.lookup(task),e=>e.status===403&&e.code==='PROVIDER_AUTH_FAILED');
 const unknown=fixture(async(req,res)=>res.json({query_status:'unknown_auth_key'}));await assert.rejects(unknown.bridge.lookup(task),e=>e.status===403&&e.code==='PROVIDER_AUTH_FAILED');
 const broken=fixture(async(req,res)=>res.json('<html>Bad Gateway</html>'));await assert.rejects(broken.bridge.lookup(task),e=>e.status===502);
 const wrapped=fixture(async(req,res)=>res.json({data:'<!doctype html><html>Bad Gateway</html>'}));await assert.rejects(wrapped.bridge.lookup(task),e=>e.status===502);
});
test('ThreatFox no_result with a textual data field is a successful source absence',async()=>{
 const body={query_status:'no_result',data:'Your search did not yield any results'};
 const bridge=createBulkProviderBridge({post:()=>{}},()=>{});bridge.register('/threatfox','ThreatFox',async(req,res)=>res.json(body));
 const result=await bridge.lookup({...task,provider:'ThreatFox'});assert.equal(result.data.Status,'No data');assert.deepEqual(result.rawPayload,body);
});
