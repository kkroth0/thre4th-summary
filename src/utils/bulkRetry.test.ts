import test from 'node:test';
import assert from 'node:assert/strict';
import { bulkRetryAt } from './bulkRetry';
import { runBulkQueue } from './bulkEnrichment';
import type { ThreatIntelligenceResult } from '../types/threat-intelligence';
const result = (query: string):ThreatIntelligenceResult => ({query,overallScore:0,threatLevel:'unknown',totalVendors:2,detections:0,vendorData:[{name:'VirusTotal',data:{Status:'Clean'}},{name:'ThreatFox',data:{},error:'Waiting',httpStatus:429,retryAt:600000}]});
test('a source cooldown does not interrupt the other 5611 queued indicators',async()=>{
 const queries=Array.from({length:5614},(_,i)=>String(i));let processed=0;
 await runBulkQueue(queries,async query=>{assert.equal(bulkRetryAt(result(query),new Map(),0),600000);processed++;},()=>false);
 assert.equal(processed,5614);
});
test('authentication errors do not become scheduled quota retries; transient failures are bounded',()=>{
 const r=result('one'),attempts=new Map<string,number>();
 r.vendorData[1]={...r.vendorData[1],httpStatus:502,errorCode:'PROVIDER_AUTH_FAILED'};
 assert.equal(bulkRetryAt(r,attempts,0),null);
 r.vendorData[1]={...r.vendorData[1],errorCode:undefined,retryAt:undefined};
 assert.equal(bulkRetryAt(r,attempts,0),30000);assert.equal(bulkRetryAt(r,attempts,0),60000);assert.equal(bulkRetryAt(r,attempts,0),null);
});
