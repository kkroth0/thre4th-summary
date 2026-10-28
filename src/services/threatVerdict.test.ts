import test from 'node:test';
import assert from 'node:assert/strict';
import {scoreThreatResults} from './threatVerdict';
import {bulkVerdictLabel} from '../utils/bulkEnrichment';
import {analyzeBulkRow} from '../utils/bulkAnalysis';
import type {VendorData} from '../types/threat-intelligence';
const source=(name:string,data:Record<string,unknown>):VendorData=>({name,data});
const absent=[source('ThreatFox',{Status:'No data'}),source('URLhaus',{Status:'No data'}),source('AlienVault OTX',{Status:'Clean','Pulse Count':'0 pulses'})];

test('an exact Axur record is contextual evidence, while an absence abstains and never proves safety',()=>{
 const hit=scoreThreatResults('94.154.43.158',[source('Axur',{'Registros Axur':2,Status:'Contexto encontrado'}),...absent]);assert.equal(hit.threatLevel,'suspicious');assert.equal(hit.signals?.[0].kind,'context');
 assert.equal(scoreThreatResults('94.154.43.158',[source('Axur',{'Registros Axur':0,Status:'Sem registro exato na Axur'})]).threatLevel,'unknown');
});
test('the observed 116.179.37.176 findings remain visible and explain their sources',()=>{
 const result=scoreThreatResults('116.179.37.176',[source('VirusTotal',{Malicious:4,Status:'Malicious'}),source('AbuseIPDB',{'Abuse Confidence Score':'80%','Total Reports':177}),source('AlienVault OTX',{'Pulse Count':'40 pulses',Status:'Suspicious Activity'}),...absent.slice(0,2)]);
 assert.equal(result.threatLevel,'malicious');assert.equal(result.detections,3);assert.deepEqual(result.signals?.map(s=>s.source),['VirusTotal','AbuseIPDB','AlienVault OTX']);
});
test('a minority detection, abuse score or OTX context cannot be erased by empty source responses',()=>{
 for(const signal of [source('VirusTotal',{Malicious:1}),source('AbuseIPDB',{'Abuse Confidence Score':'80%'}),source('AlienVault OTX',{'Pulse Count':'40 pulses'})]){
  const result=scoreThreatResults('116.179.37.176',[signal,...absent.filter(v=>v.name!==signal.name)]);assert.equal(result.threatLevel,'suspicious');assert.equal(result.reportingVendors,1);assert.equal(result.signals?.length,1);
 }
 assert.equal(scoreThreatResults('x',[source('MalwareBazaar',{Status:'Sample Found'}),...absent]).threatLevel,'malicious');
 assert.equal(scoreThreatResults('x',[source('URLhaus',{Status:'Malware Payload Found'}),source('VirusTotal',{Status:'Clean',Malicious:0})]).threatLevel,'malicious');
});
test('no-data responses abstain and incomplete lookups never present a negative verdict',()=>{
 assert.equal(scoreThreatResults('x',absent).threatLevel,'unknown');assert.equal(scoreThreatResults('x',absent).reportingVendors,0);
 const clean=source('VirusTotal',{Malicious:0,Status:'Clean'}),pending={name:'AlienVault OTX',data:{},isLoading:true};
 const running={query:'x',state:'running' as const,result:scoreThreatResults('x',[clean,pending])};assert.equal(running.result.threatLevel,'unknown');assert.equal(bulkVerdictLabel(running),'Coleta em andamento');assert.equal(analyzeBulkRow(running).record.verdict,'Coleta em andamento');
 const failed={query:'x',state:'partial' as const,result:scoreThreatResults('x',[clean,{name:'AlienVault OTX',data:{},error:'502'}])};assert.equal(failed.result.threatLevel,'unknown');assert.equal(bulkVerdictLabel(failed),'Consulta incompleta');
 assert.equal(bulkVerdictLabel({query:'x',state:'complete',result:scoreThreatResults('x',[clean])}),'Sem sinais nas fontes consultadas');
});
