import test from 'node:test';
import assert from 'node:assert/strict';
import {createBulkEntityResolver} from '../bulkEntityIdentity.js';
import {analyzeBulkRow} from '../bulkShared.generated.mjs';
const actors=[{id:'G0119',name:'Indrik Spider',aliases:['Evil Corp'],source:'fixture'},{id:'G9000',name:'Hive',aliases:[],source:'fixture'}];
const malware=[{id:'S0154',name:'Cobalt Strike',aliases:['cobalt_strike'],source:'fixture'},{id:'S9000',name:'Hive',aliases:[],source:'fixture'}];
const resolver=createBulkEntityResolver({actors,malware});
const row=adversary=>({query:'93.184.216.34',state:'complete',context:{errors:[],publications:[],evidence:[]},result:{query:'93.184.216.34',overallScore:0,threatLevel:'unknown',vendorData:[{name:'AlienVault OTX',data:{'Pulse Details':[{adversary,malwareFamilies:[],attackIds:['T1059']}]}}]}});
test('source adversary labels never create actor identities, while catalog aliases use one canonical ID',()=>{
 const result=analyzeBulkRow(resolver.normalizeRow(row('Evil Corp')));
 assert.deepEqual(result.actors,['Indrik Spider']);assert.equal(result.record.actorIds,'G0119');assert.equal(result.pairs[0].actor,'Indrik Spider');assert.equal(result.record.otxActors,'Evil Corp');
 for(const label of ['mdrfckr-ssh-backdoor','busybox-wget-malware-downloader','Automated Scanner','TI Advisory No-ESAF-SOC-TI-2026-607']){
  const a=analyzeBulkRow(resolver.normalizeRow(row(label)));assert.deepEqual(a.actors,[]);assert.deepEqual(a.pairs,[]);assert.match(String(a.record.unclassifiedEntities),new RegExp(label));
 }
});
test('known software in the adversary field is software, never an actor or an actor-technique pair',()=>{
 const a=analyzeBulkRow(resolver.normalizeRow(row('cobalt_strike')));
 assert.deepEqual(a.actors,[]);assert.deepEqual(a.families,['Cobalt Strike']);assert.equal(a.record.softwareIds,'S0154');assert.deepEqual(a.pairs,[]);
});
test('a name shared by a group and software stays ambiguous unless its catalog ID proves the role',()=>{
 const a=analyzeBulkRow(resolver.normalizeRow(row('Hive')));assert.deepEqual(a.actors,[]);assert.match(String(a.record.unclassifiedEntities),/Hive/);
 assert.equal(resolver.resolve('actor','Hive','G9000').kind,'actor');assert.equal(resolver.resolve('malware','Hive','S9000').kind,'software');
 assert.equal(resolver.resolve('actor','Cobalt Strike','G0119').kind,'ambiguous','conflicting software labels and actor IDs must not manufacture an actor');
});
test('a real actor appearing in a software field never manufactures an attribution or a malware family',()=>{
 const input=row('');input.result.vendorData[0].data['Pulse Details'][0].malwareFamilies=['Evil Corp','New malware signature'];
 const a=analyzeBulkRow(resolver.normalizeRow(input));assert.deepEqual(a.actors,[]);assert.deepEqual(a.families,['New malware signature']);assert.match(String(a.record.unclassifiedEntities),/Evil Corp/);assert.equal(a.record.sourceSoftware,'New malware signature');
});
