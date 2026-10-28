import test from 'node:test';
import assert from 'node:assert/strict';
import {summarizeEntityEvidence,evidenceHttpLink} from './bulkEntityContext';
import type {BulkEvidence} from '../services/bulkContext';
const evidence=(id:string,published='2023-09-07T20:21:43Z'):BulkEvidence=>({provider:'OTX',title:'HIVE',link:`https://otx.alienvault.com/pulse/${id}`,published,collectedAt:'2026-10-28T13:13:19Z',confidence:null,reputation:null,entities:[{id:'actor-hive',name:'Hive',kind:'actor',relation:'mentioned-by-source'}]});
test('twelve historical Hive pulses produce one label with twelve source references and the publication date',()=>{
 const rows=Array.from({length:12},(_,i)=>evidence(String(i),i===0?'2023-09-18T05:15:32.926Z':undefined)),before=JSON.stringify(rows),summary=summarizeEntityEvidence(rows);
 assert.equal(summary.groups.length,1);assert.equal(summary.groups[0].name,'Hive');assert.equal(summary.groups[0].relation,'mentioned');assert.equal(summary.groups[0].references.length,12);assert.equal(summary.groups[0].latestPublished,'2023-09-18T05:15:32.926Z');assert.equal(summary.referenceCount,12);assert.equal(JSON.stringify(rows),before);
});
test('repeated observations of the same pulse do not inflate references or remove the original history',()=>{
 const first=evidence('one'),copy={...first,link:first.link+'?utm_source=feed#context',collectedAt:'2026-10-29'};const summary=summarizeEntityEvidence([first,copy]);assert.equal(summary.recordCount,2);assert.equal(summary.groups[0].references.length,1);assert.equal(summary.referenceCount,1);
});
test('provider, entity type and relation strength remain separate rather than manufacturing attribution',()=>{
 const mentioned=evidence('one'),declared=evidence('two');declared.entities=[{...declared.entities[0],relation:'attributed-by-source'}];const other={...mentioned,provider:'Axur'},malware={...mentioned,entities:[{...mentioned.entities[0],kind:'malware' as const}]};const summary=summarizeEntityEvidence([mentioned,declared,other,malware]);assert.equal(summary.groups.length,4);assert.equal(summary.groups.filter(g=>g.relation==='attributed').length,1);
});
test('missing publication dates never become collection dates and unsupported links never become clickable',()=>{
 const row=evidence('one','');row.link='javascript:alert(1)';const summary=summarizeEntityEvidence([row]);assert.equal(summary.groups[0].latestPublished,'');assert.equal(summary.groups[0].references[0].link,'');assert.equal(evidenceHttpLink('javascript:alert(1)'),null);assert.equal(evidenceHttpLink('https://example.org/report'),'https://example.org/report');
});
