import test from 'node:test';
import assert from 'node:assert/strict';
import { auditSemanticCorrelation, semanticTextHash } from '../semanticCorrelationAudit.js';
const model={id:'test-fixture-only',revision:'v1',dimensions:8};
const article=(link,title,language,expectedEvent)=>({link,title,language,expectedEvent,pubDate:'2026-10-14T12:00:00Z',actors:[],malware:[],campaigns:[],cves:[],iocs:{hashes:[]}});
const vector=row=>({link:row.link,model:model.id,revision:model.revision,textHash:semanticTextHash(row),vector:[1,0,0,0,0,0,0,0]});
const left=article('https://example.net/en','Attack targets one company','en','event1');
const right=article('https://example.net/pt','Invasores comprometem organização','pt','event1');
test('similarity and shared actor alone cannot propose a cross-language union',()=>{
  const rows=[{...left,actors:[{id:'G1',name:'Actor'}]},{...right,actors:[{id:'G1',name:'Actor'}]}];
  const report=auditSemanticCorrelation(rows,rows.map(vector),{model});
  assert.equal(report.results[0].candidate,false); assert.equal(report.results[0].cosine,1); assert.equal(report.automaticMergingEnabled,false);
});
test('pinned vectors plus source anchors are evaluated without mutating event IDs or enabling merges',()=>{
  const rows=[{...left,iocs:{hashes:['a'.repeat(64)]}},{...right,iocs:{hashes:['a'.repeat(64)]}}];
  const report=auditSemanticCorrelation(rows,rows.map(vector),{model});
  assert.equal(report.results[0].candidate,true); assert.equal(rows[0].storyId,undefined); assert.equal(report.automaticMergingEnabled,false);
  const stale=rows.map(vector); stale[0].textHash='old'; assert.equal(auditSemanticCorrelation(rows,stale,{model}).results[0].candidate,false);
  const unlabelledLanguage=rows.map(row=>({...row,language:undefined})); assert.equal(auditSemanticCorrelation(unlabelledLanguage,unlabelledLanguage.map(vector),{model}).crossLanguage.proposed.precision,null);
});
test('evaluation exposes incorrect unions, rejects model mismatches and excludes roundup bridges',()=>{
  const rows=[{...left,iocs:{hashes:['a'.repeat(64)]}},{...right,expectedEvent:'different',iocs:{hashes:['a'.repeat(64)]}}];
  const mismatched=rows.map(vector); mismatched[1].revision='other'; assert.equal(auditSemanticCorrelation(rows,mismatched,{model}).results[0].candidate,false);
  const roundup=[rows[0],{...rows[1],title:'Boletim semanal de ameaças'}]; assert.equal(auditSemanticCorrelation(roundup,roundup.map(vector),{model}).results[0].candidate,false);
  assert.throws(()=>auditSemanticCorrelation(rows,rows.map(vector),{model:{...model,revision:''}}),/pinned/);
  assert.equal(auditSemanticCorrelation(rows,rows.map(vector),{model}).proposed.falsePositive,1);
});
