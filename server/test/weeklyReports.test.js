import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {weeklyWindow,buildWeeklyReport,createWeeklyReports} from '../weeklyReports.js';
const NOW=Date.parse('2026-10-13T12:00:00Z');
const range=weeklyWindow(new Date(NOW));
const publication=(id,score=1,ai=false)=>({title:ai?'OpenAI model vulnerability '+id:'Security report '+id,link:'https://lab.example/'+id,pubDate:'2026-10-12T12:00:00Z',score,storyId:'story-'+id,categories:ai?['Artificial Intelligence']:[],iocs:{ips:['46.101.130.1']}});

test('Sunday boundaries use Fortaleza time, excluding the following Sunday without overlap',()=>{
 assert.equal(range.from,'2026-10-11T03:00:00.000Z');assert.equal(range.to,'2026-10-18T03:00:00.000Z');
 assert.equal(weeklyWindow(new Date('2026-10-18T02:59:59Z')).id,'2026-10-11');
 assert.equal(weeklyWindow(new Date('2026-10-18T03:00:00Z')).id,'2026-10-18');
 assert.throws(()=>weeklyWindow(new Date(NOW),'2026-10-12'));assert.throws(()=>weeklyWindow(new Date(NOW),'2026-02-31'));
});
test('weekly selection ranks and deduplicates events, with independent caps of 10 general and 5 AI news',()=>{
 const publications=[...Array.from({length:20},(_,i)=>publication(i,i)),...Array.from({length:12},(_,i)=>publication('ai'+i,i,true)),{...publication(19,19),link:'https://other.example/19'}, {...publication('future',1000),pubDate:range.to}, {...publication('old',1000),pubDate:'2026-10-10T12:00:00Z'}];
 const report=buildWeeklyReport({publications},{range,now:NOW});
 assert.equal(report.news.length,10);assert.equal(report.aiNews.length,5);assert.equal(report.news[0].id,'story-19');
 assert.equal(report.news[0].sources.length,2);assert.ok(!report.news.some(row=>row.id.includes('future')||row.id.includes('old')));
 assert.equal(report.candidates.news.length,20);assert.equal(report.candidates.aiNews.length,12);
});

test('weekly boundaries preserve publisher calendar dates and merge relationships from corroborating publications',()=>{
 const report=buildWeeklyReport({publications:[{...publication('same',80),pubDate:'2026-10-11T00:00:00Z',publicationTimeKnown:false,actors:[{name:'Actor A'}]},{...publication('same',10),link:'https://second.example/report',actors:[{name:'Actor B'}],cves:['CVE-2026-10000']}]},{range,now:NOW});
 assert.equal(report.news.length,1);assert.deepEqual(report.news[0].actors,['Actor A','Actor B']);assert.deepEqual(report.news[0].cves,['CVE-2026-10000']);
});

test('25 suggestions per category; editorial choices survive restart, refresh and ranking changes',async()=>{
 const file=path.join(fs.mkdtempSync(path.join(os.tmpdir(),'weekly-selection-test-')),'weekly.sqlite');
 let publications=[...Array.from({length:40},(_,i)=>publication(i,i)),...Array.from({length:30},(_,i)=>publication('ai'+i,i,true))];
 const options={filePath:file,now:()=>NOW,getInputs:async()=>({publications})};let store=createWeeklyReports(options);
 await store.refresh('owner');assert.equal(store.get('owner').report.candidates.news.length,25);assert.equal(store.get('owner').report.candidates.aiNews.length,25);
 const selected={newsIds:['story-15'],aiNewsIds:['story-ai5']};store.select('owner',range.id,selected);
 assert.throws(()=>store.select('other',range.id,selected));assert.throws(()=>store.select('owner',range.id,{newsIds:['unknown'],aiNewsIds:[]}));
 assert.throws(()=>store.select('owner',range.id,{newsIds:Array.from({length:11},(_,i)=>'story-'+(20+i)),aiNewsIds:[]}));
 assert.throws(()=>store.select('owner',range.id,{newsIds:[],aiNewsIds:Array.from({length:6},(_,i)=>'story-ai'+(20+i))}));
 store.close();store=createWeeklyReports(options);
 publications.push(...Array.from({length:30},(_,i)=>publication('new'+i,1000+i)));await store.refresh('owner');
 const report=store.get('owner').report;assert.equal(report.selection.mode,'manual');assert.deepEqual(report.news.map(row=>row.id),selected.newsIds);assert.deepEqual(report.aiNews.map(row=>row.id),selected.aiNewsIds);
 assert.equal(report.sources.length,2);assert.ok(!report.candidates.news.some(row=>row.id==='story-15'));
 store.select('owner',range.id,{newsIds:[],aiNewsIds:[]});await store.refresh('owner');assert.equal(store.get('owner').report.news.length,0);store.close();
});

test('selected publication follows an event identity change during correlation',async()=>{
 let publications=[publication('one')];const store=createWeeklyReports({now:()=>NOW,getInputs:async()=>({publications})});
 await store.refresh('owner');store.select('owner',range.id,{newsIds:['story-one'],aiNewsIds:[]});
 publications=[{...publication('one'),storyId:'merged-event'}];await store.refresh('owner');await store.refresh('owner');
 assert.deepEqual(store.get('owner').report.selection.newsIds,['merged-event']);assert.equal(store.get('owner').report.news[0].sources[0].link,publication('one').link);store.close();
});
test('KEV added during the week includes older CVEs, AI CVEs are classified, and criminal victim claims remain unconfirmed',()=>{
 const report=buildWeeklyReport({vulnerabilities:[{id:'CVE-2025-10000',published:'2025-01-01',dateAdded:'2026-10-12',kev:true,cvss:7,action:'Apply patch'},{id:'CVE-2026-10000',published:'2026-10-12',vendor:'ollama',description:'model vulnerability',severity:'CRITICAL',cvss:10}],victims:[{id:'v1',name:'Example',country:'BR',group:'ExampleGroup',published:'2026-10-12'},{id:'v1',name:'Example',country:'BR',group:'ExampleGroup',published:'2026-10-12'}]},{range,now:NOW});
 assert.equal(report.vulnerabilities.total,1);assert.equal(report.vulnerabilities.kevCount,1);assert.equal(report.vulnerabilities.ai.total,1);
 assert.equal(report.ransomware.brazil,1);assert.equal(report.ransomware.victims[0].claimStatus,'unconfirmed');
});
test('daily drafts persist after restart, remain account scoped, and update only after a content change',async()=>{
 const file=path.join(fs.mkdtempSync(path.join(os.tmpdir(),'weekly-report-test-')),'weekly.sqlite');
 let inputs={publications:[publication('one')]},calls=0;
 const options={filePath:file,now:()=>NOW,getInputs:async()=>{calls++;return {...inputs};}};
 let store=createWeeklyReports(options);const first=await store.refresh('owner');await store.refresh('owner');assert.equal(store.get('owner').report.revision,1);
 assert.equal(store.get('other').report,null);
 inputs={publications:[publication('one'),publication('two')]};await store.refresh('owner');assert.equal(store.get('owner').report.revision,2);
 store.close();store=createWeeklyReports(options);assert.equal(store.get('owner').report.news.length,2);assert.equal(first.news.length,1);
 store.configure('owner',{enabled:false});await store.refresh('owner');assert.equal(calls,3);store.close();
});
test('failed NVD update preserves previous vulnerability data and exposes failed source coverage',async()=>{
 let failed=false;
 const store=createWeeklyReports({now:()=>NOW,getInputs:async()=>({vulnerabilities:failed?[]:[{id:'CVE-2026-10000',published:'2026-10-12',cvss:10}],coverage:{vulnerabilities:{status:failed?'error':'ready'}}})});
 await store.refresh('owner');failed=true;await store.refresh('owner');
 assert.equal(store.get('owner').report.vulnerabilities.total,1);assert.equal(store.get('owner').report.coverage.vulnerabilities.status,'error');store.close();
});

test('scheduler rolls over on Sunday and incorporates late publications in the previous week',async()=>{
 let clock=Date.parse('2026-10-17T23:00:00Z');let inputs={publications:[publication('one')]};
 const store=createWeeklyReports({now:()=>clock,getInputs:async()=>({...inputs})});await store.refresh('owner');
 clock=Date.parse('2026-10-18T03:01:00Z');inputs={publications:[publication('one'),publication('late')]};
 await store.tick();assert.equal(store.get('owner').report.range.id,'2026-10-18');assert.equal(store.get('owner','2026-10-11').report.news.length,2);store.close();
});


test('scheduled historical refresh keeps the recipient used for that week',async()=>{
 let clock=Date.parse('2026-10-17T23:00:00Z');const profiles={first:{id:'first',name:'First'},second:{id:'second',name:'Second'}};
 const store=createWeeklyReports({now:()=>clock,getProfile:(_owner,id)=>profiles[id],getInputs:async()=>({publications:[publication('one')]})});
 store.configure('owner',{enabled:true,profileId:'first'});await store.refresh('owner');
 clock=Date.parse('2026-10-18T03:01:00Z');store.configure('owner',{enabled:true,profileId:'second'});await store.tick();
 assert.equal(store.get('owner').report.profile.id,'second');assert.equal(store.get('owner','2026-10-11').report.profile.id,'first');store.close();
});
