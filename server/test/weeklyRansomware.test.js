import test from 'node:test';
import assert from 'node:assert/strict';
import {createWeeklyRansomware,historyMonths,weeklyProfile} from '../weeklyRansomware.js';
import {buildWeeklyReport,weeklyWindow} from '../weeklyReports.js';
const now=Date.parse('2026-10-22T15:00:00Z'),range=weeklyWindow(new Date(now));
test('Ultrapar maps six business themes into four exact source sectors without duplicates',()=>{
 const p=weeklyProfile({id:'u',name:'Grupo Ultrapar'});
 assert.deepEqual(p.ransomwareSectors,['Financial Services','Transportation','Manufacturing','Energy & Utilities']);
 const victims=['Financial Services','Transportation','Manufacturing','Energy & Utilities','Technology'].map((sector,i)=>({id:String(i),country:'BR',name:'Company '+i,sector,group:'G',discovered:'2026-10-20T12:00:00Z',published:'2026-01-01'}));
 const d=buildWeeklyReport({victims},{range,now,profile:p});
 assert.equal(d.ransomware.latam,5);assert.equal(d.ransomware.focusCount,4);
 assert.equal(d.ransomware.focusBySector.reduce((n,s)=>n+s.count,0),4);
 assert.equal(d.ransomware.history.at(-1).latam,5);
});
test('monthly Pro history covers twelve weeks, shares requests and never calls the recent-100 feed',async()=>{
 const calls=[],http={get:async(url,options)=>{calls.push({url,options});return {data:{count:1,victims:[{id:String(options.params.month),victim:'Observed',discovered:'2026-10-20T12:00:00Z'}]}};}};
 const api=createWeeklyRansomware({http,apiKey:'test-key',now:()=>now});
 const [a,b]=await Promise.all([api.get(range),api.get(range)]);
 assert.deepEqual(historyMonths(range,now),['2026-08','2026-09','2026-10']);
 assert.equal(calls.length,3);assert.equal(a.victims.length,3);assert.deepEqual(a,b);
 assert.ok(calls.every(c=>c.options.params.date==='discovered'&&c.options.headers['X-API-KEY']==='test-key'&&c.url.endsWith('/victims/')));
 await api.get(range);assert.equal(calls.length,3);
});
test('truncated month exposes partial coverage, leaves chart weeks missing and can retry',async()=>{
 let broken=true;const http={get:async()=>({data:{count:broken?2:1,victims:[{id:'one',discovered:'2026-10-20T12:00:00Z'}]}})};
 const api=createWeeklyRansomware({http,apiKey:'test-key',now:()=>now});
 const first=await api.get(range);assert.equal(first.coverage.status,'partial');assert.equal(first.victims.length,0);
 const report=buildWeeklyReport({victims:[],coverage:{ransomware:first.coverage}},{range,now});
 assert.ok(report.ransomware.history.every(w=>w.latam===null));
 broken=false;assert.equal((await api.get(range)).coverage.status,'ready');
});
