import test from 'node:test';
import assert from 'node:assert/strict';
import {weeklyNewsPriority} from '../weeklyNewsSelection.js';
import {buildWeeklyReport,weeklyWindow} from '../weeklyReports.js';
const row=(link,title='Security update',score=20)=>({link,title,score,pubDate:'2026-10-21T12:00:00Z'});
test('weekly preferences exclude Medium and dominant Asian-language text, not Asian publishers in English',()=>{
 assert.equal(weeklyNewsPriority(row('https://research.medium.com/report')),null);
 assert.equal(weeklyNewsPriority(row('https://example.com/report','最新网络安全漏洞分析与攻击技术研究报告')),null);
 assert.ok(weeklyNewsPriority(row('https://asec.ahnlab.com/en/report','Chinese threat actors target Fortinet firewalls')));
 assert.ok(weeklyNewsPriority(row('https://example.com/report','APT report mentions 中国 and Microsoft')));
});
test('source host is verified and known sources and profile assets improve bounded ranking',()=>{
 const trusted=weeklyNewsPriority(row('https://www.cisa.gov/news','FortiGate security update'),{assets:[{vendor:'Fortinet',product:'FortiGate'}]});
 assert.ok(trusted.score>weeklyNewsPriority(row('https://unknown.example/report','Security update',999999)).score);
 assert.equal(weeklyNewsPriority({...row('https://cisa.gov.evil.example/news'),source:'CISA'}).sourceTier,'other');
 assert.ok(trusted.selectionReasons.some(reason=>reason.includes('Ativo do perfil')));
 assert.ok(!weeklyNewsPriority(row('https://example.com','JavaScript attack'),{assets:[{product:'Java'}]}).selectionReasons.some(reason=>reason.includes('Ativo do perfil')));
});
test('weekly grouped story uses eligible representative and preserves manual choices after editorial preference changes',()=>{
 const now=Date.parse('2026-10-22T12:00:00Z'),range=weeklyWindow(new Date(now));
 const medium={...row('https://author.medium.com/report','Medium report',10000),storyId:'same'};
 const official={...row('https://www.cisa.gov/report','Official report'),storyId:'same'};
 const report=buildWeeklyReport({publications:[medium,official]},{range,now});
 assert.equal(report.news[0].title,'Official report');
 const old={...report.news[0],id:'old',sources:[{link:medium.link}]};
 const retained=buildWeeklyReport({publications:[medium]},{range,now,selection:{newsIds:['old'],aiNewsIds:[]},retained:{news:[old]}});
 assert.equal(retained.candidates.news.length,0);assert.equal(retained.news[0].id,'old');
});
test('organization actor relationships and OT context prioritize matching stories',()=>{
 const profile={actors:['apt1'],ot:{present:true},sectors:['Energy'],threatModel:{actorIds:['apt1'],actors:[{id:'apt1',name:'Example APT'}]}};
 const base=row('https://www.cisa.gov/report');
 const result=weeklyNewsPriority({...base,actors:[{id:'apt1'}],categories:['OT/ICS'],sectors:['Energy']},profile);
 assert.ok(result.score>weeklyNewsPriority(base,profile).score);
 assert.ok(result.selectionReasons.some(reason=>reason.includes('Example APT')));
 assert.ok(weeklyNewsPriority({...base,actors:['Example APT']},profile).selectionReasons.some(reason=>reason.includes('Example APT')));
 assert.ok(!weeklyNewsPriority({...base,actors:[{id:'unrelated',name:'Other'}]},profile).selectionReasons.some(reason=>reason.includes('Ator')));
});
