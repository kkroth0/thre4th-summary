import test from 'node:test';
import assert from 'node:assert/strict';
import {weeklyNewsPriority,diverseWeeklySuggestions,WEEKLY_EDITORIAL_WEIGHTS} from '../weeklyNewsSelection.js';
import {buildWeeklyReport,weeklyWindow,filterWeeklyReportLanguages} from '../weeklyReports.js';
const row=(link,title='Security update',score=20)=>({link,title,score,pubDate:'2026-10-21T12:00:00Z'});

test('a Korean headline cannot be diluted by English summaries or cached article boilerplate',()=>{
 const title='2026년 3분기 랜섬웨어 동향보고서';
 const description='Quarterly ransomware threat intelligence report with indicators and technical analysis. '.repeat(30);
 assert.equal(weeklyNewsPriority({...row('https://asec.ahnlab.com/ko/report',title,125),description},null,{body:researchBody,now:dateNow}),null);
 for(const title of ['脅威調査報告','威胁调查报告','랜섬웨어 보고서','รายงานภัยคุกคาม'])assert.equal(weeklyNewsPriority({...row('https://research.example/report',title),description}),null,title);
 assert.ok(weeklyNewsPriority({...row('https://asec.ahnlab.com/en/report','Asian threat actors target European companies'),description}));
});

test('a saved event can keep its supported-language coverage and selection without retaining a Korean headline',()=>{
 const now=Date.parse('2026-10-22T12:00:00Z');
 const english={...row('https://asec.ahnlab.com/en/report','Quarterly ransomware research'),storyId:'same'};
 const report=buildWeeklyReport({publications:[english]},{now,range:weeklyWindow(new Date(now))});
 const ko={link:'https://asec.ahnlab.com/ko/report',title:'2026년 3분기 랜섬웨어 동향보고서',source:'Research'};
 const stale={...report.news[0],title:ko.title,sources:[ko,...report.news[0].sources]};
 const before={...report,news:[stale],candidates:{news:[stale],aiNews:[]},selection:{mode:'manual',newsIds:['same'],aiNewsIds:[]}};
 const cleaned=filterWeeklyReportLanguages(before);
 assert.equal(cleaned.news[0].title,english.title);assert.deepEqual(cleaned.selection,before.selection);
 assert.equal(cleaned.news[0].sources.length,1);assert.equal(cleaned.sources[0].link,english.link);
 assert.deepEqual(Object.keys(cleaned).sort(),Object.keys(before).sort());
 assert.equal(filterWeeklyReportLanguages(cleaned),cleaned);
 assert.equal(filterWeeklyReportLanguages(report),report);
});
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

const dateNow=Date.parse('2026-10-22T12:00:00Z');
const researchBody='We investigated this ransomware campaign and identified malicious activity affecting FortiGate appliances. Our research includes network observations. '+ 'The investigation describes operational disruption and credential theft. '.repeat(25);
test('editorial scores use bounded components, prefer relevant research and downgrade complementary coverage',()=>{
 const profile={assets:[{vendor:'Fortinet',product:'FortiGate'}],sectors:['Energy']};
 const article={...row('https://www.volexity.com/blog/report','Investigation'),sectors:['Energy'],iocs:{ips:['45.148.10.95']}};
 const priority=weeklyNewsPriority(article,profile,{body:researchBody,now:dateNow});
 assert.equal(priority.sourceKind,'research');assert.equal(priority.sourceRole,'primary');assert.equal(priority.bodyStatus,'read');assert.equal(priority.contextMatched,true);
 assert.equal(priority.score,Object.values(priority.scoreBreakdown).reduce((sum,value)=>sum+value,0));
 for(const [key,cap]of Object.entries(WEEKLY_EDITORIAL_WEIGHTS))assert.ok(priority.scoreBreakdown[key]<=cap);
 assert.ok(priority.score>=0&&priority.score<=100);
 const generic=weeklyNewsPriority(row('https://www.cisa.gov/news','Security news',999999),profile,{now:dateNow});assert.ok(priority.score>generic.score);
 const complementary=weeklyNewsPriority({...article,link:'https://cyberpress.org/story'},profile,{body:researchBody,now:dateNow});
 assert.equal(complementary.sourceKind,'complementary');assert.equal(complementary.sourceRole,'coverage');assert.ok(priority.score>complementary.score);
 assert.equal(weeklyNewsPriority({...article,link:'https://volexity.com.evil.example/blog'},profile).sourceKind,'other');
});
test('diversity softens publisher concentration but neither fills quotas nor loses available stories',()=>{
 const rows=[...Array.from({length:4},(_,i)=>({id:'a'+i,score:80,publisherGroup:'a.example',editorialTopic:'General'})),{id:'b',score:79,publisherGroup:'b.example',editorialTopic:'General'}];
 const result=diverseWeeklySuggestions(rows,5);assert.equal(result[2].id,'b');assert.equal(result.length,5);
 assert.equal(diverseWeeklySuggestions([rows[0]],25).length,1);
 assert.equal(diverseWeeklySuggestions([{...rows[0],editorialEligible:false}]).length,0);
});
test('cached article reading re-ranks one event toward its original research and leaves catalog totals intact',()=>{
 const primary={...row('https://www.volexity.com/blog/original','Original investigation'),storyId:'same',iocs:{ips:['45.148.10.95']}};
 const copy={...row('https://cyberpress.org/copy','Republished investigation',100),storyId:'same'};
 const routine={...row('https://www.cisa.gov/news-events/ics-advisories/notice','Routine advisory'),cves:['CVE-2026-10000']};
 const bodies=new Map([[primary.link,researchBody],[copy.link,'The publisher reports on a security story. '.repeat(30)]]);let reads=0;
 const report=buildWeeklyReport({publications:[copy,primary,routine],bodyFor:link=>{reads++;return bodies.get(link)||'';},vulnerabilities:[{id:'CVE-2026-10000',published:'2026-10-21T10:00:00Z'}]},{now:dateNow,range:weeklyWindow(new Date(dateNow)),profile:{assets:[{product:'FortiGate'}]}});
 assert.equal(report.news[0].title,primary.title);assert.equal(report.news[0].sourceRole,'primary');assert.equal(report.news[0].sources[0].link,primary.link);
 assert.equal(report.candidates.news.length,1);assert.equal(report.vulnerabilities.total,1);assert.ok(reads<=3);assert.equal(report.curation.externalRequests,0);
});
test('body review is bounded and excludes sources whose cached body fails the language preference',()=>{
 const publications=Array.from({length:100},(_,i)=>({...row('https://research.example/'+i),storyId:'story'+i}));let reads=0;const reviewed=new Set();
 const report=buildWeeklyReport({publications,bodyFor:link=>{reads++;reviewed.add(link);return '最新网络安全漏洞分析与攻击技术研究报告'.repeat(100);}},{now:dateNow,range:weeklyWindow(new Date(dateNow))});
 assert.ok(reads<=80);assert.ok(report.curation.reviewedEvents<=80);assert.ok(report.candidates.news.every(item=>item.sources.every(source=>!reviewed.has(source.link))));
});


test('predicted or explicitly unobserved exploitation is not labeled as reported exploitation',()=>{
 for(const description of ['No evidence of exploitation in the wild has been found.','The issue is not actively exploited.','The issue could be actively exploited.','Não há evidência de exploração ativa.','Sem evidência de exploração ativa.']){
   const result=weeklyNewsPriority({...row('https://example.com/story'),description},null,{now:dateNow});
   assert.ok(!result.selectionReasons.includes('Exploração relatada na fonte'),description);
 }
 const reported=weeklyNewsPriority({...row('https://example.com/story'),description:'The vendor reports the flaw is actively exploited.'},null,{now:dateNow});
 assert.ok(reported.selectionReasons.includes('Exploração relatada na fonte'));
});
