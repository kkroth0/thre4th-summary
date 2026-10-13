import test from 'node:test';
import assert from 'node:assert/strict';
import { extractIOCs } from '../ctiIntel.js';
import { buildMalwareIndex, matchMalware } from '../malwareMatch.js';
import { completeNewsFeed, reviewNewsEvidence } from '../newsQuality.js';
import { buildWeeklyReport,weeklyWindow } from '../weeklyReports.js';
import { completeReportEvidence } from '../reportEvidence.js';
import { readFileSync } from 'node:fs';

test('software versions and HTTP/USB terms do not become threat infrastructure or malware',()=>{
  const text='ASUS AiCloud 2.0.0.39 のバージョン is vulnerable. Returns HTTP 404 Not Found. USB audio failed. ftp uploads files. IOC: 154.81.156.10';
  assert.deepEqual(extractIOCs(text).ips,['154.81.156.10']);
  const families=[{id:'404',name:'404 Keylogger',aliases:['404']},{id:'usb',name:'USBStealer',aliases:['USB']},{id:'ftp',name:'ftp',aliases:[]}];
  const index=buildMalwareIndex(families);
  assert.deepEqual(matchMalware(text,index),[]);
  assert.equal(matchMalware('404 Keylogger and USBStealer infected the host',index).length,2);
  const reviewed=reviewNewsEvidence({title:'ASUS AiCloud',description:text,iocs:{ips:['2.0.0.39','154.81.156.10']},malware:[{id:'404',name:'404 Keylogger',matched:'404',via:'distinctive'}]});
  assert.deepEqual(reviewed.iocs.ips,['154.81.156.10']);assert.deepEqual(reviewed.malware,[]);
});
test('a true IP remains when also mentioned independently of a software version',()=>{
  assert.deepEqual(reviewNewsEvidence({title:'Version 2.0.0.39. IOC 2.0.0.39',iocs:{ips:['2.0.0.39']}}).iocs.ips,['2.0.0.39']);
});
test('archived CVE publications remain searchable and broad-source tutorials stay out of the security feed',()=>{
  const archived={link:'https://msrc.microsoft.com/cve',title:'CVE-2026-83943 Azure API Center',pubDate:'2026-10-08',cves:['CVE-2026-83943']};
  const irrelevant=reviewNewsEvidence({link:'https://habr.com/tutorial',title:'Kubernetes просто лабы: Deployment и Pod'});
  const rows=completeNewsFeed([],[archived,irrelevant]);assert.equal(rows.length,1);assert.equal(rows[0].title,archived.title);
});
test('weekly suggestions exclude first collection timestamps of historical publications',()=>{
  const now=Date.parse('2026-10-13T12:00:00Z'),range=weeklyWindow(new Date(now));
  const row={link:'https://lab.example/report',title:'Security report from June',pubDate:'2026-10-12T12:00:00Z',dateInferred:true};
  const report=buildWeeklyReport({publications:[row,{...row,link:'https://lab.example/current',dateInferred:false}]},{range,now});
  assert.equal(report.candidates.news.length,1);assert.equal(report.candidates.news[0].sources[0].link,'https://lab.example/current');
});
test('bulletin and JSON preserve all 32 C2Agent hashes even when synthesis supplies 28',()=>{
  const hashes=[...new Set(readFileSync(new URL('./fixtures/c2agent-indicators.txt',import.meta.url),'utf8').match(/\b[a-f0-9]{64}\b/g))];
  const report={iocs:hashes.slice(0,28).map(valor=>({categoria:'Arquivo',tipo:'SHA256',valor}))};
  const job={urls:['https://github.com/report'],documents:[{iocText:hashes.join('\n')}]};
  const complete=completeReportEvidence(report,job);assert.equal(complete.iocs.length,32);assert.deepEqual(new Set(complete.iocs.map(row=>row.valor)),new Set(hashes));
  assert.deepEqual(completeReportEvidence(complete,job),complete);
});
