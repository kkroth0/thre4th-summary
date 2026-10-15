import test from 'node:test';
import assert from 'node:assert/strict';
import { extractIOCs, extractReadableText } from '../ctiIntel.js';
import { buildMalwareIndex, matchMalware } from '../malwareMatch.js';
import { completeNewsFeed, reviewNewsEvidence, recoverJoinedTableIps, removeVersionIndicators } from '../newsQuality.js';
import { buildWeeklyReport,weeklyWindow } from '../weeklyReports.js';
import { completeReportEvidence } from '../reportEvidence.js';
import { readFileSync } from 'node:fs';
import { prepareFeedJobDocuments } from '../feedJobDocuments.js';

test('feed responses discard malformed entity slots without erasing valid associations or missing metadata',()=>{
  const valid={id:'win.vidar',name:'Vidar'};
  const [row,legacy]=completeNewsFeed([],[{link:'https://test.example/security',title:'Security report',actors:[null,{name:'No ID'}],malware:[null,valid],campaigns:[null]}, {link:'https://test.example/legacy',title:'Security report'}]);
  assert.deepEqual(row.actors,[]);assert.deepEqual(row.malware,[valid]);assert.deepEqual(row.campaigns,[]);
  assert.equal(legacy.actors,undefined);
});

test('software versions and HTTP/USB terms do not become threat infrastructure or malware',()=>{
  const text='ASUS AiCloud 2.0.0.39 のバージョン is vulnerable. Returns HTTP 404 Not Found. USB audio failed. ftp uploads files. IOC: 154.81.156.10';
  assert.deepEqual(extractIOCs(text).ips,['154.81.156.10']);
  assert.deepEqual(extractIOCs('One Rails 8.1.3.1 app on Ruby 4.0.6. IP: 64.227.4.134').ips,['64.227.4.134']);
  const families=[{id:'404',name:'404 Keylogger',aliases:['404']},{id:'usb',name:'USBStealer',aliases:['USB']},{id:'ftp',name:'ftp',aliases:[]}];
  const index=buildMalwareIndex(families);
  assert.deepEqual(matchMalware(text,index),[]);
  assert.equal(matchMalware('404 Keylogger and USBStealer infected the host',index).length,2);
  const reviewed=reviewNewsEvidence({title:'ASUS AiCloud',description:text,iocs:{ips:['2.0.0.39','154.81.156.10']},malware:[{id:'404',name:'404 Keylogger',matched:'404',via:'distinctive'}]});
  assert.deepEqual(reviewed.iocs.ips,['154.81.156.10']);assert.deepEqual(reviewed.malware,[]);
});

test('firmware release suffixes are not IPv4 and stale archived matches are removed without removing real IOC occurrences',()=>{
  const text='Lantronix G520 Series cellular gateways running 2.6.0.4R6_stable. IOC: 64.227.4.134';
  assert.deepEqual(extractIOCs(text).ips,['64.227.4.134']);
  assert.deepEqual(removeVersionIndicators({ips:['2.6.0.4','64.227.4.134']},text).ips,['64.227.4.134']);
  assert.deepEqual(removeVersionIndicators({ips:['2.6.0.4']},text+' Separately, C2 address: 2.6.0.4:443').ips,['2.6.0.4']);
});
test('a true IP remains when also mentioned independently of a software version',()=>{
  assert.deepEqual(reviewNewsEvidence({title:'Version 2.0.0.39. IOC 2.0.0.39',iocs:{ips:['2.0.0.39']}}).iocs.ips,['2.0.0.39']);
});

test('Ivanti affected/fixed version lists do not become IP infrastructure, including lists across lines',()=>{
  const text='Ivanti Connect Secure versions 25.1.1.1 and prior, 25.1.2.2 and prior, 25.1.3.0, and 25.1.1.2 are affected.\nC2 IP: 108.165.147.64';
  assert.deepEqual(extractIOCs(text).ips,['108.165.147.64']);
  assert.deepEqual(extractIOCs('Fixed versions:\n25.1.1.1\n25.1.2.2\n25.1.3.1').ips,[]);
  assert.deepEqual(extractIOCs(text+'\nSeparately, IOC: 25.1.2.2:443').ips,['108.165.147.64','25.1.2.2']);
  assert.deepEqual(extractIOCs('Version 25.1.1.1 is affected. Attackers connect to 25.1.2.2.').ips,['25.1.2.2']);
});

test('version tables and Portuguese version comparisons preserve independent network IOCs',()=>{
  for(const text of [
    'Afeta as versões 22.8R2.4 e anteriores, 25.1.2.2 e anteriores, e 25.1.1.1 e anteriores.',
    'Affected versions are:\n• Connect Secure 22.8R2.4 and earlier\n• Connect Secure 25.1.2.2 and earlier',
    'Affected versions\nResolved versions\n25.1.1.1 and prior in the applicable code line\n25.1.1.2\n25.1.2.2 and prior in the applicable code line\n25.1.3.0, 25.1.3.1',
    'Fixed releases are 25.1.1.2, 25.1.3.0 or 25.1.3.1. Upgrade to 25.1.3.1',
  ]) {
    assert.deepEqual(extractIOCs(text).ips,[],text);
    assert.deepEqual(extractIOCs(text+'\nIOC: 108.165.147.64 and 25.1.2.2:443').ips,['108.165.147.64','25.1.2.2']);
  }
});

test('version columns and later software references are not independent IP sightings',()=>{
  const table='| Product | Affected Versions | Fixed Versions |\n|---|---|---|\n| VPN Gateway | 25.1.1.1 and prior 25.1.2.2 and prior | 25.1.1.2 25.1.3.0, 25.1.3.1 |';
  const text=table+'\nThe fixed versions are 25.1.1.2, 25.1.3.0 or 25.1.3.1.\nConfirm the vendor advisory before relying on 25.1.1.2 as a fix.\n25.1.3.0 requires the newer platform.\nCNA record: the version list omits the older-platform 25.1.1.2 exception.\nC2 IP: 108.165.147.64';
  assert.deepEqual(extractIOCs(text).ips,['108.165.147.64']);
  assert.deepEqual(reviewNewsEvidence({title:'VPN security',description:text,iocs:{ips:['25.1.1.2','25.1.3.0','25.1.3.1','108.165.147.64']}}).iocs.ips,['108.165.147.64']);
  for(const network of ['IOC: 25.1.3.0:443','Attackers connect to 25.1.3.0','Attackers contacted 25.1.3.0.','25.1.3.0','| IP address |\n|---|\n| 25.1.3.0 |']) {
    assert.ok(extractIOCs(text+'\n'+network).ips.includes('25.1.3.0'),network);
  }
});

test('an alphanumeric firmware build anchors the rest of its version list',()=>{
  const text='Patched appliances run Secure Gateway 22.8R2.5, 25.1.1.2, 25.1.3.0 and 25.1.3.1.\nProtection shipped in the 25.1.3.0 release.';
  assert.deepEqual(extractIOCs(text).ips,[]);
  assert.deepEqual(extractIOCs(text+'\nC2 IP: 108.165.147.64\nIP IOC: 25.1.3.1:443').ips,['108.165.147.64','25.1.3.1']);
  assert.deepEqual(reviewNewsEvidence({title:'Gateway security update',description:text,iocs:{ips:['25.1.1.2','25.1.3.0','25.1.3.1']}}).iocs.ips,[]);
  assert.deepEqual(extractIOCs('IPv4: 154.81.156.10 Firmware 22.8R2.5\nIP address: 108.165.147.64 Version 3').ips,['154.81.156.10','108.165.147.64']);
});

test('inline table markup and old concatenated labels do not hide IPs or corrupt endpoints',()=>{
  const text=extractReadableText('<article><table><tr><td><strong>204.8.96.109</strong>Tor exit</td><td><code>/fz/x.js</code>Browser-based payload</td></tr></table></article>');
  assert.match(text,/204\.8\.96\.109 Tor exit/);assert.match(text,/\/fz\/x\.js Browser-based/);
  assert.deepEqual(extractIOCs(text).ips,['204.8.96.109']);
  assert.deepEqual(extractIOCs('IOC: 9.9.9.10. Not a five-part address: 5.4.3.2.1').ips,['9.9.9.10']);
  const row={iocs:{ips:['147.90.235.22'],hashes:['a'.repeat(64)]}};
  const recovered=recoverJoinedTableIps(row,'147.90.235.22\nBundles204.8.96.109Tor Exit\nVersion2.0.0.39Beta\nChrome131.0.0.0\nv8.1.3.1');
  assert.deepEqual(recovered.iocs.ips,['147.90.235.22','204.8.96.109']);assert.deepEqual(recovered.iocs.hashes,row.iocs.hashes);
  assert.equal(recoverJoinedTableIps(recovered,'204.8.96.109Tor Exit'),recovered);
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

test('bulletin generation reuses an archived repository body when the live RSS entry has rotated out',()=>{
  const link='https://github.com/research/report',hash='a'.repeat(64);
  const documents=prepareFeedJobDocuments([link],{items:[{link,title:'Report'},{link,title:'Report',text:'Malware evidence '.repeat(150),iocs:{hashes:[hash]}}]});
  assert.equal(documents.length,1);assert.ok(documents[0].text.length>=1500);assert.equal(documents[0].iocText,hash);
});
