import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import JSZip from 'jszip';
import { analyzeBulkRow,analyzeBulkRows,canonicalBulkRows } from './bulkAnalysis';
import { buildBulkExcelWorkbook } from './iocExcelWorkbook';
import { addBulkExcelCharts } from './bulkExcelCharts';
import type { BulkRow } from './bulkEnrichment';
import type { BulkEvidence } from '../services/bulkContext';
const Excel=createRequire(`${process.cwd()}/package.json`)('exceljs') as typeof import('exceljs');
const base=(query='185.220.101.5'):BulkRow=>({query,state:'complete',result:{query,overallScore:90,threatLevel:'malicious',totalVendors:2,detections:1,vendorData:[{name:'VirusTotal',data:{Malicious:12,'Detection Rate':'12/90'}},{name:'AlienVault OTX',data:{'Pulse Details':[{adversary:'Actor A',malwareFamilies:['Family A'],attackIds:['T1059.001'],tags:[]}]}}]},context:{errors:[],publications:[],evidence:[]}});

test('an unsupported query is an explicit coverage exception, never a zero-match source finding',()=>{
 const row=base();row.result!.vendorData.push({name:'ThreatFox',unsupported:true,data:{Status:'Consulta não aceita pela fonte'},rawPayload:{query_status:'illegal_search_term'}});
 const a=analyzeBulkRow(row),summary=analyzeBulkRows([row]);assert.equal(a.record.tfMatches,null);assert.equal(a.record['status:ThreatFox'],'Consulta não aceita pela fonte');assert.match(String(a.record.notes),/ThreatFox.*não aceita/);assert.equal(summary.unsupported,1);assert.equal(summary.partial,0);assert.equal(summary.coverage.find(x=>x.name==='ThreatFox')!.count,0);
});
const evidence=(name:string,relation:string,technique:string):BulkEvidence=>({provider:'Axur',title:'Source report',link:'https://lab.example/report',published:'2026-10-27',collectedAt:'2026-10-27',confidence:90,reputation:null,entities:[{id:name,kind:'actor',name,relation}],...{payload:{relatedTTPs:[technique]}}});

test('Axur response status, report links, contextual actors and structured MITRE codes reach the analytical export',()=>{
 const row=base();row.result!.vendorData.push({name:'Axur',data:{'Registros Axur':2,Status:'Contexto encontrado'}});
 row.context!.evidence=[{...evidence('APT28','mentioned-with','T1566'),...{payload:{relatedTTPs:[{code:'TA0001',name:'Initial access'},{code:'T1059',name:'Command execution'}],attacks:[{code:'T1566.001',name:'Spearphishing Attachment'}]}}}];
 const result=analyzeBulkRow(row);assert.equal(result.record['status:Axur'],'Respondida');assert.equal(result.record.axActors,'APT28');assert.match(String(result.record.axLinks),/https:\/\/lab.example\/report/);assert.ok(result.techniques.includes('T1059'));assert.ok(result.techniques.includes('T1566.001'));assert.match(String(result.record.tactics),/TA0001/);assert.ok(!result.actors.includes('APT28'));assert.ok(result.mentions.includes('APT28'));
});

test('an existing malicious verdict remains prioritized while other APIs are pending',()=>{
 const row=base();row.state='running';row.result!.vendorData=[{name:'AbuseIPDB',data:{'Abuse Confidence Score':100}},{name:'Axur',data:{},isLoading:true}];assert.equal(analyzeBulkRow(row).priority,'Investigar');assert.equal(analyzeBulkRows([row]).partial,1);
});
test('completed Axur inventory coverage is labelled as an imported base rather than a new API response',()=>{
 const row=base();row.result!.vendorData.push({name:'Axur',data:{Status:'Sem correspondência na base Axur importada',Origem:'Base Axur importada · varredura concluída','Última varredura':'2026-10-22T10:56:53.959Z'},cacheState:'inventory-miss',collectedAt:'2026-10-22T10:56:53.959Z'});
 assert.equal(analyzeBulkRow(row).record['status:Axur'],'Base importada');assert.equal(analyzeBulkRows([row]).partial,0);
});
test('context is retained without manufacturing an attribution or cross-report actor-technique pairs',()=>{
 const row=base();row.context!.evidence=[evidence('Context Actor','mentioned-with','T1566'),evidence('Actor B','attributed-by-source','T1486')];
 const a=analyzeBulkRow(row);assert.deepEqual(a.actors,['Actor B','Actor A']);assert.ok(a.mentions.includes('Context Actor'));
 assert.deepEqual(a.pairs,[{actor:'Actor B',technique:'T1486'},{actor:'Actor A',technique:'T1059.001'}]);
 assert.match(String(a.record.tactics),/TA0002/);assert.match(String(a.record.tactics),/TA0040/);
 const b=analyzeBulkRows([row,row]);assert.equal(b.total,1);assert.equal(b.actors[0].count,1);
});
test('only exact known infrastructure and test indicators leave threat rankings; original detections survive',()=>{
 for(const query of ['8.8.8.8','example.org','a.example.com','44d88612fea8a8f36de82e1278abb02f']){const a=analyzeBulkRow(base(query));assert.equal(a.excluded,true);assert.deepEqual(a.actors,[]);assert.deepEqual(a.families,[]);assert.equal(a.record.vtMalicious,12);assert.equal(a.record.verdict,'Malicioso');}
 const row=base('8.8.8.9');row.result!.vendorData.push({name:'AbuseIPDB',data:{ISP:'Google',ASN:15169}});assert.equal(analyzeBulkRow(row).excluded,false,'ASN or organization never whitelists an arbitrary IP');
 assert.equal(analyzeBulkRow(base('notexample.org')).excluded,false);
});
test('curated FP scope is exact and does not erase independent detections',()=>{
 const row=base();row.result!.vendorData.push({name:'ThreatFox',data:{Status:'Malicious','All Malware':['Family B']}},{name:'abuse.ch Hunting',data:{'FP Matches':[{entry_value:row.query,matchRelation:'exact'}]}});
 const a=analyzeBulkRow(row);assert.equal(a.fp,true);assert.equal(a.priority,'Investigar');assert.equal(a.record.vtMalicious,12);assert.ok(!a.families.includes('Family B'));
 row.result!.vendorData.at(-1)!.data['FP Matches']=[{entry_value:row.query+':443',matchRelation:'host'}];assert.equal(analyzeBulkRow(row).fp,false);
});
test('missing responses stay distinct from zero findings, including partial DNS results and percent strings',()=>{
 const row=base();row.result!.vendorData=[{name:'VirusTotal',data:{Malicious:0}},{name:'ThreatFox',data:{},error:'HTTP 502'},{name:'AbuseIPDB',data:{'Abuse Confidence Score':'87%','Last Report':'2026-10-26','Is Whitelisted':'No'}},{name:'DNS / Team Cymru',data:{'Reverse Hostname':'host.example'},error:'ASN timeout'}];
 const a=analyzeBulkRow(row);assert.equal(a.record.vtMalicious,0);assert.equal(a.record.tfMatches,null);assert.equal(a.record['status:ThreatFox'],'Indisponível');assert.equal(a.record['status:MalwareBazaar'],'Não consultada');assert.equal(a.record.abScore,87);assert.equal(a.record.rdns,'host.example');assert.equal(a.record.abLast,'2026-10-26');
 const summary=analyzeBulkRows([row]);assert.equal(summary.coverage.find(x=>x.name==='ThreatFox')!.count,0);
});
test('canonical deduplication preserves URL path case and the latest source status',()=>{
 const newer={...base('EXAMPLE.ORG'),state:'partial' as const};const rows=canonicalBulkRows([base('example.org'),newer,base('https://example.org/A'),base('https://example.org/a')]);assert.equal(rows.length,3);assert.equal(rows[0],newer);
});
test('aggregated OTX adversary text and generic AV/file labels remain in source columns without inflating rankings',()=>{
 const row=base();row.result!.vendorData[1].data['Pulse Details']=[{adversary:'APT28',malwareFamilies:['HEADLACE','Generic Trojan','ALF:Backdoor:MSIL/Noancooe.KA','___FilesToHash_17jun','SUSP_XORed_Mozilla_Oct19'],attackIds:['T1059.001']},{adversary:'Core Werewolf, Tortoiseshell, PackClient, Abusing Browser Extensions',malwareFamilies:[],attackIds:['T1486']}];
 const a=analyzeBulkRow(row);assert.deepEqual(a.actors,['APT28']);assert.deepEqual(a.families,['HEADLACE']);assert.deepEqual(a.pairs,[{actor:'APT28',technique:'T1059.001'}]);
 assert.match(String(a.record.otxActors),/Core Werewolf/);assert.match(String(a.record.otxFamilies),/Generic Trojan/);assert.match(String(a.record.notes),/fora do ranking/);
});
test('analytical sheets preserve literal values, headers, source links and editable chart bindings',async()=>{
 const rows=[base(),base('185.220.101.6')];rows[0].context!.evidence=[evidence('Context Actor','mentioned-with','T1566')];
 const wb=buildBulkExcelWorkbook(rows,Excel),sheet=wb.getWorksheet('Indicadores')!;
 assert.equal(sheet.getRow(5).getCell('indicator').value,rows[0].query);assert.equal(sheet.views[0].state,'frozen');assert.equal((sheet.views[0] as any).xSplit,4);assert.equal((sheet.autoFilter as any).from.row,4);assert.equal(wb.getWorksheet('_dados')!.state,'hidden');
 assert.equal(sheet.getRow(5).getCell('vtMalicious').value,12);assert.equal(sheet.getRow(5).getCell('techniques').value,'T1566; T1059.001');assert.equal(sheet.getRow(5).getCell('axLinks').hyperlink,'https://lab.example/report');
 const bytes=await addBulkExcelCharts(new Uint8Array(await wb.xlsx.writeBuffer()),rows),zip=await JSZip.loadAsync(bytes);
 const paths=Object.keys(zip.files).filter(x=>/\/charts\/chart\d+\.xml$/.test(x));assert.equal(paths.length,8);
 const chart=await zip.file('xl/drawings/charts/chart1.xml')!.async('string');assert.match(chart,/'_dados'!\$A\$3:\$A\$3/);assert.match(chart,/<c:v>Actor A<\/c:v>/);assert.match(chart,/<c:v>2<\/c:v>/);assert.match(chart,/<c:majorUnit val="1"\/>/);
 const bar=chart.match(/<c:barChart>[\s\S]*?<\/c:barChart>/)![0];assert.ok(bar.indexOf('<c:gapWidth')<bar.indexOf('<c:axId'),'OOXML bar spacing must precede axis identifiers');
 const scale=chart.match(/<c:valAx>[\s\S]*?<c:scaling>([\s\S]*?)<\/c:scaling>/)![1];assert.ok(scale.indexOf('<c:max')<scale.indexOf('<c:min'),'OOXML scaling requires max before min');
 const restored=new Excel.Workbook();await restored.xlsx.load(bytes);assert.equal(restored.getWorksheet('Indicadores')!.getCell('C5').value,rows[0].query);assert.equal(restored.getWorksheet('Evidências')!.getRow(2).getCell(5).hyperlink,'https://lab.example/report');
});
