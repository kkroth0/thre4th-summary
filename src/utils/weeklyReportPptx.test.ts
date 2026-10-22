import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import JSZip from 'jszip';
import { buildWeeklySlides } from './weeklyReportPptx';
import type { WeeklyReportData, WeeklyNews } from '@/types/weekly-report';

const news: WeeklyNews = {id:'selected',title:'Selected publication',summary:'Selected summary',published:'2026-10-13T15:25:00Z',score:80,severity:'High',sources:[{title:'Selected publication',source:'Research',link:'https://example.com/selected',published:'2026-10-13T15:25:00Z'}],categories:[],actors:[],malware:[],cves:[],ttps:[]};
const report: WeeklyReportData = {range:{id:'2026-10-11',from:'2026-10-11T03:00:00Z',to:'2026-10-18T03:00:00Z',timezone:'America/Fortaleza',exclusiveEnd:true},profile:null,generatedAt:'2026-10-13T16:00:00Z',updatedAt:'2026-10-13T16:00:00Z',revision:2,news:[news],aiNews:[],selection:{mode:'manual',newsIds:['selected'],aiNewsIds:[]},candidates:{news:[news,{...news,id:'unselected',title:'Do not export this candidate'}],aiNews:[]},vulnerabilities:{total:0,critical:0,kevCount:0,kev:[],priority:[],monitored:[],ai:{total:0,critical:0,items:[],vendors:[]}},ransomware:{total:0,latam:0,brazil:0,victims:[],byCountry:[],byGroup:[],bySector:[],claimsAreUnconfirmed:true},reports:[],recommendations:[],actors:[],malware:[],ttps:[],coverage:{news:{publications:2,lastCollectedAt:null},ransomware:{status:'ready'},vulnerabilities:{sources:{nvd:{status:'ready'}}}},sources:news.sources};

test('weekly PowerPoint exports the editorial selection with publisher time and complete source notes',()=>{
  const slides=buildWeeklySlides(report);const content=JSON.stringify(slides);
  assert.match(content,/Selected publication/);assert.match(content,/13\/10\/2026 · 12:25/);
  assert.match(content,/https:\/\/example.com\/selected/);assert.doesNotMatch(content,/Do not export this candidate/);
});
test('weekly PowerPoint paginates the three native CVE blocks without losing records',()=>{
  const rows=Array.from({length:23},(_,i)=>({id:'CVE-2026-'+(10000+i),published:'2026-10-13',dateAdded:'',vendor:'Vendor',product:'Product',description:'Description',cvss:8,kev:false,severity:'HIGH',epss:0.1,action:'',references:[]}));
  const slides=buildWeeklySlides({...report,vulnerabilities:{...report.vulnerabilities,priority:rows}});
  for(const row of rows)assert.match(JSON.stringify(slides),new RegExp(row.id));
  assert.equal(slides.filter(slide=>Object.values(slide.values).some(value=>value.startsWith('Prioridades em vulnerabilidades'))).length,8);
});
test('EY template preserves native layouts, country geometry and charts without customer or incident content',async()=>{
  const zip=await JSZip.loadAsync(await fs.readFile('public/templates/weekly-report-ey-v3.pptx'));
  const slides=Object.keys(zip.files).filter(name=>/^ppt\/slides\/slide\d+\.xml$/.test(name));assert.equal(slides.length,19);
  const xml=(await Promise.all(Object.keys(zip.files).filter(name=>name.endsWith('.xml')).map(name=>zip.file(name)!.async('string')))).join('\n');
  assert.doesNotMatch(xml,/Votorantim|Ultrapar|BRBJUS|BPMoney|Hospital Israelita|Flax Typhoon|The Gentlemen/i);
  assert.match(await zip.file('ppt/presentation.xml')!.async('string'),/cx="7562088" cy="10689336"/);
  assert.match(await zip.file('ppt/slides/slide1.xml')!.async('string'),/logo EY/i);
  assert.ok((await zip.file('ppt/slides/slide16.xml')!.async('string')).match(/name="País /g)!.length>100);
  assert.equal(Object.keys(zip.files).filter(name=>/^ppt\/charts\/chart\d+\.xml$/.test(name)).length,2);
  assert.ok(!Object.keys(zip.files).some(name=>name.startsWith('ppt/embeddings/')));
  for(const number of [13,14,17,20]){const slide=await zip.file(`ppt/slides/slide${number}.xml`)!.async('string');assert.ok((slide.match(/<p:pic>/g)||[]).length<=1,'No example vendor logo may be assigned to a new product');}
  for(const name of ['ppt/charts/chart1.xml','ppt/charts/chart2.xml']){const chart=await zip.file(name)!.async('string');assert.ok((chart.match(/<c:dLbl>[\s\S]*?<\/c:dLbl>/g)||[]).every(label=>!/<a:t>\d+<\/a:t>/.test(label)),'No example chart value may survive in a custom data label');}
});

test('source paragraphs keep their own hyperlinks and unused CVE cards are removed',()=>{
 const sources=[...news.sources,{...news.sources[0],source:'Second lab',link:'https://example.net/reference'}];
 const slides=buildWeeklySlides({...report,news:[{...news,sources}],vulnerabilities:{...report.vulnerabilities,priority:[{id:'CVE-2026-10000',published:'2026-10-13',dateAdded:'',vendor:'Vendor',product:'Product',description:'Full description',cvss:9.8,kev:false,severity:'CRITICAL',epss:null,action:'',references:[]}]}});
 assert.deepEqual(slides.find(s=>s.source===6)?.links?.S6_5159,sources.map(source=>source.link));
 const cves=slides.find(s=>s.source===13)!;assert.ok(cves.removeIds?.includes(10));assert.ok(cves.removeIds?.includes(11));assert.ok(!cves.removeIds?.includes(9));
 assert.equal(cves.links?.S13_5517,'https://nvd.nist.gov/vuln/detail/CVE-2026-10000');
});
test('page references follow selected content and no previous-week comparison is invented',()=>{
 const slides=buildWeeklySlides(report),toc=slides.find(s=>s.source===4)!;
 const vuln=slides.findIndex(s=>s.source===12)+1;
 assert.equal(toc.values.S4_21,String(vuln));
 const ai=slides.find(s=>s.source===20)!;assert.equal(ai.values.S20_5899,'—');
 assert.equal(ai.values.S20_5897,'comparação anterior indisponível');
 assert.ok(slides.every(s=>!s.notes.includes('Do not export this candidate')));
});
