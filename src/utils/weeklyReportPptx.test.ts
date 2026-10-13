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
test('weekly PowerPoint paginates native CVE tables without losing rows',()=>{
  const rows=Array.from({length:23},(_,i)=>({id:'CVE-2026-'+(10000+i),published:'2026-10-13',dateAdded:'',vendor:'Vendor',product:'Product',description:'Description',cvss:8,kev:false,severity:'HIGH',epss:0.1,action:'',references:[]}));
  const slides=buildWeeklySlides({...report,vulnerabilities:{...report.vulnerabilities,priority:rows}});
  for(const row of rows)assert.match(JSON.stringify(slides),new RegExp(row.id));
  assert.equal(slides.filter(slide=>Object.values(slide.values).some(value=>value.startsWith('Prioridades em vulnerabilidades'))).length,3);
});
test('public template contains only reusable layouts, editable tables, and no source incident content',async()=>{
  const zip=await JSZip.loadAsync(await fs.readFile('public/templates/weekly-report-template-v2.pptx'));
  const slides=Object.keys(zip.files).filter(name=>/^ppt\/slides\/slide\d+\.xml$/.test(name));assert.equal(slides.length,8);
  const xml=(await Promise.all(Object.keys(zip.files).filter(name=>name.endsWith('.xml')).map(name=>zip.file(name)!.async('string')))).join('\n');
  assert.doesNotMatch(xml,/Votorantim|BRBJUS|BPMoney/i);assert.ok(!Object.keys(zip.files).some(name=>name.startsWith('ppt/embeddings/')));
  for(const number of [17,26,37,40])assert.match(await zip.file(`ppt/slides/slide${number}.xml`)!.async('string'),/<a:tbl>/);
});
