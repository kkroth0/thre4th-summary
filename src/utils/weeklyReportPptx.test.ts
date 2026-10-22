import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import JSZip from 'jszip';
import { buildWeeklySlides } from './weeklyReportPptx';
import { exportWeeklyPptx } from './weeklyReportPptx';
import { weeklyProductLogo } from './weeklyPptxLogos';
import type { WeeklyReportData, WeeklyNews } from '@/types/weekly-report';

const news: WeeklyNews = {id:'selected',title:'Selected publication',summary:'Selected summary',published:'2026-10-13T15:25:00Z',score:80,severity:'High',sources:[{title:'Selected publication',source:'Research',link:'https://example.com/selected',published:'2026-10-13T15:25:00Z'}],categories:[],actors:[],malware:[],cves:[],ttps:[]};
const report: WeeklyReportData = {range:{id:'2026-10-11',from:'2026-10-11T03:00:00Z',to:'2026-10-18T03:00:00Z',timezone:'America/Fortaleza',exclusiveEnd:true},profile:null,generatedAt:'2026-10-13T16:00:00Z',updatedAt:'2026-10-13T16:00:00Z',revision:2,news:[news],aiNews:[],selection:{mode:'manual',newsIds:['selected'],aiNewsIds:[]},candidates:{news:[news,{...news,id:'unselected',title:'Do not export this candidate'}],aiNews:[]},vulnerabilities:{total:0,critical:0,kevCount:0,kev:[],priority:[],monitored:[],ai:{total:0,critical:0,items:[],vendors:[]}},ransomware:{total:0,latam:0,brazil:0,victims:[],byCountry:[],byGroup:[],bySector:[],claimsAreUnconfirmed:true},reports:[],recommendations:[],actors:[],malware:[],ttps:[],coverage:{news:{publications:2,lastCollectedAt:null},ransomware:{status:'ready'},vulnerabilities:{sources:{nvd:{status:'ready'}}}},sources:news.sources};

test('weekly PowerPoint exports the editorial selection with publisher time and complete source notes',()=>{
  const slides=buildWeeklySlides(report);const content=JSON.stringify(slides);
  assert.match(content,/Selected publication/);assert.match(content,/13\/10\/2026 · 12:25/);
  assert.match(content,/https:\/\/example.com\/selected/);assert.doesNotMatch(content,/Do not export this candidate/);
});

test('weekly export requires completed reading and editorial writing before fetching its template',async()=>{
  await assert.rejects(exportWeeklyPptx(report),/Redija o boletim/);
});
test('product logos follow actual products and never substitute an unrelated vendor mark',()=>{
 const base={id:'CVE-2026-10000',description:'',vendor:'',product:'',cvss:null,severity:'',published:'',dateAdded:'',kev:false,epss:null,action:'',references:[]};
 for(const family of ['Java','PHP','Node.js'])assert.ok(weeklyProductLogo({...base,editorialFamily:family}));
 assert.equal(weeklyProductLogo({...base,vendor:'Siemens',product:'Software Center'}),'siemens');assert.equal(weeklyProductLogo({...base,vendor:'Plex',product:'Media Server'}),'plex');assert.equal(weeklyProductLogo({...base,product:'SiteGuard Server Edition'}),'siteguard');assert.equal(weeklyProductLogo({...base,vendor:'Unknown vendor'}),null);
});
test('weekly slides use written stories and section analysis instead of feed snippets and generic cards',()=>{
  const article={id:news.id,status:'ready' as const,title:'Manchete redigida com a leitura da notícia',lead:'Uma abertura escrita após a leitura das fontes.',context:'Uma análise específica das permissões do fornecedor.',body:['Primeiro parágrafo que desenvolve o acontecimento.','Segundo parágrafo que explica a consequência.'],attention:[{title:'Contas do fornecedor',text:'As credenciais concentravam permissões em diferentes ambientes.'},{title:'Sistemas administrados',text:'O alcance depende dos sistemas vinculados à conta.'},{title:'Histórico de acessos',text:'Os registros ajudam a delimitar a atividade observada.'}],sourceUrls:[news.sources[0].link],evidence:[{url:news.sources[0].link,status:'read',hash:'body-hash'}]};
  const editorial={status:'ready' as const,available:true,articles:[article],sections:{executive:{priority:'Leitura editorial da semana.',overview:'Panorama escrito a partir das notícias lidas.'},ransomware:{overview:'Interpretação do panorama de publicações.',trend:'Leitura do histórico com períodos comparáveis.',groups:'Leitura específica dos grupos.'},ai:{interpretation:'Interpretação das publicações em ferramentas de IA.',leadership:'Consequência específica para a liderança.'},cves:[]}};
  const slides=buildWeeklySlides({...report,editorial});const story=slides.find(s=>s.source===6)!;
  assert.equal(story.values.S6_5130,article.title);assert.equal(story.values.S6_5131,article.lead);assert.equal(story.values.S6_5140,article.body[0]);assert.equal(story.values.S6_5147,article.attention[0].title);
  assert.equal(slides.find(s=>s.source===3)?.values.S3_5049,editorial.sections.executive.overview);assert.equal(slides.find(s=>s.source===16)?.values.S16_167,editorial.sections.ransomware.overview);
  assert.match(story.notes,/body-hash/);assert.doesNotMatch(JSON.stringify(story.values),/Selected summary|Identificar relações|Para a organização, o impacto depende/);
});
test('weekly PowerPoint caps legacy priorities at three native CVE cards on one page',()=>{
  const rows=Array.from({length:23},(_,i)=>({id:'CVE-2026-'+(10000+i),published:'2026-10-13',dateAdded:'',vendor:'Vendor',product:'Product',description:'Description',cvss:8,kev:false,severity:'HIGH',epss:0.1,action:'',references:[]}));
  const slides=buildWeeklySlides({...report,vulnerabilities:{...report.vulnerabilities,priority:rows}});
  for(const row of rows.slice(0,3))assert.match(JSON.stringify(slides),new RegExp(row.id));
  for(const row of rows.slice(3))assert.doesNotMatch(JSON.stringify(slides),new RegExp(row.id));
  assert.equal(slides.filter(slide=>slide.source===13).length,1);
});

test('weekly PowerPoint uses curated runtime highlights and only confirmed KEV entries',()=>{
  const make=(id:number,editorialFamily:string,kev=false)=>({id:`CVE-2026-${id}`,editorialFamily,published:'2026-10-13',dateAdded:'2026-10-13',vendor:'',product:'',description:'Description',cvss:9.1,kev,severity:'CRITICAL',epss:null,action:'',references:[]});
  const highlights=[make(10001,'Java'),make(10002,'PHP'),make(10003,'Node.js')],exploited=[make(20001,'Siemens',true),make(20002,'Plex',true),make(20003,'SiteGuard',true),make(20004,'Not KEV')];
  const slides=buildWeeklySlides({...report,vulnerabilities:{...report.vulnerabilities,total:3716,kevCount:6,priority:[make(99999,'Unselected')],editorial:{focus:['Java','PHP','Node.js'],highlights,exploited,missingFocus:[]}}});
  assert.equal(slides.filter(slide=>slide.source===13).length,1);assert.equal(slides.filter(slide=>slide.source===14).length,1);
  for(const row of [...highlights,...exploited.slice(0,3)])assert.match(JSON.stringify(slides),new RegExp(row.id));
  assert.doesNotMatch(JSON.stringify(slides),/CVE-2026-99999|CVE-2026-20004/);
  assert.equal(slides.find(s=>s.source===13)?.values.S13_9,'Java');
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
 assert.equal(slides.find(s=>s.source===12)?.values.S12_11,'Prioridades em vulnerabilidades');
 assert.equal(slides.find(s=>s.source===15)?.values.S15_13,'Panorama das organizações citadas');
});

test('news columns do not split firmware and software versions at decimal points',()=>{
 const slides=buildWeeklySlides({...report,news:[{...news,summary:'O fabricante publicou uma correção. A atualização exige a versão 4.0.9.8 do produto. A equipe deve avaliar a exposição.'}]});
 const values=slides.find(s=>s.source===6)!.values;
 assert.ok([values.S6_5140,values.S6_5141].some(value=>value.includes('4.0.9.8')));
});
test('ransomware table highlights only the recipient sectors and hides markers on empty rows',()=>{
 const victims=['Technology','Manufacturing'].map((sector,i)=>({id:String(i),name:'Organization '+i,group:'G',country:'BR',sector,published:'2026-10-13',discovered:'2026-10-13',description:'',permalink:'https://example.com/'+i,claimStatus:'unconfirmed' as const}));
 const slides=buildWeeklySlides({...report,ransomware:{...report.ransomware,victims,focusSectors:['Manufacturing'],focusCount:1}});
 const table=slides.find(s=>s.source===17)!;
 assert.deepEqual(table.fills?.slice(0,2),[{id:6038,color:'A3A3AE'},{id:6043,color:'B08A00'}]);
 assert.ok(table.removeIds?.includes(6047));
});
