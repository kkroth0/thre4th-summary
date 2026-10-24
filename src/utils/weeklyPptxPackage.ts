import JSZip from 'jszip';
import manifest from '@/config/weeklyReportTemplate.json';
import type {WeeklyReportData} from '@/types/weekly-report';
import {buildWeeklySlides,countryNames} from './weeklyTemplateSlides';
import {fillWeeklyCharts} from './weeklyPptxCharts';
import {fillWeeklyProductLogos} from './weeklyPptxLogos';
import {A,P,R,REL,children,first,parse,serialize,escapeXml,relation,override,writeText,setFill} from './weeklyPptxXml';
const validLink=(v:string)=>{try{const u=new URL(v);return /^https?:$/.test(u.protocol)&&!u.username&&!u.password?u.href:null;}catch{return null;}};
export async function createWeeklyPptx(report:WeeklyReportData,bytes:ArrayBuffer):Promise<Blob>{
 if(report.editorial?.status!=='ready'||[...report.news,...report.aiNews].some(item=>!report.editorial?.articles?.some(article=>article.id===item.id&&article.status==='ready')))throw Error('Redação com leitura das fontes necessária antes da exportação.');
 const zip=await JSZip.loadAsync(bytes),slides=buildWeeklySlides(report);
 const load=async(n:string)=>{const f=zip.file(n);if(!f)throw Error('Template part missing: '+n);return f.async('string');};
 const originals=new Map<number,{xml:string;rels:string}>();for(const s of slides)if(!originals.has(s.source))originals.set(s.source,{xml:await load(`ppt/slides/slide${s.source}.xml`),rels:await load(`ppt/slides/_rels/slide${s.source}.xml.rels`)});
 const presentation=parse(await load('ppt/presentation.xml')),rels=parse(await load('ppt/_rels/presentation.xml.rels')),types=parse(await load('[Content_Types].xml'));
 const list=first(presentation,P,'sldIdLst');while(list.firstChild)list.removeChild(list.firstChild);
 for(const e of children(rels.documentElement))if(e.getAttribute('Type')?.endsWith('/slide'))rels.documentElement.removeChild(e);
 for(const e of children(types.documentElement))if(/^\/ppt\/(?:slides|notesSlides)\//.test(e.getAttribute('PartName')||''))types.documentElement.removeChild(e);
 for(const n of Object.keys(zip.files))if(/^ppt\/(?:slides|notesSlides)\//.test(n))zip.remove(n);
 for(const[index,s]of slides.entries()){
  const n=900+index,doc=parse(originals.get(s.source)!.xml),sr=parse(originals.get(s.source)!.rels),values={...manifest.defaults,...s.values} as Record<string,string>;
  const shapes=new Map(Array.from(doc.getElementsByTagNameNS(P,'sp')).map(sp=>[Number(first(sp,P,'cNvPr')?.getAttribute('id')),sp]));
  for(const id of s.removeIds||[])for(const node of Array.from(doc.getElementsByTagNameNS(P,'cNvPr')))if(Number(node.getAttribute('id'))===id){const shape=node.parentNode?.parentNode;shape?.parentNode?.removeChild(shape);shapes.delete(id);}
  for(const shape of shapes.values()){
   const token=Array.from(shape.getElementsByTagNameNS(A,'t')).map(t=>t.textContent||'').join('').match(/^\{\{([^}]+)\}\}$/)?.[1];if(token)writeText(shape,values[token]||'');
   if(token&&values[token]==='Sumário'){const nav=first(shape,P,'cNvPr');if(nav){const click=doc.createElementNS(A,'a:hlinkClick');click.setAttributeNS(R,'r:id','weeklyToc');click.setAttribute('action','ppaction://hlinksldjump');nav.appendChild(click);if(!children(sr.documentElement).some(e=>e.getAttribute('Id')==='weeklyToc'))relation(sr,'weeklyToc','slide',`slide${900+slides.findIndex(slide=>slide.source===4)}.xml`);}}
   const links=token&&s.links?.[token];if(links){const urls=Array.isArray(links)?links:[links],paragraphs=Array.from(shape.getElementsByTagNameNS(A,'p'));urls.forEach((url,i)=>{const link=validLink(url),run=paragraphs[i]&&first(paragraphs[i],A,'r');if(!link||!run)return;let pr=first(run,A,'rPr');if(!pr){pr=doc.createElementNS(A,'a:rPr');run.insertBefore(pr,run.firstChild);}const click=doc.createElementNS(A,'a:hlinkClick'),id=`source_${index}_${first(shape,P,'cNvPr').getAttribute('id')}_${i}`;click.setAttributeNS(R,'r:id',id);pr.appendChild(click);relation(sr,id,'hyperlink',link,true);});}
  }
  if(s.source===3)for(const id of [5021,5023,5025,5027]){const shape=shapes.get(id);if(shape)setFill(shape,report.vulnerabilities.kevCount?'FF9B37':'72727E');}
  for(const {id,color} of s.fills||[]){const shape=shapes.get(id);if(shape)setFill(shape,color);}
  if([13,14].includes(s.source))for(const shape of shapes.values()){const text=Array.from(shape.getElementsByTagNameNS(A,'t')).map(t=>t.textContent||'').join('');if(text.startsWith('CVSS ')){const score=Number(text.match(/^CVSS (\d+(?:[.,]\d+)?)/)?.[1]?.replace(',','.'));setFill(shape,!Number.isFinite(score)?'72727E':score>=9?'E03C31':score>=7?'FF9B37':'72727E');}}
  for(const bar of s.bars||[]){const shape=shapes.get(bar.id);if(!shape)continue;const ext=first(shape,A,'ext'),off=first(shape,A,'off'),width=s.source===20?1250000:1691640,filled=Math.round(width*bar.count/Math.max(1,bar.max));ext?.setAttribute('cx',String(Math.max(1,filled)));const label=shapes.get(bar.label),labelOff=label&&first(label,A,'off');if(labelOff&&off)labelOff.setAttribute('x',String(Number(off.getAttribute('x'))+filled+60000));}
  if(s.map){
   const max=Math.max(1,...Object.values(s.map)),biggest=new Map<string,{x:number;y:number;area:number}>();
   for(const shape of shapes.values()){const code=first(shape,P,'cNvPr')?.getAttribute('name')?.match(/^País ([A-Z]{2})$/)?.[1];if(!code)continue;const count=s.map[code]||0;setFill(shape,count?(count/max>.6?'FFE600':'B6A300'):'2E2E38');const off=first(shape,A,'off'),ext=first(shape,A,'ext');if(off&&ext){const w=Number(ext.getAttribute('cx')),h=Number(ext.getAttribute('cy'));if(w*h>(biggest.get(code)?.area||0))biggest.set(code,{x:Number(off.getAttribute('x'))+w/2,y:Number(off.getAttribute('y'))+h/2,area:w*h});}}
   const top=Object.entries(s.map).sort((a,b)=>b[1]-a[1]).slice(0,7);for(let i=0;i<7;i++){const label=shapes.get(5618+i);if(!label)continue;const row=top[i];if(!row){label.parentNode?.removeChild(label);continue;}writeText(label,`${countryNames[row[0]]||row[0]}  ${row[1]}`);const ext=first(label,A,'ext');ext?.setAttribute('cx','1100000');const pos=biggest.get(row[0]),off=first(label,A,'off');if(pos&&off){off.setAttribute('x',String(Math.round(Math.max(700000,Math.min(6100000,pos.x-350000)))));off.setAttribute('y',String(Math.round(pos.y)));}}
   const arrow=shapes.get(169);if(arrow)arrow.parentNode?.removeChild(arrow);
  }
  if([13,14].includes(s.source)){const v=report.vulnerabilities;const rows=s.source===13?(v.editorial?.highlights??v.priority).slice(0,3):(v.editorial?.exploited??v.kev).filter(row=>row.kev).slice(0,3);await fillWeeklyProductLogos(zip,doc,sr,rows);if(rows.some(row=>row.editorialFamily==='PHP'))s.notes+='\nPHP: logo alternativo de Levi Morrison, https://www.php.net/download-logos.php; CC BY-SA 4.0 https://creativecommons.org/licenses/by-sa/4.0/. Arte preservada e redimensionada proporcionalmente.';}
  const note=`<?xml version="1.0" encoding="UTF-8"?><p:notes xmlns:p="${P}" xmlns:a="${A}"><p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/><p:sp><p:nvSpPr><p:cNvPr id="2" name="Sources"/><p:cNvSpPr/><p:nvPr><p:ph type="body" idx="1"/></p:nvPr></p:nvSpPr><p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t>${escapeXml(s.notes)}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:notes>`;
  relation(sr,'weeklyNotes','notesSlide',`../notesSlides/notesSlide${n}.xml`);zip.file(`ppt/notesSlides/notesSlide${n}.xml`,note);
  const nr=parse(`<Relationships xmlns="${REL}"/>`);relation(nr,'slide','slide',`../slides/slide${n}.xml`);if(zip.file('ppt/notesMasters/notesMaster1.xml'))relation(nr,'master','notesMaster','../notesMasters/notesMaster1.xml');zip.file(`ppt/notesSlides/_rels/notesSlide${n}.xml.rels`,serialize(nr));override(types,`/ppt/notesSlides/notesSlide${n}.xml`,'application/vnd.openxmlformats-officedocument.presentationml.notesSlide+xml');
  zip.file(`ppt/slides/slide${n}.xml`,serialize(doc));zip.file(`ppt/slides/_rels/slide${n}.xml.rels`,serialize(sr));const entry=presentation.createElementNS(P,'p:sldId');entry.setAttribute('id',String(256+index));entry.setAttributeNS(R,'r:id','weekly'+n);list.appendChild(entry);relation(rels,'weekly'+n,'slide',`slides/slide${n}.xml`);override(types,`/ppt/slides/slide${n}.xml`,'application/vnd.openxmlformats-officedocument.presentationml.slide+xml');
 }
 await fillWeeklyCharts(zip,report,types);
 zip.file('ppt/presentation.xml',serialize(presentation));zip.file('ppt/_rels/presentation.xml.rels',serialize(rels));zip.file('[Content_Types].xml',serialize(types));
 const core=parse(await load('docProps/core.xml'));for(const[name,value]of Object.entries({title:`Boletim Semanal ${manifest.publisher.name} - ${report.range.id}`,creator:manifest.publisher.name,lastModifiedBy:'ThreatSumm4ry'}))for(const node of Array.from(core.getElementsByTagNameNS('*',name)))node.textContent=value;zip.file('docProps/core.xml',serialize(core));
 const app=parse(await load('docProps/app.xml'));for(const[name,value]of Object.entries({Slides:String(slides.length),Notes:String(slides.length)}))for(const node of Array.from(app.getElementsByTagNameNS('*',name)))node.textContent=value;zip.file('docProps/app.xml',serialize(app));
 return zip.generateAsync({type:'blob',mimeType:'application/vnd.openxmlformats-officedocument.presentationml.presentation',compression:'DEFLATE'});
}
