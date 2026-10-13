import JSZip from 'jszip';
import { formatPublicationDate } from './publicationDate';
import manifest from '@/config/weeklyTemplate.json';
import type { WeeklyReportData, WeeklyCve, WeeklyNews } from '@/types/weekly-report';

const A='http://schemas.openxmlformats.org/drawingml/2006/main';
const P='http://schemas.openxmlformats.org/presentationml/2006/main';
const R='http://schemas.openxmlformats.org/officeDocument/2006/relationships';
const REL='http://schemas.openxmlformats.org/package/2006/relationships';
const CT='http://schemas.openxmlformats.org/package/2006/content-types';
type Slide={source:number;values:Record<string,string>;notes:string;links?:Record<string,string>};
const day=(value:string)=>new Date(/^\d{4}-\d\d-\d\d$/.test(value)?value+'T12:00:00Z':value).toLocaleDateString('pt-BR',{timeZone:'America/Fortaleza'});
const shorten=(text:unknown,max:number)=>{const value=String(text||'').replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim();return value.length<=max?value:value.slice(0,max-1).replace(/\s+\S*$/,'')+'…';};
const validLink=(value:string)=>{try{const url=new URL(value);return ['http:','https:'].includes(url.protocol)&&!url.username&&!url.password?url.href:null;}catch{return null;}};
const chunks=<T,>(rows:T[],size:number)=>Array.from({length:Math.max(1,Math.ceil(rows.length/size))},(_,i)=>rows.slice(i*size,(i+1)*size));

export function buildWeeklySlides(report:WeeklyReportData):Slide[]{
  const role=manifest.roles;
  const period=`${day(report.range.from)} a ${day(report.range.to)}`;
  const slides:Slide[]=[];
  const add=(source:number,values:Record<string,string>,notes:string,links?:Record<string,string>)=>slides.push({source,values,notes,links});
  add(role.cover.slide,{[role.cover.edition]:`Versão ${report.revision}`,[role.cover.date]:day(report.updatedAt),[role.cover.period]:period,[role.cover.recipient]:report.profile?`Preparado para ${report.profile.name}`:'Panorama de inteligência',[role.cover.product]:'ThreatSumm4ry'},'Período de domingo às 00h ao domingo seguinte às 00h, com fim exclusivo. Horário: America/Fortaleza.');
  add(role.summary.slide,{[role.summary.title]:'Resumo executivo',[role.summary.body]:`${period}\n\n${report.news.length} notícias gerais e ${report.aiNews.length} notícias de inteligência artificial selecionadas para este relatório, sem repetir os eventos correlacionados.\n\n${report.vulnerabilities.total} CVEs publicadas na semana, ${report.vulnerabilities.critical} críticas. ${report.vulnerabilities.kevCount} CVEs adicionadas ao CISA KEV. ${report.vulnerabilities.ai.total} CVEs em ferramentas de IA.\n\n${report.ransomware.latam} alegações de ransomware na América Latina, ${report.ransomware.brazil} no Brasil. As publicações dos grupos permanecem não confirmadas.\n\n${report.reports.length} relatórios concluídos nesta conta durante a semana.\n\nA versão acompanha os novos insumos coletados. Verifique a cobertura das fontes no apêndice.`},JSON.stringify(report.coverage,null,2));
  function news(item:WeeklyNews,ai:boolean){
    const fields=role.news;
    const signals=[item.cves.length?`CVEs: ${item.cves.join(', ')}`:'CVEs não informadas.',item.actors.length?`Atores citados: ${item.actors.join(', ')}`:'Ator não informado nas fontes.',item.malware.length?`Malware citado: ${item.malware.join(', ')}`:'Malware não informado nas fontes.'];
    add(fields.slide,{[fields.category]:ai?'IA':'NOTÍCIA',[fields.region]:'OSINT',[fields.severity]:`SCORE ${item.score}`,[fields.date]:formatPublicationDate({...item,pubDate:item.published}).text,[fields.title]:shorten(item.title,175),[fields.summary]:shorten(item.summary||item.title,650),[fields.context]:shorten(`${item.sources.length} ${item.sources.length===1?'fonte registrada':'fontes registradas'} no mesmo evento. ${signals.join(' ')} As relações indicam o que as fontes citaram; não confirmam comprometimento da sua organização.`,420),[fields.facts]:signals.map(signal=>shorten(signal,140)).join('\n'),[fields.metric]:String(item.sources.length),[fields.metricCaption]:item.sources.length===1?'fonte registrada no evento':'fontes registradas no evento',[fields.action1]:'Revisar as fontes e validar a presença dos indicadores na telemetria da organização.',[fields.action2]:item.cves.length?'Verificar versões e exposição dos produtos citados; consultar as orientações do fabricante.':'Revisar as técnicas reportadas e as detecções disponíveis para o cenário.',[fields.ttp1]:shorten(item.ttps[0]||'',12),[fields.ttpLabel1]:'',[fields.ttp2]:shorten(item.ttps[1]||'',12),[fields.ttpLabel2]:'',[fields.sources]:shorten(item.sources.map(source=>source.source).join(' · '),180)},item.sources.map(source=>`${source.source} | ${source.published} | ${source.title}\n${source.link}`).join('\n\n'),{[fields.title]:item.sources[0]?.link||'',[fields.sources]:item.sources[0]?.link||''});
  }
  report.news.forEach(item=>news(item,false));
  function table(kind:keyof typeof manifest.tables,title:string,subtitle:string,headers:string[],rows:string[][],notes:string){
    const template=manifest.tables[kind],fields=role[kind];
    chunks(rows,template.rows).forEach((part,index)=>{
      const values:Record<string,string>={...('title' in fields?{[fields.title]:title+(rows.length>template.rows?` · ${index+1}`:'')}:{})};
      if('subtitle' in fields)values[fields.subtitle]=subtitle;
      if('note' in fields)values[fields.note]=subtitle;
      for(let row=0;row<=template.rows;row++)for(let col=0;col<template.cols;col++)values[`T${template.slide}_${row}_${col}`]=row===0?(headers[col]||''):(part[row-1]?.[col]||'');
      if(!part.length)values[`T${template.slide}_1_0`]='Sem registros';
      add(template.slide,values,notes);
    });
  }
  const cves=(rows:WeeklyCve[])=>rows.map(row=>[day(row.kev&&row.dateAdded?row.dateAdded+'T12:00:00Z':row.published),row.id,shorten(`${row.vendor} ${row.product}`,80),shorten(row.description,165),row.cvss==null?'—':String(row.cvss),shorten(row.action||`KEV: ${row.kev?'Sim':'Não'} · EPSS: ${row.epss==null?'—':(row.epss*100).toFixed(2)+'%'}`,110)]);
  const cveNotes=(rows:WeeklyCve[])=>rows.map(row=>`${row.id}\nhttps://nvd.nist.gov/vuln/detail/${row.id}\n${(row.references||[]).map(reference=>reference.url).join('\n')}`).join('\n\n');
  table('vulnerabilities','Vulnerabilidades com exploração ativa',`${report.vulnerabilities.kevCount} CVEs adicionadas ao CISA KEV nesta semana.`,['Data','CVE','Produto','Descrição','CVSS','Ação recomendada'],cves(report.vulnerabilities.kev),cveNotes(report.vulnerabilities.kev));
  table('vulnerabilities','Prioridades em vulnerabilidades','Até 50 registros ordenados por KEV, CVSS e EPSS. Validar versões e exposição.', ['Data','CVE','Produto','Descrição','CVSS','Sinais / ação'],cves(report.vulnerabilities.priority),cveNotes(report.vulnerabilities.priority));
  if(report.profile)table('vulnerabilities','Produtos monitorados',`Correspondências com ${report.profile.name}; confirmar versões e exposição.`,['Data','CVE','Produto','Descrição','CVSS','Sinais / ação'],cves(report.vulnerabilities.monitored),cveNotes(report.vulnerabilities.monitored));
  table('ransomware','Ransomware na América Latina',`${report.ransomware.latam} alegações na LATAM, ${report.ransomware.brazil} no Brasil. Fonte: ransomware.live. Alegações não confirmadas.`,['Data','Organização citada','País','Grupo','Setor','Escopo','Situação'],report.ransomware.victims.map(row=>[day(row.published||row.discovered),shorten(row.name,65),row.country,shorten(row.group,25),shorten(row.sector,25),'LATAM','Não confirmada']),report.ransomware.victims.map(row=>`${row.name}\n${row.permalink}`).join('\n\n'));
  report.aiNews.forEach(item=>news(item,true));
  table('vulnerabilities','Vulnerabilidades em ferramentas de IA',`${report.vulnerabilities.ai.total} CVEs publicadas, ${report.vulnerabilities.ai.critical} críticas. Classificação por fabricante, produto e descrição.`,['Data','CVE','Produto','Descrição','CVSS','Sinais / ação'],cves(report.vulnerabilities.ai.items),cveNotes(report.vulnerabilities.ai.items));
  table('recommendations','Recomendações da semana','Orientações do CISA KEV. A aplicação deve ser avaliada pela equipe responsável.', ['Nº','Ação recomendada','Prioridade','Área','Origem'],report.recommendations.map((row,i)=>[String(i+1),shorten(row.action,190),'Imediata','Segurança / TI',row.cve]),report.recommendations.map(row=>`${row.cve}\n${row.source}`).join('\n'));
  table('actors','Atores e malware citados','Entidades mencionadas nas notícias selecionadas; não implica atribuição a cada indicador.', ['Entidade','Tipo','Menções na semana','Contexto','Fonte'],[...report.actors.map(row=>[row.name,'Ator',String(row.count),'Notícias selecionadas','Base unificada']),...report.malware.map(row=>[row.name,'Malware',String(row.count),'Notícias selecionadas','Base unificada'])],report.sources.map(row=>row.link).join('\n'));
  const health=Object.entries(report.coverage.vulnerabilities.sources||{}).map(([name,source])=>`${name}: ${source.status}`).join(' · ');
  add(role.notice.slide,{[role.notice.title]:'Metodologia e fontes',[role.notice.body]:`Dados da base unificada de notícias e IOCs, catálogo NVD com CISA KEV/EPSS e publicações indexadas por ransomware.live.\n\nNotícias gerais: até 10. Notícias de IA: até 5. Até 25 sugestões por categoria, deduplicadas pela correlação da plataforma. A seleção editorial permanece salva durante as atualizações.\n\nCobertura de vulnerabilidades: ${health||report.coverage.vulnerabilities.status||'aguardando'}. Ransomware.live: ${report.coverage.ransomware.status}.\n\nOs indicadores e as entidades preservam as referências de origem. Alegações de criminosos não são confirmação de um incidente.\n\nPeríodo: ${period}. Horário de Fortaleza, de domingo às 00h ao domingo seguinte às 00h, com fim exclusivo. TLP:AMBER.`},report.sources.map(row=>`${row.source} | ${row.title}\n${row.link}`).join('\n\n'));
  return slides;
}

export async function createWeeklyPptx(report:WeeklyReportData,bytes:ArrayBuffer):Promise<Blob>{
  const zip=await JSZip.loadAsync(bytes),slides=buildWeeklySlides(report);
  const parse=(xml:string)=>{const document=new DOMParser().parseFromString(xml,'application/xml');if(document.getElementsByTagName('parsererror').length)throw Error('Invalid template XML');return document;};
  const serialize=(document:Document)=>new XMLSerializer().serializeToString(document);
  const load=async(name:string)=>{const file=zip.file(name);if(!file)throw Error('Template part missing');return file.async('string');};
  const originals=new Map<number,{xml:string;rels:string}>();
  for(const slide of slides)if(!originals.has(slide.source))originals.set(slide.source,{xml:await load(`ppt/slides/slide${slide.source}.xml`),rels:await load(`ppt/slides/_rels/slide${slide.source}.xml.rels`)});
  const presentation=parse(await load('ppt/presentation.xml')),relationships=parse(await load('ppt/_rels/presentation.xml.rels')),types=parse(await load('[Content_Types].xml'));
  const list=presentation.getElementsByTagNameNS(P,'sldIdLst')[0];while(list.firstChild)list.removeChild(list.firstChild);
  for(const item of Array.from(relationships.documentElement.children))if(item.getAttribute('Type')?.endsWith('/slide'))item.remove();
  for(const item of Array.from(types.documentElement.children))if(/^\/ppt\/slides\/(?:_rels\/)?slide\d+\.xml/.test(item.getAttribute('PartName')||''))item.remove();
  for(const name of Object.keys(zip.files))if(/^ppt\/slides\/(?:_rels\/)?slide\d+\.xml(?:\.rels)?$/.test(name))zip.remove(name);
  function relation(document:Document,id:string,type:string,target:string,external=false){const element=document.createElementNS(REL,'Relationship');element.setAttribute('Id',id);element.setAttribute('Type',R+'/'+type);element.setAttribute('Target',target);if(external)element.setAttribute('TargetMode','External');document.documentElement.appendChild(element);}
  function contentType(name:string,type:string){const item=types.createElementNS(CT,'Override');item.setAttribute('PartName',name);item.setAttribute('ContentType',type);types.documentElement.appendChild(item);}
  for(const [index,slide] of slides.entries()){
    const number=900+index,prototype=originals.get(slide.source)!,document=parse(prototype.xml),rels=parse(prototype.rels);
    const values:Record<string,string>={...manifest.defaults,...slide.values,page:String(index+1)};
    const optional=[manifest.roles.news.ttp1,manifest.roles.news.ttp2,manifest.roles.news.ttpLabel1,manifest.roles.news.ttpLabel2];
    for(const shape of Array.from(document.getElementsByTagNameNS(P,'sp')))if(Array.from(shape.getElementsByTagNameNS(A,'t')).some(node=>optional.some(key=>node.textContent===`{{${key}}}`&&!values[key])))shape.remove();
    for(const node of Array.from(document.getElementsByTagNameNS(A,'t'))){const token=node.textContent?.match(/^\{\{([^}]+)\}\}$/)?.[1];node.textContent=(node.textContent||'').replace(/\{\{([^}]+)\}\}/g,(_,key)=>values[key]||'').replace(/\{\{page\}\}/g,String(index+1));
      const link=token&&slide.links?.[token]&&validLink(slide.links[token]);
      if(link&&node.parentElement?.localName==='r'){const run=node.parentElement;let properties=run.getElementsByTagNameNS(A,'rPr')[0];if(!properties){properties=document.createElementNS(A,'a:rPr');run.insertBefore(properties,run.firstChild);}const id='weeklyLink'+index+'_'+Array.from(document.getElementsByTagNameNS(A,'t')).indexOf(node);const click=document.createElementNS(A,'a:hlinkClick');click.setAttributeNS(R,'r:id',id);properties.appendChild(click);relation(rels,id,'hyperlink',link,true);}
      const paragraph=node.parentElement?.parentElement;
      if(token&&paragraph?.localName==='p'&&(node.textContent?.length||0)>80){let properties=paragraph.getElementsByTagNameNS(A,'pPr')[0];if(!properties){properties=document.createElementNS(A,'a:pPr');paragraph.insertBefore(properties,paragraph.firstChild);}properties.setAttribute('algn','l');}
      if(node.textContent?.includes('\n')&&node.parentElement?.localName==='r'&&paragraph?.localName==='p'){
        const lines=node.textContent.split('\n'),run=node.parentElement;node.textContent=lines[0];let anchor:Element=run;
        for(const line of lines.slice(1)){const br=document.createElementNS(A,'a:br');paragraph.insertBefore(br,anchor.nextSibling);const next=run.cloneNode(true) as Element;next.getElementsByTagNameNS(A,'t')[0].textContent=line;paragraph.insertBefore(next,br.nextSibling);anchor=next;}
      }
    }
    // Adapt native table columns to the report fields and remove unused template rows.
    const proportions:Record<number,number[]>={17:[.12,.18,.18,.28,.07,.17],26:[.12,.25,.06,.18,.12,.1,.17],37:[.06,.46,.14,.16,.18],40:[.25,.12,.13,.3,.2]};
    for(const table of Array.from(document.getElementsByTagNameNS(A,'tbl'))){
      const columns=Array.from(table.getElementsByTagNameNS(A,'gridCol')),width=columns.reduce((sum,column)=>sum+Number(column.getAttribute('w')),0);
      const layout=proportions[slide.source];if(layout)columns.forEach((column,col)=>column.setAttribute('w',String(Math.round(width*layout[col]))));
      const rows=Array.from(table.children).filter(row=>row.localName==='tr');
      for(const [rowIndex,row] of rows.entries())if(rowIndex>0){
        if(!Array.from(row.getElementsByTagNameNS(A,'t')).some(node=>node.textContent?.trim())){row.remove();continue;}
        const cells=Array.from(row.children).filter(cell=>cell.localName==='tc');
        const column=slide.source===17?4:slide.source===26?5:slide.source===37?2:-1;
        if(column>=0&&cells[column]){const cell=cells[column];let properties=cell.getElementsByTagNameNS(A,'tcPr')[0];if(!properties){properties=document.createElementNS(A,'a:tcPr');cell.appendChild(properties);}for(const fill of Array.from(properties.children))if(['solidFill','noFill','gradFill'].includes(fill.localName))fill.remove();const fill=document.createElementNS(A,'a:solidFill'),color=document.createElementNS(A,'a:srgbClr');const score=Number(cell.textContent?.trim());color.setAttribute('val',slide.source!==17?'FFE600':score>=9?'E53935':score>=7?'FF9800':score>=4?'FFCE54':'EBECF2');fill.appendChild(color);properties.appendChild(fill);
          for(const run of Array.from(cell.getElementsByTagNameNS(A,'rPr'))){for(const child of Array.from(run.children))if(child.localName==='solidFill')child.remove();const textFill=document.createElementNS(A,'a:solidFill'),textColor=document.createElementNS(A,'a:srgbClr');textColor.setAttribute('val',slide.source===17&&score>=9?'FFFFFF':'191A24');textFill.appendChild(textColor);run.insertBefore(textFill,Array.from(run.children).find(child=>child.localName!=='ln')||null);}
        }
      }
      let frame:Element|null=table.parentElement;while(frame&&frame.localName!=='graphicFrame')frame=frame.parentElement;
      const transform=frame&&Array.from(frame.children).find(child=>child.localName==='xfrm'),extent=transform?.getElementsByTagNameNS(A,'ext')[0];
      if(extent)extent.setAttribute('cy',String(Array.from(table.children).filter(row=>row.localName==='tr').reduce((sum,row)=>sum+Number(row.getAttribute('h')),0)));
    }
    relation(rels,'weeklyNotes','notesSlide',`../notesSlides/notesSlide${number}.xml`);
    const escape=(value:string)=>value.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    zip.file(`ppt/notesSlides/notesSlide${number}.xml`,`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:notes xmlns:p="${P}" xmlns:a="${A}"><p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/><p:sp><p:nvSpPr><p:cNvPr id="2" name="Sources"/><p:cNvSpPr/><p:nvPr><p:ph type="body" idx="1"/></p:nvPr></p:nvSpPr><p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t>${escape(slide.notes)}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:notes>`);
    const noteRels=parse(`<Relationships xmlns="${REL}"/>`);relation(noteRels,'slide','slide',`../slides/slide${number}.xml`);if(zip.file('ppt/notesMasters/notesMaster1.xml'))relation(noteRels,'master','notesMaster','../notesMasters/notesMaster1.xml');
    zip.file(`ppt/notesSlides/_rels/notesSlide${number}.xml.rels`,serialize(noteRels));
    contentType(`/ppt/notesSlides/notesSlide${number}.xml`,'application/vnd.openxmlformats-officedocument.presentationml.notesSlide+xml');
    zip.file(`ppt/slides/slide${number}.xml`,serialize(document));zip.file(`ppt/slides/_rels/slide${number}.xml.rels`,serialize(rels));
    const entry=presentation.createElementNS(P,'p:sldId');entry.setAttribute('id',String(256+index));entry.setAttributeNS(R,'r:id','weeklySlide'+number);list.appendChild(entry);relation(relationships,'weeklySlide'+number,'slide',`slides/slide${number}.xml`);
    contentType(`/ppt/slides/slide${number}.xml`,'application/vnd.openxmlformats-officedocument.presentationml.slide+xml');
  }
  zip.file('ppt/presentation.xml',serialize(presentation));zip.file('ppt/_rels/presentation.xml.rels',serialize(relationships));zip.file('[Content_Types].xml',serialize(types));
  const app=parse(await load('docProps/app.xml'));for(const [name,value] of Object.entries({Slides:String(slides.length),Notes:String(slides.length),Application:'ThreatSumm4ry'}))for(const node of Array.from(app.getElementsByTagNameNS('*',name)))node.textContent=value;zip.file('docProps/app.xml',serialize(app));
  const core=parse(await load('docProps/core.xml'));for(const [name,value] of Object.entries({title:`Relatório semanal · ${report.range.id}`,creator:'ThreatSumm4ry',lastModifiedBy:'ThreatSumm4ry'}))for(const node of Array.from(core.getElementsByTagNameNS('*',name)))node.textContent=value;zip.file('docProps/core.xml',serialize(core));
  return zip.generateAsync({type:'blob',mimeType:'application/vnd.openxmlformats-officedocument.presentationml.presentation',compression:'DEFLATE'});
}

export async function exportWeeklyPptx(report:WeeklyReportData){const response=await fetch('/templates/weekly-report-template-v2.pptx');if(!response.ok)throw Error('Template unavailable');const blob=await createWeeklyPptx(report,await response.arrayBuffer());const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=`Relatorio_Semanal_${report.range.id}_v${report.revision}.pptx`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
