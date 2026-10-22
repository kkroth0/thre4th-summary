import fs from 'node:fs/promises';import path from 'node:path';import JSZip from 'jszip';
// Reuses native EY objects. No customer text, incident, external link, chart
// cache or embedded source workbook is allowed in the distributable template.
const source=process.argv[2];if(!source)throw Error('Pass the approved EY source PPTX');
const root=process.cwd(),zip=await JSZip.loadAsync(await fs.readFile(source));
const selected=[1,2,3,4,5,6,12,13,14,15,16,17,18,19,20,21,26,27,28];
const roles={cover:1,intro:2,summary:3,toc:4,newsDivider:5,news:6,vulnerabilityDivider:12,vulnerabilities:13,exploited:14,ransomwareDivider:15,map:16,ransomware:17,history:18,aiDivider:19,aiOverview:20,aiNews:21,tlp:26,notice:27,back:28};
const staticText=new Set(['TLP:AMBER','BOLETIM SEMANAL','Inteligência\nCibernética','EY CTI Brasil • Cyber Fusion Center','Cyber Threat Intelligence e Threat Hunting','Sobre este boletim','Fato','O que aconteceu, com data e fonte.','Análise do EY CTI Brasil','Pontos de atenção','Onde o risco aparece no ambiente.','Resumo executivo','NÍVEL DE AMEAÇA EXTERNA','BAIXO','MÉDIO','ALTO','CRÍTICO','A semana em números','Panorama semanal','Nesta edição','00','01','02','03','04','05','Notícias em destaque','Vulnerabilidades','Ransomware na América Latina','Inteligência artificial','Apêndice','Sumário','Notícias com a análise do EY CTI Brasil','O QUE ACONTECEU','PONTOS DE ATENÇÃO','FONTES','DESCRIÇÃO','CORREÇÃO','MAIS INFORMAÇÕES','ONDE SE CONCENTRAM','RECORTE BRASIL','TODAS AS VÍTIMAS DA SEMANA','VÍTIMA','PAÍS','GRUPO','ENCAMINHAMENTO SUGERIDO','IDENTIFICAR VÍNCULOS','AVALIAR EXPOSIÇÃO','DEFINIR RESPOSTA','Cruzar a lista com o cadastro de terceiros.','Se houver vínculo, avaliar acesso, dependência e impacto potencial.','Encaminhar os casos relevantes às áreas responsáveis.','Verificar se as organizações da lista fazem parte da cadeia de fornecedores ou parceiros.','Tendência das últimas 12 semanas','Vítimas por semana','Os três grupos mais ativos, semana a semana','ESTA SEMANA','COMO INTERPRETAR','ONDE ESTÃO AS FALHAS','IA em outros produtos','Frameworks e MLOps','Servidores de modelos','Conectores MCP','Plataformas de IA','Agentes de IA','recursos de IA dentro de sistemas comuns','bibliotecas para criar e treinar modelos','rodam os modelos para quem os usa','ligam assistentes de IA a dados e sistemas','ambientes para montar apps e agentes','IA que executa tarefas por conta própria','VALIDAR NO INVENTÁRIO','FERRAMENTA','FALHAS*','GRAVIDADE','O QUE IMPORTA PARA A LIDERANÇA','LOCALIZAR','PRIORIZAR','TRATAR','Identificar as ferramentas e as versões em uso.','Avaliar a criticidade do ativo, o acesso e o impacto potencial.','Definir responsável e prazo para correção ou mitigação.','Aviso','Definições do TLP','TLP:RED','TLP:AMBER+STRICT','TLP:GREEN','TLP:CLEAR']);
const decode=s=>s.replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&apos;/g,"'");
const manifest={version:3,url:'/templates/weekly-report-ey-v3.pptx',roles,defaults:{},shapes:{},charts:[],source:'EY weekly bulletin, approved reference; A4 portrait, Overpass'};
for(const name of Object.keys(zip.files)){
 if(/^ppt\/notesSlides\//.test(name)||/^ppt\/embeddings\//.test(name))zip.remove(name);
 if(!name.endsWith('.xml')&&!name.endsWith('.rels'))continue;
 if(!zip.file(name))continue;let text=await zip.file(name).async('string');
 if(/^ppt\/slides\/slide\d+\.xml$/.test(name)){
  const number=Number(name.match(/slide(\d+)/)[1]);if(!selected.includes(number)){zip.remove(name);continue;}
  manifest.shapes[number]={};
  text=text.replace(/<p:sp\b[\s\S]*?<\/p:sp>/g,sp=>{
   const id=sp.match(/<p:cNvPr\b[^>]*\bid="(\d+)"/)?.[1];const paragraphs=[...sp.matchAll(/<a:p\b[^>]*>[\s\S]*?<\/a:p>/g)];const full=paragraphs.map(p=>[...p[0].matchAll(/<a:t\b[^>]*>([\s\S]*?)<\/a:t>/g)].map(m=>decode(m[1])).join('')).join('\n');
   if(!id||!full)return sp;const key=`S${number}_${id}`;manifest.defaults[key]=staticText.has(full)?full:'';
   manifest.shapes[number][id]=key;
   // Keep paragraph geometry and uniform typography; remove source wording.
   const first=paragraphs[0]?.[0];if(!first)return sp;
   let rpr=sp.match(/<a:rPr\b[^>]*(?:\/>|>[\s\S]*?<\/a:rPr>)/)?.[0]||'';
   const prs=[...sp.matchAll(/<a:rPr\b[^>]*(?:\/>|>[\s\S]*?<\/a:rPr>)/g)].map(m=>m[0]);
   if(prs.some(p=>! /\bb="1"/.test(p)))rpr=rpr.replace(/\s+b="1"/,'');
   rpr=rpr.replace(/<a:hlinkClick\b[^>]*(?:\/>|>[\s\S]*?<\/a:hlinkClick>)/g,'');
   const ppr=first.match(/<a:pPr\b[^>]*(?:\/>|>[\s\S]*?<\/a:pPr>)/)?.[0]||'';
   return sp.replace(/<p:txBody>([\s\S]*?)<\/p:txBody>/,(_,body)=>`<p:txBody>${body.slice(0,body.indexOf('<a:p'))}<a:p>${ppr}<a:r>${rpr}<a:t>{{${key}}}</a:t></a:r></a:p></p:txBody>`);
  });
  text=text.replace(/<a:hlinkClick\b[^>]*(?:\/>|>[\s\S]*?<\/a:hlinkClick>)/g,'');
  // Vendor/company logos describe the example edition, not future records.
  // EY and the source layout stay intact; no old brand is assigned to new data.
  if([13,14,17,20].includes(number))text=text.replace(/<p:pic\b[\s\S]*?<\/p:pic>/g,pic=>/name="Logo EY"/.test(pic)?pic:'');
 }
 if(/^ppt\/slides\/_rels\/slide\d+\.xml.rels$/.test(name)){
  const number=Number(name.match(/slide(\d+)/)[1]);if(!selected.includes(number)){zip.remove(name);continue;}
  text=text.replace(/<Relationship\b[^>]*\bType="[^"]*\/(?:notesSlide|hyperlink|slide)"[^>]*\/>/g,'');
 }
 if(/^ppt\/charts\/chart\d+\.xml$/.test(name)){
  manifest.charts.push(name);
  text=text.replace(/<c:(?:numCache|strCache)>[\s\S]*?<\/c:(?:numCache|strCache)>/g,cache=>cache.replace(/<c:v>[\s\S]*?<\/c:v>/g,'<c:v>0</c:v>')).replace(/<c:externalData\b[\s\S]*?<\/c:externalData>/g,'');
  text=text.replace(/<c:dLbl>[\s\S]*?<\/c:dLbl>/g,label=>label.replace(/<a:t>[\s\S]*?<\/a:t>/g,'<a:t>—</a:t>'));
  const rn=name.replace('charts/','charts/_rels/')+'.rels';zip.remove(rn);
 }
 if(name==='ppt/presentation.xml')text=text.replace(/<p:sldIdLst>[\s\S]*?<\/p:sldIdLst>/,`<p:sldIdLst>${selected.map((n,i)=>`<p:sldId id="${256+i}" r:id="weeklyTemplate${n}"/>`).join('')}</p:sldIdLst>`);
 if(name==='ppt/_rels/presentation.xml.rels')text=text.replace(/<Relationship\b[^>]*\bType="[^"]*\/slide"[^>]*\/>/g,'').replace('</Relationships>',selected.map(n=>`<Relationship Id="weeklyTemplate${n}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide${n}.xml"/>`).join('')+'</Relationships>');
 if(name==='[Content_Types].xml')text=text.replace(/<Override\b[^>]*\bPartName="\/ppt\/(?:notesSlides|slides)\/[^>]*\/>/g,part=>selected.some(n=>part.includes(`PartName="/ppt/slides/slide${n}.xml"`))?part:'');
 if(name==='docProps/core.xml')text=text.replace(/<dc:title>[\s\S]*?<\/dc:title>/,'<dc:title>Boletim Semanal EY CTI Brasil</dc:title>').replace(/<cp:keywords>[\s\S]*?<\/cp:keywords>/,'<cp:keywords/>');
 if(name==='docProps/app.xml')text=text.replace(/<Slides>\d+<\/Slides>/,`<Slides>${selected.length}</Slides>`).replace(/<Notes>\d+<\/Notes>/,'<Notes>0</Notes>').replace(/<TitlesOfParts>[\s\S]*?<\/TitlesOfParts>/,'');
 zip.file(name,text);
}
// The TLP and legal copy is source-independent; recipient clauses are filled at export.
for(const n of [26,27]){const src=await JSZip.loadAsync(await fs.readFile(source));const t=await src.file(`ppt/slides/slide${n}.xml`).async('string');for(const sp of t.match(/<p:sp\b[\s\S]*?<\/p:sp>/g)||[]){const id=sp.match(/<p:cNvPr\b[^>]*\bid="(\d+)"/)?.[1];if(n===26&&Number(id)>=5983&&Number(id)<=5994){manifest.defaults[`S${n}_${id}`]=[...sp.matchAll(/<a:t\b[^>]*>([\s\S]*?)<\/a:t>/g)].map(m=>decode(m[1])).join('');}}}
const out=path.join(root,'public/templates/weekly-report-ey-v3.pptx');await fs.writeFile(out,await zip.generateAsync({type:'nodebuffer',compression:'DEFLATE'}));await fs.writeFile(path.join(root,'src/config/weeklyEyTemplate.json'),JSON.stringify(manifest,null,2)+'\n');console.log(JSON.stringify({layouts:selected.length,charts:manifest.charts.length,output:out}));
