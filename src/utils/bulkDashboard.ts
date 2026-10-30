import type ExcelJS from 'exceljs';
import type { BulkAnalysis, Count } from './bulkAnalysis';
import attack from './bulkAttackTactics.json';

export const BULK_COLORS = { ink:'FF202936',yellow:'FFFFD447',muted:'FF607084',pale:'FFF2F5F9',white:'FFFFFFFF',red:'FFB63737',teal:'FF087F8C' };
const C=BULK_COLORS;
function text(ws:ExcelJS.Worksheet,row:number,from:number,to:number,value:string|number,dark=false,size=11){
  if(from!==to)ws.mergeCells(row,from,row,to);
  const cell=ws.getCell(row,from);cell.value=value;
  cell.font={name:'Arial',size,bold:dark||size>14,color:{argb:dark?C.white:C.ink}};
  cell.fill={type:'pattern',pattern:'solid',fgColor:{argb:dark?C.ink:C.pale}};
  cell.alignment={horizontal:'left',vertical:'middle',wrapText:true,indent:1};
  if(typeof value==='number')cell.numFmt='#,##0';return cell;
}
function page(wb:ExcelJS.Workbook,name:string,title:string,date:string,last=123){
  const ws=wb.getWorksheet(name)||wb.addWorksheet(name);ws.views.splice(0,ws.views.length,{showGridLines:false,zoomScale:85});ws.properties.tabColor={argb:C.yellow};
  ws.pageSetup={paperSize:9,orientation:'portrait',fitToPage:true,fitToWidth:1,fitToHeight:0,printArea:`A1:X${last}`};
  for(let i=1;i<=24;i++)ws.getColumn(i).width=7;
  for(let i=1;i<=last;i++)ws.getRow(i).height=20;
  text(ws,2,2,24,title,true,24);ws.getRow(2).height=44;
  text(ws,3,2,24,`ThreatSumm4ry  /  Enriquecimento de IOCs  /  ${new Date(date).toLocaleString('pt-BR',{timeZone:'America/Fortaleza'})} (UTC−3)`,true,10);
  ws.headerFooter.oddFooter='&LThreatSumm4ry · Enriquecimento de IOCs&R&P / &N';return ws;
}
export function bulkChartData(a:BulkAnalysis):Count[][]{
  return [a.actors,a.families,a.techniques,a.tactics,a.priorities.filter(x=>x.count),a.types,a.asns,a.coverage].map(items=>items.slice(0,10).map(x=>({...x,name:x.name.length>48?x.name.slice(0,45)+'…':x.name})));
}
const amount=(n:number,one:string,many:string)=>`${n.toLocaleString('pt-BR')} ${n===1?one:many}`;
/** Every finding and chart uses the same deduplicated export snapshot. */
export function addBulkDashboard(wb:ExcelJS.Workbook,a:BulkAnalysis,date:string){
  const dashboard=page(wb,'Dashboard','Análise de indicadores',date);
  const investigate=a.analyses.filter(x=>x.priority==='Investigar').length;
  const metrics:[number,string][]=[[a.total,'INDICADORES ÚNICOS'],[investigate,'PARA INVESTIGAÇÃO'],[a.attributed,'ATOR DO CATÁLOGO DECLARADO'],[a.families.length,'MALWARES / FERRAMENTAS'],[a.excluded,'PÚBLICOS / TESTES'],[a.partial,'COBERTURA INCOMPLETA']];
  metrics.forEach(([n,label],i)=>{const x=2+i*4;text(dashboard,5,x,x+2,n,false,28).alignment={horizontal:'center',vertical:'middle'};text(dashboard,6,x,x+2,label,true,8).alignment={horizontal:'center',vertical:'middle',wrapText:true};});
  dashboard.getRow(5).height=44;dashboard.getRow(6).height=30;
  text(dashboard,9,2,24,'LEITURA DO LOTE',true,11);
  const statements=[
    `${amount(investigate,'indicador exige','indicadores exigem')} investigação por detecções ou registros diretos nas fontes. O veredito original permanece no detalhamento.`,
    `${amount(a.catalogMentioned,'indicador cita','indicadores citam')} ${amount(a.catalogActors.length,'ator do catálogo','atores do catálogo')}. Em ${a.attributed}, a fonte declara o ator explicitamente. Rótulos sem validação ficam separados; menção ou declaração não confirma autoria.`,
    `${amount(a.excluded,'indicador público ou de teste foi retirado','indicadores públicos ou de teste foram retirados')} dos rankings de atores, malware, TTPs e ASN. As evidências foram mantidas.`,
    `${amount(a.evidence,'evidência disponível','evidências disponíveis')} no histórico; ${amount(a.partial,'indicador com','indicadores com')} cobertura incompleta. ${amount(a.unsupported,'consulta não foi aceita pela fonte','consultas não foram aceitas pelas fontes')}, discriminadas nas abas de indicadores e fontes. Recusa ou falha não representa ausência de registros.`,
  ];
  statements.forEach((s,i)=>{text(dashboard,10+i*2,2,24,s);dashboard.getRow(10+i*2).height=i===3?46:31;});
  const captions=['Atores do catálogo declarados pela fonte; não confirma autoria.','Malwares e ferramentas citados, sem inferir o operador.','Citações de inteligência; não são telemetria do ambiente.','Derivadas das técnicas citadas e do catálogo ATT&CK local.','Triagem calculada; separada do score original.','Todos os indicadores únicos exportados.','Hospedagem na mesma rede não comprova relação entre atores.','IOCs com resposta concluída, inclusive sem achados.'];
  const chartData=bulkChartData(a);
  captions.forEach((caption,i)=>{const row=18+Math.floor(i/2)*20,from=i%2===0?2:14,to=i%2===0?12:24;text(dashboard,row,from,to,caption,false,9);dashboard.getRow(row).height=28;if(!chartData[i].some(x=>x.count))text(dashboard,row+18,from,to,'Sem dados recebidos para este recorte.',false,10);});
  text(dashboard,100,2,24,'ATORES × TÉCNICAS  /  COOCORRÊNCIA NA MESMA EVIDÊNCIA',true,11);dashboard.getRow(100).height=30;
  const actors=a.actors.slice(0,10),techniques=a.techniques.slice(0,10);
  if(!actors.length||!techniques.length){text(dashboard,102,2,24,'Nenhum par ator–técnica com declaração explícita na mesma evidência. As menções de contexto estão na aba Relações.');dashboard.getRow(102).height=40;}
  else{
    text(dashboard,102,2,7,'Ator do catálogo',true,10);techniques.forEach((t,j)=>text(dashboard,102,8+j,8+j,t.name,true,8));dashboard.getRow(102).height=32;
    actors.forEach((actor,i)=>{text(dashboard,103+i,2,7,actor.name,false,10);dashboard.getRow(103+i).height=28;techniques.forEach((tech,j)=>{const n=a.analyses.filter(x=>x.pairs.some(p=>p.actor.toLowerCase()===actor.name.toLowerCase()&&p.technique===tech.name)).length;const cell=text(dashboard,103+i,8+j,8+j,n||'—',false,10);cell.alignment={horizontal:'center',vertical:'middle'};cell.fill={type:'pattern',pattern:'solid',fgColor:{argb:n?C.yellow:C.pale}};});});
  }
  text(dashboard,116,2,24,'CRITÉRIOS DE LEITURA',true,11);
  text(dashboard,117,2,24,'Contagens por IOC único. Rankings mostram até 10 entradas; a base completa permanece nas abas analíticas. Atribuição de uma fonte, reputação e contexto são dimensões distintas. Não há novas consultas durante a exportação.',false,10);dashboard.getRow(117).height=42;
  text(dashboard,120,2,24,'Antes de bloquear IPs, domínios, URLs ou hashes, valide a evidência, a recência e o impacto em ativos e serviços legítimos. User-Agents genéricos não sustentam bloqueio isoladamente.',false,10);dashboard.getRow(120).height=40;
  const helper=wb.addWorksheet('_dados');helper.state='hidden';
  chartData.forEach((items,i)=>{const start=2+i*14;helper.getCell(start,1).value='Categoria';helper.getCell(start,2).value='Indicadores';items.forEach((x,j)=>{helper.getCell(start+j+1,1).value=x.name;helper.getCell(start+j+1,2).value=x.count;});});
}
