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
  const executive=page(wb,'Resumo executivo','Síntese do enriquecimento',date,57);
  const completed=a.total-a.partial;
  const sections=[
    ['Escopo e cobertura',`O lote contém ${amount(a.total,'indicador único','indicadores únicos')}. ${amount(completed,'tem','têm')} processamento concluído e ${amount(a.partial,'apresenta','apresentam')} cobertura incompleta. ${amount(a.unsupported,'consulta não foi aceita pela fonte','consultas não foram aceitas pelas fontes')}; essas recusas estão identificadas e não equivalem a achados negativos. ${amount(a.evidence,'evidência do histórico foi preservada','evidências do histórico foram preservadas')}, com data e referência quando fornecidas pela origem.`],
    ['O que merece atenção',investigate?`${amount(investigate,'indicador reúne','indicadores reúnem')} detecções no VirusTotal ou registros diretos de malware em fontes consultadas. Esta prioridade organiza a revisão; não é confirmação de comprometimento. ${a.analyses.filter(x=>x.priority==='Atenção').length} outros indicadores receberam atenção por reputação ou relatos de abuso.`:'Nenhum indicador elegível recebeu prioridade de investigação pelos critérios desta exportação. A leitura considera apenas as fontes respondidas; ausência de detecção não comprova que um IOC seja benigno.'],
    ['Atores, malwares e ferramentas',`${amount(a.catalogMentioned,'indicador cita','indicadores citam')} ${amount(a.catalogActors.length,'ator do catálogo','atores do catálogo')}; ${a.attributed} têm declaração explícita da fonte. Há ${a.families.length} nomes de malware ou ferramentas. IDs do catálogo, nomes originais e rótulos sem validação ficam separados. Entidades apenas citadas permanecem no contexto. Citação e declaração não confirmam autoria ou execução no ambiente.`],
    ['Sinais que exigem contexto',`${amount(a.excluded,'indicador público ou de teste foi excluído','indicadores públicos ou de teste foram excluídos')} dos rankings de ameaça. ${amount(a.analyses.filter(x=>x.fp).length,'IOC teve','IOCs tiveram')} correspondência exata na revisão de falsos positivos da abuse.ch. Essa revisão não apaga achados de fontes independentes.`],
    ['Uso operacional','Antes de bloquear qualquer IP, domínio, URL ou hash, confira a referência, o período observado e o possível impacto em ativos e serviços legítimos. Infraestrutura compartilhada, resolvedores públicos e indicadores de teste exigem contexto. Não há recomendação de bloqueio automático de User-Agents.'],
  ];
  sections.forEach(([title,body],i)=>{const row=6+i*6;text(executive,row,2,24,title,true,12);text(executive,row+1,2,24,body,false,11);executive.getRow(row+1).height=i===0?82:64;});
  text(executive,37,2,24,'INDICADORES PRIORIZADOS  /  ATÉ 10 CASOS',true,11);
  const top=a.analyses.filter(x=>['Investigar','Atenção','Revisar'].includes(x.priority)).slice(0,10);
  if(!top.length){text(executive,39,2,24,'Sem casos elegíveis para priorização neste lote. Indicadores públicos e testes permanecem no detalhamento.');executive.getRow(39).height=38;}
  top.forEach((x,i)=>{const row=39+i;text(executive,row,2,8,x.row.query,false,10);text(executive,row,9,12,x.priority,false,10);text(executive,row,13,24,`${x.record.verdict} · ${x.record.actors||x.record.families||x.record.notes||'Revisar fontes e referências.'}`,false,10);executive.getRow(row).height=38;});
  text(executive,52,2,24,'Como navegar',true,11);
  text(executive,53,2,24,'Indicadores e abas por tipo: leitura por fonte. Publicações, Evidências e Relações: rastreabilidade. Fontes, Detalhes por fonte e Dados extensos: respostas originais, incluindo campos adicionais e conteúdo completo.',false,10);executive.getRow(53).height=42;
  text(executive,56,2,24,`Mapeamento tático: catálogo ATT&CK local de ${attack.generatedAt.slice(0,10)}. Fonte: ${attack.source}`,false,9);
  const helper=wb.addWorksheet('_dados');helper.state='hidden';
  chartData.forEach((items,i)=>{const start=2+i*14;helper.getCell(start,1).value='Categoria';helper.getCell(start,2).value='Indicadores';items.forEach((x,j)=>{helper.getCell(start+j+1,1).value=x.name;helper.getCell(start+j+1,2).value=x.count;});});
}
