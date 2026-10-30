import type ExcelJS from 'exceljs';
import type { BulkAnalysis, Count } from './bulkAnalysis';
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
export function bulkChartData(a:BulkAnalysis):Count[][]{
  return [a.actors,a.families,a.techniques,[],[],[],a.asns,[]].map(items=>items.slice(0,10).map(x=>({...x,name:x.name.length>48?x.name.slice(0,45)+'…':x.name})));
}
/** Reader-facing intelligence only. Collection diagnostics remain in the application. */
export function addBulkDashboard(wb:ExcelJS.Workbook,a:BulkAnalysis,date:string,metrics?:{publicationCount:number;mentionedIndicators:number}){
  const dashboard=wb.getWorksheet('Dashboard')||wb.addWorksheet('Dashboard');
  dashboard.views.splice(0,dashboard.views.length,{showGridLines:false,zoomScale:85});dashboard.properties.tabColor={argb:C.yellow};
  dashboard.pageSetup={paperSize:9,orientation:'landscape',fitToPage:true,fitToWidth:1,fitToHeight:1,printArea:'A1:X53'};
  for(let i=1;i<=24;i++)dashboard.getColumn(i).width=7;
  for(let i=1;i<=53;i++)dashboard.getRow(i).height=20;
  text(dashboard,2,2,24,'Análise de IOCs',true,24);dashboard.getRow(2).height=44;
  text(dashboard,3,2,24,`ThreatSumm4ry  /  ${new Date(date).toLocaleString('pt-BR',{timeZone:'America/Fortaleza'})} (UTC−3)`,true,10);
  const cards:[number,string][]=[[a.total,'INDICADORES'],[metrics?.publicationCount??0,'PUBLICAÇÕES'],[a.actors.length,'ATORES RELACIONADOS'],[a.families.length,'MALWARES / FERRAMENTAS'],[a.techniques.length,'TÉCNICAS ATT&CK'],[metrics?.mentionedIndicators??a.catalogMentioned,'COM MENÇÕES']];
  cards.forEach(([n,label],i)=>{const x=2+i*4;text(dashboard,5,x,x+2,n,false,28).alignment={horizontal:'center',vertical:'middle'};text(dashboard,6,x,x+2,label,true,8).alignment={horizontal:'center',vertical:'middle',wrapText:true};});
  dashboard.getRow(5).height=44;dashboard.getRow(6).height=30;
  const helper=wb.addWorksheet('_dados');helper.state='hidden';
  bulkChartData(a).forEach((items,i)=>{const start=2+i*14;helper.getCell(start,1).value='Categoria';helper.getCell(start,2).value='Indicadores';items.forEach((x,j)=>{helper.getCell(start+j+1,1).value=x.name;helper.getCell(start+j+1,2).value=x.count;});});
}
