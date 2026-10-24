import JSZip from 'jszip';
import manifest from '@/config/weeklyReportTemplate.json';
import type {WeeklyReportData} from '@/types/weekly-report';
import {day} from './weeklyTemplateSlides';
import {R,REL,CT,children,first,parse,serialize,escapeXml,relation} from './weeklyPptxXml';

export async function fillWeeklyCharts(zip:JSZip,report:WeeklyReportData,types:Document){
 const history=report.ransomware.history||[],totals=new Map<string,number>();history.forEach(w=>w.byGroup.forEach(g=>totals.set(g.name,(totals.get(g.name)||0)+g.count)));
 const groups=[...totals].sort((a,b)=>b[1]-a[1]).slice(0,3).map(g=>g[0]);while(groups.length<3)groups.push('Sem grupo '+(groups.length+1));
 for(const[ci,name]of manifest.charts.entries()){
  const file=zip.file(name);if(!file)throw Error('Native chart missing');const d=parse(await file.async('string')),C='http://schemas.openxmlformats.org/drawingml/2006/chart',series=Array.from(d.getElementsByTagNameNS(C,'ser'));
  const names=series.length===2?['América Latina','Brasil']:groups;
  const values=series.length===2?[history.map(w=>w.latam),history.map(w=>w.brazil)]:groups.map(name=>history.map(w=>w.available?w.byGroup.find(g=>g.name===name)?.count||0:null));
  const labels=history.map(w=>day(new Date(Date.parse(w.to)-1).toISOString()).slice(0,5)),categories=labels.length?labels:Array(12).fill('—');
  for(let si=0;si<series.length;si++){
   const ser=series[si],col=String.fromCharCode(66+si);
   const caches=[{parent:'tx',ref:'strRef',cache:'strCache',values:[names[si]||'Sem dados'],formula:`Sheet1!$${col}$1`},{parent:'cat',ref:'strRef',cache:'strCache',values:categories,formula:`Sheet1!$A$2:$A$${categories.length+1}`},{parent:'val',ref:'numRef',cache:'numCache',values:values[si]?.length?values[si]:Array(12).fill(null),formula:`Sheet1!$${col}$2:$${col}$${categories.length+1}`}];
   for(const config of caches){let parent=first(ser,C,config.parent);if(!parent){parent=d.createElementNS(C,'c:'+config.parent);ser.appendChild(parent);}while(parent.firstChild)parent.removeChild(parent.firstChild);const ref=d.createElementNS(C,'c:'+config.ref),formula=d.createElementNS(C,'c:f');formula.textContent=config.formula;ref.appendChild(formula);const cache=d.createElementNS(C,'c:'+config.cache),count=d.createElementNS(C,'c:ptCount');count.setAttribute('val',String(config.values.length));cache.appendChild(count);config.values.forEach((value,idx)=>{if(value==null)return;const pt=d.createElementNS(C,'c:pt'),v=d.createElementNS(C,'c:v');pt.setAttribute('idx',String(idx));v.textContent=String(value);pt.appendChild(v);cache.appendChild(pt);});ref.appendChild(cache);parent.appendChild(ref);}
   for(const label of Array.from(ser.getElementsByTagNameNS(C,'dLbl'))){const index=Number(first(label,C,'idx')?.getAttribute('val'));for(const text of Array.from(label.getElementsByTagNameNS('http://schemas.openxmlformats.org/drawingml/2006/main','t')))text.textContent=String(values[si]?.[index]??'—');}
  }
  for(const axis of Array.from(d.getElementsByTagNameNS(C,'valAx'))){const scaling=first(axis,C,'scaling');if(scaling)for(const c of children(scaling))if(['max','min'].includes(c.localName))scaling.removeChild(c);}
  const cs=first(d,C,'chartSpace');for(const old of Array.from(d.getElementsByTagNameNS(C,'externalData')))old.parentNode?.removeChild(old);const ext=d.createElementNS(C,'c:externalData');ext.setAttributeNS(R,'r:id','weeklyWorkbook');cs.appendChild(ext);zip.file(name,serialize(d));
  const cr=parse(`<Relationships xmlns="${REL}"/>`),embedded=`weekly-chart${ci+1}.xlsx`;relation(cr,'weeklyWorkbook','package','../embeddings/'+embedded);zip.file(name.replace('charts/','charts/_rels/')+'.rels',serialize(cr));
  // Store the actual plotted data as an editable workbook, not just a chart cache.
  const xlsx=new JSZip(),S='http://schemas.openxmlformats.org/spreadsheetml/2006/main';
  const cell=(v:string|number|null,c:number,r:number)=>v==null?'':typeof v==='number'?`<c r="${String.fromCharCode(65+c)}${r}"><v>${v}</v></c>`:`<c r="${String.fromCharCode(65+c)}${r}" t="inlineStr"><is><t>${escapeXml(v)}</t></is></c>`;
  const rows=[['Semana',...names],...categories.map((label,i)=>[label,...values.map(s=>s[i]??null)])];
  xlsx.file('[Content_Types].xml',`<Types xmlns="${CT}"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>`);
  xlsx.file('_rels/.rels',`<Relationships xmlns="${REL}"><Relationship Id="rId1" Type="${R}/officeDocument" Target="xl/workbook.xml"/></Relationships>`);
  xlsx.file('xl/workbook.xml',`<workbook xmlns="${S}" xmlns:r="${R}"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>`);
  xlsx.file('xl/_rels/workbook.xml.rels',`<Relationships xmlns="${REL}"><Relationship Id="rId1" Type="${R}/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`);
  xlsx.file('xl/worksheets/sheet1.xml',`<worksheet xmlns="${S}"><sheetData>${rows.map((row,i)=>`<row r="${i+1}">${row.map((v,c)=>cell(v,c,i+1)).join('')}</row>`).join('')}</sheetData></worksheet>`);
  zip.file('ppt/embeddings/'+embedded,await xlsx.generateAsync({type:'uint8array'}));
  if(!children(types.documentElement).some(e=>e.getAttribute('Extension')==='xlsx')){const e=types.createElementNS(CT,'Default');e.setAttribute('Extension','xlsx');e.setAttribute('ContentType','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');types.documentElement.appendChild(e);}
 }
}
