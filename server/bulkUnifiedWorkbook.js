import ExcelJS from 'exceljs';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import readline from 'node:readline';
import {pipeline} from 'node:stream/promises';
import {once} from 'node:events';
import {setImmediate as yieldTurn} from 'node:timers/promises';
import {createBulkRawTable} from './bulkRawTable.js';
import {addBulkDashboard,BULK_COLORS as C,scrubXml,workbookMetadata,prepareBulkChartZip,BULK_REPORT_VERSION,createUnifiedBulkRegistry,projectUnifiedBulkRow,UNIFIED_INDICATOR_COLUMNS,UNIFIED_PUBLICATION_COLUMNS,UNIFIED_MENTION_COLUMNS,UNIFIED_RELATION_COLUMNS,UNIFIED_TECHNIQUE_COLUMNS} from './bulkShared.generated.mjs';

/** One projection/writer is shared by durable exports and saved-snapshot repairs. */
export async function writeUnifiedBulkWorkbook({rows,outputPath,asOf=new Date().toISOString(),progress=()=>{},project=projectUnifiedBulkRow}){
 const final=outputPath,tmp=final+'.tmp.xlsx',candidate=final+'.ready.xlsx',spool=final+'.unified-parts';let spoolStream;
 function header(ws,columns){ws.columns=columns.map(([key,,width])=>({key,width}));const row=ws.getRow(1);row.values=columns.map(column=>column[1]);row.height=42;row.font={name:'Arial',size:10,bold:true,color:{argb:C.white}};row.fill={type:'pattern',pattern:'solid',fgColor:{argb:C.ink}};row.alignment={vertical:'middle',wrapText:true};return row;}
async function valuesFor(values,sheet,row,keys){return values.map((value,i)=>{
 if(value==null||value==='')return undefined;if(typeof value==='number'||typeof value==='boolean')return value;
 if(typeof value!=='string')throw Error('A análise unificada aceita somente campos estruturados.');
 if(['date','firstMention','lastMention','created'].includes(keys[i])&&Number.isFinite(Date.parse(value)))return new Date(Date.parse(value)-3*3600000);
 const text=scrubXml(value);if(text.length>32767)throw Error('Um campo da análise excede o tamanho permitido pelo Excel.');return text;
});}
function rawTable(wb,name,columns){return createBulkRawTable(wb,name,columns,{header,valuesFor,colors:C,progress:async count=>{progress(count);await yieldTurn();},cellFormat:(cell,key)=>{if(['date','firstMention','lastMention','created'].includes(key)&&cell.value instanceof Date)cell.numFmt='dd/mm/yyyy hh:mm';}});}
 try{
 const registry=createUnifiedBulkRegistry();spoolStream=fs.createWriteStream(spool,{mode:0o600});
 let total=0;for await(const item of rows){
  const record=registry.add(project(item));
  if(!spoolStream.write(JSON.stringify(record)+'\n'))await once(spoolStream,'drain');
  if(++total%100===0){progress(total);await yieldTurn();}
 }
 await new Promise((resolve,reject)=>{spoolStream.once('error',reject);spoolStream.end(resolve);});
 const report=registry.finish();const wb=new ExcelJS.stream.xlsx.WorkbookWriter({filename:tmp,useStyles:true,useSharedStrings:true,zip:{zlib:{level:6}}});
 workbookMetadata(wb,'Análise unificada de IOCs',new Date().toISOString(),'Indicadores, atores, malware e publicações');wb.addWorksheet('Dashboard');addBulkDashboard(wb,report.analysis,new Date().toISOString(),report);
 for(const name of ['Dashboard','_dados']){const ws=wb.getWorksheet(name);ws.eachRow(row=>row.commit());ws.commit();}
 const eachProjection=async callback=>{const lines=readline.createInterface({input:fs.createReadStream(spool),crlfDelay:Infinity});for await(const line of lines)await callback(JSON.parse(line));};
 let table=rawTable(wb,'Indicadores',UNIFIED_INDICATOR_COLUMNS);await eachProjection(async item=>table.add(item.record));table.finish();
 table=rawTable(wb,'Publicações',UNIFIED_PUBLICATION_COLUMNS);for(const row of report.publications)await table.add(row);table.finish();
 table=rawTable(wb,'Menções',UNIFIED_MENTION_COLUMNS);await eachProjection(async item=>{for(const row of item.mentions)await table.add(row);});table.finish();
 table=rawTable(wb,'Relações',UNIFIED_RELATION_COLUMNS);let relationCount=0;await eachProjection(async item=>{for(const row of item.relations){await table.add(row);relationCount++;}});table.finish();
 table=rawTable(wb,'Técnicas ATT&CK',UNIFIED_TECHNIQUE_COLUMNS);for(const row of report.techniques)await table.add(row);table.finish();
 await wb.commit();
 const bytes=await fsp.readFile(tmp),zip=await prepareBulkChartZip(new Uint8Array(bytes.buffer,bytes.byteOffset,bytes.byteLength),[],report.analysis);
 await pipeline(zip.generateNodeStream({type:'nodebuffer',streamFiles:false,compression:'DEFLATE'}),fs.createWriteStream(candidate,{mode:0o600}));await fsp.rename(candidate,final);
 const summary={total,evidence:report.mentions,publications:report.publicationCount,relations:relationCount,catalogActors:report.analysis.actors.length,software:report.analysis.families.length,partial:report.analysis.partial,unsupported:report.analysis.unsupported,charts:4,bytes:(await fsp.stat(final)).size,generatedAt:asOf,reportVersion:BULK_REPORT_VERSION,executiveSummaryIncluded:false,rawJsonIncluded:false};
 await fsp.unlink(tmp);await fsp.unlink(spool);return {file:final,total,summary};
 }catch(error){try{spoolStream?.destroy();}catch{}for(const file of [tmp,candidate,spool])try{await fsp.unlink(file);}catch{}throw error;}
}
