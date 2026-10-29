// Diagnostic only: read saved rows, exercise export analysis, and remove temporary QA files.
// Does not modify the batch, source results, quotas or export queue.
import fs from 'node:fs';import path from 'node:path';import os from 'node:os';import crypto from 'node:crypto';import {pathToFileURL} from 'node:url';
const root=path.resolve(process.argv[2]),login=String(process.argv[3]).toLowerCase();if(!/^[a-z0-9-]{1,39}$/.test(login))throw Error('Invalid account');
const users=JSON.parse(fs.readFileSync(path.join(root,'server/.users.json'),'utf8')),owner=Object.keys(users).find(id=>users[id].login?.toLowerCase()===login);if(!owner)throw Error('Account unavailable');
const {parse}=await import(pathToFileURL(path.join(root,'server/node_modules/dotenv/lib/main.js'))),env=parse(fs.readFileSync(path.join(root,'.env')));
const {createBulkStore}=await import(pathToFileURL(path.join(root,'server/bulkJobs.js'))),shared=await import(pathToFileURL(path.join(root,'server/bulkShared.generated.mjs'))),{createBulkLocalSnapshot}=await import(pathToFileURL(path.join(root,'server/bulkLocalSnapshot.js'))),{default:ExcelJS}=await import(pathToFileURL(path.join(root,'server/node_modules/exceljs/excel.js')));
const store=createBulkStore({filePath:env.BULK_JOBS_PATH||path.join(root,'server/.bulk-enrichment.sqlite'),readOnly:true,eligibleSources:shared.eligibleSources,composeRow:shared.composeBulkRow});
const item=store.prepare('SELECT job FROM bulk_exports WHERE owner=? ORDER BY created DESC LIMIT 1').get(owner),job=store.owned(owner,item.job),qaDir=fs.mkdtempSync(path.join(os.tmpdir(),'bulk-export-stage-')),lean=[];
let stage='saved-analysis',ordinal=null,snapshot;
try{
 for(const entry of store.items(job.id,{})){
  ordinal=entry.ordinal;const row=store.row(job,entry),a=shared.analyzeBulkRow(row);
  lean.push({...a,record:{score:a.record.score,actors:a.record.actors,families:a.record.families,notes:a.record.notes,tactics:a.record.tactics,type:a.record.type},row:{query:row.query,state:row.state,contextLoading:row.contextLoading,context:{errors:row.context.errors,publications:[],evidence:Array(row.context.evidence.length).fill(null)},result:{query:row.query,overallScore:row.result.overallScore,threatLevel:row.result.threatLevel,detections:row.result.detections,totalVendors:row.result.totalVendors,vendorData:row.result.vendorData.map(v=>({name:v.name,data:{},error:v.error,isLoading:v.isLoading,unsupported:v.unsupported}))}}});
 }
 console.log(JSON.stringify({readOnly:true,stage,rows:lean.length,heapMiB:Math.round(process.memoryUsage().heapUsed/1048576)}));
 stage='local-tail';snapshot=createBulkLocalSnapshot({filePath:env.IOC_INTELLIGENCE_PATH||path.join(root,'server/.ioc-intelligence.sqlite'),spoolPath:path.join(qaDir,'context'),owner});
 let checked=0;for(const entry of store.prepare('SELECT * FROM bulk_items WHERE job=? AND ordinal>=? ORDER BY ordinal').iterate(job.id,5000)){ordinal=entry.ordinal;shared.analyzeBulkRow(snapshot.enrich(store.row(job,entry)));checked++;}
 snapshot.close();snapshot=null;console.log(JSON.stringify({readOnly:true,stage,checked}));
 stage='aggregate';lean.sort((a,b)=>shared.PRIORITIES.indexOf(a.priority)-shared.PRIORITIES.indexOf(b.priority)||Number(b.record.score)-Number(a.record.score)||a.row.query.localeCompare(b.row.query));const analysis=shared.aggregateBulkAnalyses(lean);
 console.log(JSON.stringify({readOnly:true,stage,rows:analysis.total,actors:analysis.actors.length,techniques:analysis.techniques.length}));
 stage='dashboard';const wb=new ExcelJS.stream.xlsx.WorkbookWriter({filename:path.join(qaDir,'dashboard.xlsx'),useStyles:true,useSharedStrings:false});wb.addWorksheet('Dashboard');wb.addWorksheet('Resumo executivo');shared.addBulkDashboard(wb,analysis,new Date().toISOString());
 for(const name of ['Dashboard','Resumo executivo','_dados']){const ws=wb.getWorksheet(name);ws.eachRow(row=>row.commit());ws.commit();}
 await wb.commit();console.log(JSON.stringify({readOnly:true,stage,ok:true}));
}catch(error){const safe=String(error.message).replaceAll(root,'<app>').replace(/https?:\/\/\S+/g,'[url]').replace(/\b[a-f0-9]{32,}\b/gi,'[redacted]');console.log(JSON.stringify({readOnly:true,failed:true,stage,ordinal,name:error.name,code:error.code||null,message:safe,stack:String(error.stack).split('\n').slice(1,5).map(line=>line.replaceAll(root,'<app>'))}));}
finally{try{snapshot?.close();}catch{}store.close();for(const name of fs.readdirSync(qaDir)){const target=path.resolve(qaDir,name);if(path.dirname(target)!==qaDir)throw Error('Invalid QA cleanup path');if(fs.statSync(target).isFile())fs.unlinkSync(target);}fs.rmdirSync(qaDir);}
