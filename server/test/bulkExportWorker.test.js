import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {tmpdir} from 'node:os';
import crypto from 'node:crypto';
import {Worker} from 'node:worker_threads';
import ExcelJS from 'exceljs';
import unzipper from 'unzipper';
import {createBulkStore} from '../bulkJobs.js';
import {eligibleSources,composeBulkRow} from '../bulkShared.generated.mjs';

test('the streaming workbook omits an executive narrative and retains verdicts while a second IOC awaits VirusTotal',async()=>{
 const dir=fs.mkdtempSync(path.join(tmpdir(),'bulk-worker-verdict-')),filePath=path.join(dir,'jobs.sqlite'),store=createBulkStore({filePath,eligibleSources,composeRow:composeBulkRow}),owner='qa-owner';
 try{
  const job=store.create({sub:owner,login:owner},['93.184.216.34','93.184.216.35'],['VirusTotal']);let task;
  while((task=store.claim())){
   if(task.provider==='@context')store.settle(task,{publications:[],evidence:[],errors:[]});
   else if(task.query==='93.184.216.34')store.settle(task,{name:'VirusTotal',data:{Status:'Malicious','Detection Rate':'5/70',Malicious:5},rawPayload:{simulation:true}});
   else store.settle(task,null,{status:429,message:'Simulated quota',retryAt:Date.now()+600000});
  }
  const id=crypto.randomUUID(),at=Date.now();store.prepare('INSERT INTO bulk_exports(id,job,owner,created,updated,revision,filters) VALUES(?,?,?,?,?,?,?)').run(id,job.id,owner,at,at,1,'{}');store.close();
  const result=await new Promise((resolve,reject)=>{
   const worker=new Worker(new URL('../bulkExportWorker.js',import.meta.url),{workerData:{filePath,exportId:id,jobId:job.id,owner,outputDir:dir},resourceLimits:{maxOldGenerationSizeMb:192},execArgv:[]});
   const timeout=setTimeout(()=>{worker.terminate();reject(Error('Fixture export timed out'));},20000);
   worker.on('message',message=>{if(message.done||message.error){clearTimeout(timeout);message.error?reject(Error(message.error)):resolve(message);}});worker.on('error',error=>{clearTimeout(timeout);reject(error);});worker.on('exit',code=>{if(code){clearTimeout(timeout);reject(Error('Worker exited: '+code));}});
  });
  assert.equal(result.total,2);assert.equal(result.summary.partial,1);
  const archive=await unzipper.Open.file(result.file),workbook=(await archive.files.find(file=>file.path==='xl/workbook.xml').buffer()).toString();
  for(const name of ['Resumo executivo','Dados extensos','Consulta original','Detalhes por fonte'])assert.ok(!workbook.includes(name));assert.equal(result.summary.rawJsonIncluded,false);const sheet=workbook.match(/<sheet\b(?=[^>]*\bname="Indicadores")[^>]*\/>/)[0],sheetId=sheet.match(/\bsheetId="(\d+)"/)[1];
  assert.ok(archive.files.some(file=>file.path==='xl/worksheets/sheet'+sheetId+'.xml'));
  const restored=new ExcelJS.Workbook();await restored.xlsx.readFile(result.file);assert.equal(restored.getWorksheet('Indicadores').getCell('C2').value,'Malicioso');assert.equal(restored.getWorksheet('Indicadores').getCell('C3').value,'Sem evidência suficiente');
  assert.equal(archive.files.filter(file=>/\/charts\/chart\d+\.xml$/.test(file.path)).length,4);
 }finally{try{store.close();}catch{}const target=path.resolve(dir);assert.ok(target.startsWith(path.resolve(tmpdir())+path.sep+'bulk-worker-verdict-'));fs.rmSync(target,{recursive:true,force:true});}
});
