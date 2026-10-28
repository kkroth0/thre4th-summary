import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {once} from 'node:events';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';
import path from 'node:path';
import {tmpdir} from 'node:os';
import crypto from 'node:crypto';
import {registerBulkService} from '../bulkService.js';
test('XLSX download serves the authenticated owner from its private dot directory',async()=>{
 const dir=mkdtempSync(path.join(tmpdir(),'ts-bulk-download-')),outputDir=path.join(dir,'.bulk-exports');mkdirSync(outputDir);
 const app=express();app.use(express.json());const service=registerBulkService(app,{filePath:path.join(dir,'jobs.sqlite'),outputDir,requirePremium:(req,res,next)=>{const owner=req.get('X-Test-Owner');if(!owner)return res.status(401).json({error:'Unauthorized'});req.user={sub:owner,login:owner};next();},lookup:()=>{throw Error('No upstream calls in download tests');},readContext:async()=>({}),canRun:()=>true});
 const job=service.store.create({sub:'owner',login:'owner'},['8.8.8.8'],['VirusTotal']),id=crypto.randomUUID(),bytes=Buffer.from('PK test-only workbook bytes');writeFileSync(path.join(outputDir,id+'.xlsx'),bytes);
 service.store.prepare("INSERT INTO bulk_exports(id,job,owner,state,created,updated,revision) VALUES(?,?,?,'complete',?,?,?)").run(id,job.id,'owner',Date.now(),Date.now(),1);
 const server=app.listen(0,'127.0.0.1');await once(server,'listening');const url=`http://127.0.0.1:${server.address().port}/api/bulk/exports/${id}/download`;
 try{assert.equal((await fetch(url)).status,401);assert.equal((await fetch(url,{headers:{'X-Test-Owner':'other'}})).status,404);const response=await fetch(url,{headers:{'X-Test-Owner':'owner'}});assert.equal(response.status,200);assert.match(response.headers.get('content-disposition'),/attachment.*\.xlsx/);assert.deepEqual(Buffer.from(await response.arrayBuffer()),bytes);}finally{await new Promise(r=>server.close(r));await service.close();assert.ok(path.resolve(dir).startsWith(path.resolve(tmpdir())+path.sep+'ts-bulk-download-'));rmSync(dir,{recursive:true,force:true});}
});
