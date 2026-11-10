import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import ExcelJS from 'exceljs';
import {once} from 'node:events';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';
import path from 'node:path';
import {tmpdir} from 'node:os';
import crypto from 'node:crypto';
import {registerBulkService} from '../bulkService.js';

test('available-result Excel downloads while two complete workbooks await VirusTotal', {timeout: 20000}, async () => {
 const directory = mkdtempSync(path.join(tmpdir(), 'ts-bulk-partial-'));
 const app = express();
 app.use(express.json());
 const principal = {sub: 'owner', login: 'owner'};
 const service = registerBulkService(app, {
  filePath: path.join(directory, 'jobs.sqlite'),
  outputDir: path.join(directory, '.bulk-exports'),
  requirePremium: (req, res, next) => { req.user = principal; next(); },
  lookup: () => { throw Error('No upstream calls in export tests'); },
  readContext: async () => ({}),
  canRun: () => false,
 });
 const job = service.store.create(principal, ['8.8.8.8'], ['VirusTotal', 'AlienVault OTX']);
 let task;
 while ((task = service.store.claim())) {
  if (task.provider === 'VirusTotal') {
   service.store.settle(task, null, {status: 429, retryAt: Date.now() + 600000, message: 'Quota'});
  } else {
   service.store.settle(task, {name: task.provider, data: {'Pulse Count': '9 pulses'}, rawPayload: {pulse_info: {count: 9}}});
  }
 }
 const otherJob = service.store.create(principal, ['9.9.9.9'], ['VirusTotal']);
 const quota = service.store.prepare("SELECT until_at FROM bulk_blocks WHERE provider='VirusTotal'").get().until_at;
 const server = app.listen(0, '127.0.0.1');
 await once(server, 'listening');
 const root = 'http://127.0.0.1:' + server.address().port;
 const post = (jobId, body) => fetch(root + '/api/bulk/jobs/' + jobId + '/exports', {
  method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
 });
 try {
  const full = await post(job.id, {waitForComplete: true});
  assert.equal(full.status, 202);
  const queued = await full.json();
  assert.equal(queued.state, 'awaiting_completion');
  const otherFull = await post(otherJob.id, {waitForComplete: true});
  assert.equal(otherFull.status, 202);
  const otherQueued = await otherFull.json();
  assert.equal(otherQueued.state, 'awaiting_completion');

  const available = await post(job.id, {waitForComplete: false, type: 'ip'});
  assert.equal(available.status, 202);
  const snapshot = await available.json();
  assert.equal(snapshot.state, 'pending');
  assert.notEqual(snapshot.id, queued.id);
  const duplicate = await post(job.id, {waitForComplete: false, type: 'ip'});
  assert.equal(duplicate.status, 202);
  assert.equal((await duplicate.json()).id, snapshot.id);
  const secondAvailable = await post(job.id, {});
  assert.equal(secondAvailable.status, 202);
  const overLimit = await post(job.id, {query: '8.8'});
  assert.equal(overLimit.status, 409);

  service.start();
  let exported;
  for (let attempt = 0; attempt < 200; attempt++) {
   const status = await fetch(root + '/api/bulk/exports/' + snapshot.id);
   assert.equal(status.status, 200);
   exported = await status.json();
   if (exported.state === 'complete' || exported.state === 'error') break;
   await new Promise(resolve => setTimeout(resolve, 50));
  }
  assert.equal(exported.state, 'complete');
  const response = await fetch(root + '/api/bulk/exports/' + snapshot.id + '/download');
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-disposition'), /attachment.*\.xlsx/);
  const workbook = new ExcelJS.Workbook();
  await workbook.xlsx.load(Buffer.from(await response.arrayBuffer()));
  const indicators = workbook.getWorksheet('Indicadores');
  assert.equal(indicators.rowCount, 2);
  assert.match(JSON.stringify(indicators.getRow(2).values), /8\.8\.8\.8/);
  assert.equal(service.store.prepare('SELECT state FROM bulk_exports WHERE id=?').get(queued.id).state, 'awaiting_completion');
  assert.equal(service.store.prepare('SELECT state FROM bulk_exports WHERE id=?').get(otherQueued.id).state, 'awaiting_completion');
  assert.equal(service.store.prepare("SELECT until_at FROM bulk_blocks WHERE provider='VirusTotal'").get().until_at, quota);
  assert.equal(service.store.savedProvider('owner', 'AlienVault OTX', '8.8.8.8').vendor.rawPayload.pulse_info.count, 9);
 } finally {
  await new Promise(resolve => server.close(resolve));
  await service.close();
  const target = path.resolve(directory);
  assert.ok(target.startsWith(path.resolve(tmpdir()) + path.sep + 'ts-bulk-partial-'));
  rmSync(target, {recursive: true, force: true});
 }
});

test('XLSX download serves the authenticated owner from its private dot directory',async()=>{
 const dir=mkdtempSync(path.join(tmpdir(),'ts-bulk-download-')),outputDir=path.join(dir,'.bulk-exports');mkdirSync(outputDir);
 const app=express();app.use(express.json());const service=registerBulkService(app,{filePath:path.join(dir,'jobs.sqlite'),outputDir,requirePremium:(req,res,next)=>{const owner=req.get('X-Test-Owner');if(!owner)return res.status(401).json({error:'Unauthorized'});req.user={sub:owner,login:owner};next();},lookup:()=>{throw Error('No upstream calls in download tests');},readContext:async()=>({}),canRun:()=>true});
 const job=service.store.create({sub:'owner',login:'owner'},['8.8.8.8'],['VirusTotal']),id=crypto.randomUUID(),bytes=Buffer.from('PK test-only workbook bytes');writeFileSync(path.join(outputDir,id+'.xlsx'),bytes);
 service.store.prepare("INSERT INTO bulk_exports(id,job,owner,state,created,updated,revision) VALUES(?,?,?,'complete',?,?,?)").run(id,job.id,'owner',Date.now(),Date.now(),1);
 const server=app.listen(0,'127.0.0.1');await once(server,'listening');const url=`http://127.0.0.1:${server.address().port}/api/bulk/exports/${id}/download`;
 try{assert.equal((await fetch(url)).status,401);assert.equal((await fetch(url,{headers:{'X-Test-Owner':'other'}})).status,404);const response=await fetch(url,{headers:{'X-Test-Owner':'owner'}});assert.equal(response.status,200);assert.match(response.headers.get('content-disposition'),/attachment.*\.xlsx/);assert.deepEqual(Buffer.from(await response.arrayBuffer()),bytes);}finally{await new Promise(r=>server.close(r));await service.close();assert.ok(path.resolve(dir).startsWith(path.resolve(tmpdir())+path.sep+'ts-bulk-download-'));rmSync(dir,{recursive:true,force:true});}
});
