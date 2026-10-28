import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import { Worker } from 'node:worker_threads';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { setImmediate as yieldTurn } from 'node:timers/promises';
import { createBulkStore,createBulkRunner } from './bulkJobs.js';
import { prepareBulkInput,eligibleSources,composeBulkRow,BULK_SOURCES,THREAT_VERDICT_VERSION,analyzeBulkRow,ANALYTICAL_COLUMNS,valueText } from './bulkShared.generated.mjs';

const bad=(message,status=400)=>Object.assign(Error(message),{status});
const validFilters=input=>({query:String(input?.query||'').slice(0,256),type:['ip','domain','url','hash'].includes(input?.type)?input.type:'all',state:['queued','running','complete','partial','error','unsupported'].includes(input?.state)?input.state:'all'});
const csv=value=>{let s=valueText(value);if(/^[\s]*[=+@-]/.test(s))s="'"+s;return '"'+s.replace(/"/g,'""')+'"';};

export function registerBulkService(app,{filePath,outputDir,requirePremium,lookup,readContext,canRun,concurrency=3,requiredSources=()=>[]}){
 const store=createBulkStore({filePath,eligibleSources,composeRow:composeBulkRow}),runner=createBulkRunner({store,lookup,readContext,canRun,concurrency,canSchedule:()=>!exportWorker,onError:()=>console.warn('Bulk scheduling deferred')});
 let exportWorker=null,exportTimer,started=false;
 const handle=fn=>async(req,res)=>{res.set('Cache-Control','private, no-store');try{await fn(req,res);}catch(e){if(!res.headersSent)res.status(e.status||500).json({error:e.status?e.message:'Não foi possível concluir a operação do lote.'});}};
 const routes='/api/bulk/jobs';
 app.get(routes,requirePremium,handle((req,res)=>res.json({jobs:store.list(req.user.sub),sources:BULK_SOURCES,requiredSources:requiredSources(req.user)})));
 app.post(routes,requirePremium,handle((req,res)=>{
  if(typeof req.body.input!=='string'||Buffer.byteLength(req.body.input)>3_800_000)throw bad('Envie uma lista de até 3,8 MB.');
  const parsed=prepareBulkInput(req.body.input),sources=[...new Set([...(Array.isArray(req.body.sources)?req.body.sources:[]),...requiredSources(req.user)])].filter(s=>BULK_SOURCES.includes(s));
  if(!sources.length)throw bad('Selecione ao menos uma fonte.');
  if(!parsed.indicators.some(q=>eligibleSources(q,sources).length))throw bad('Nenhuma fonte selecionada é compatível com os indicadores.');
  const job=store.create(req.user,parsed.indicators,sources,parsed.excluded,req.body.requestId,req.body.fresh===true);res.status(201).json(job);runner.wake();
 }));
 app.get(routes+'/:id',requirePremium,handle((req,res)=>res.json(store.summary(req.user.sub,req.params.id))));
 app.get(routes+'/:id/rows',requirePremium,handle((req,res)=>{
  const page=store.page(req.user.sub,req.params.id,{...validFilters(req.query),page:req.query.page,size:req.query.size}),tag='"'+crypto.createHash('sha256').update(JSON.stringify([THREAT_VERDICT_VERSION,page.total,page.page,page.size,page.revision,validFilters(req.query)])).digest('hex')+'"';
  res.set('ETag',tag);if(req.get('If-None-Match')===tag)return res.status(304).end();res.json({total:page.total,page:page.page,size:page.size,rows:page.load()});
 }));
 app.get(routes+'/:id/rows/:ordinal',requirePremium,handle((req,res)=>{const j=store.owned(req.user.sub,req.params.id),n=Number(req.params.ordinal);if(!Number.isInteger(n)||n<0||n>=j.total)throw bad('Indicador não encontrado.',404);res.json(store.completeRow(req.user.sub,j.id,n));}));
 app.post(routes+'/:id/action',requirePremium,handle((req,res)=>{res.json(store.action(req.user.sub,req.params.id,req.body.action,req.user));runner.wake();}));
 app.get(routes+'/:id/download',requirePremium,handle(async(req,res)=>{
  const j=store.owned(req.user.sub,req.params.id),format=String(req.query.format||'json');if(!['json','csv','txt'].includes(format))throw bad('Formato inválido.');
  const snapshot=createBulkStore({filePath,readOnly:true,eligibleSources,composeRow:composeBulkRow}),filters=validFilters(req.query);snapshot.db.exec('BEGIN');
  res.set('Content-Encoding','identity');res.set('Content-Disposition',`attachment; filename="threatsumm4ry-bulk-${j.id}.${format}"`);res.type(format==='json'?'application/json':format==='csv'?'text/csv':'text/plain');
  async function* data(){try{
   if(format==='json')yield '{"generatedAt":'+JSON.stringify(new Date().toISOString())+',"jobId":'+JSON.stringify(j.id)+',"rows":[';
   if(format==='csv')yield '\uFEFF'+[...ANALYTICAL_COLUMNS.map(x=>x[1]),'Resultado completo (JSON)','Contexto completo (JSON)'].map(csv).join(',')+'\r\n';
   let n=0;for(const item of snapshot.items(j.id,filters)){const row=snapshot.row(j,item);if(format==='txt')yield row.query+'\n';else if(format==='json')yield(n?',':'')+JSON.stringify(row);else{const a=analyzeBulkRow(row);a.record.rank=n+1;yield [...ANALYTICAL_COLUMNS.map(c=>a.record[c[0]]),row.result,row.context].map(csv).join(',')+'\r\n';}n++;await yieldTurn();}
   if(format==='json')yield '],"count":'+n+'}';
  }finally{snapshot.close();}}
  await pipeline(Readable.from(data(),{objectMode:false,highWaterMark:65536}),res);
 }));
 app.post(routes+'/:id/exports',requirePremium,handle((req,res)=>{
  const j=store.owned(req.user.sub,req.params.id),filters=JSON.stringify({...validFilters(req.body),verdictVersion:THREAT_VERDICT_VERSION}),existing=store.prepare("SELECT id,state FROM bulk_exports WHERE job=? AND owner=? AND filters=? AND (state IN ('pending','running') OR (state='complete' AND revision=?)) ORDER BY created DESC LIMIT 1").get(j.id,j.owner,filters,j.revision);
  if(existing)return res.status(202).json(existing);
  if(store.prepare("SELECT COUNT(*) n FROM bulk_exports WHERE owner=? AND state IN ('pending','running')").get(j.owner).n>=2)throw bad('Há duas planilhas em preparação. Aguarde uma delas terminar.',409);
  const id=crypto.randomUUID(),at=Date.now();store.prepare('INSERT INTO bulk_exports(id,job,owner,created,updated,revision,filters) VALUES(?,?,?,?,?,?,?)').run(id,j.id,j.owner,at,at,j.revision,filters);res.status(202).json({id,state:'pending'});tickExports();
 }));
 app.get('/api/bulk/exports/:id',requirePremium,handle((req,res)=>{const item=store.prepare('SELECT id,job,state,created,updated,error,revision FROM bulk_exports WHERE id=? AND owner=?').get(req.params.id,req.user.sub);if(!item)throw bad('Exportação não encontrada.',404);res.json(item);}));
 app.get('/api/bulk/exports/:id/download',requirePremium,handle((req,res)=>{
  const item=store.prepare('SELECT * FROM bulk_exports WHERE id=? AND owner=?').get(req.params.id,req.user.sub);if(!item||item.state!=='complete')throw bad('Planilha ainda não disponível.',404);
  const file=path.resolve(outputDir,item.id+'.xlsx');if(path.dirname(file)!==path.resolve(outputDir)||!fs.existsSync(file))throw bad('Planilha não encontrada.',404);
  res.set('Content-Encoding','identity');res.download(file,'ThreatSumm4ry_Enriquecimento_'+new Date(item.created).toISOString().slice(0,10)+'.xlsx',{dotfiles:'allow'});
 }));
 function tickExports(){if(exportWorker||!started)return;
  store.prepare("UPDATE bulk_exports SET state='pending' WHERE state='running' AND updated<?").run(Date.now()-5*60000);
  const item=store.prepare("SELECT * FROM bulk_exports WHERE state='pending' ORDER BY created LIMIT 1").get();if(!item)return;
  store.prepare("UPDATE bulk_exports SET state='running',updated=? WHERE id=?").run(Date.now(),item.id);
  const worker=new Worker(new URL('./bulkExportWorker.js',import.meta.url),{workerData:{filePath,exportId:item.id,jobId:item.job,owner:item.owner,outputDir},execArgv:[],resourceLimits:{maxOldGenerationSizeMb:192}});exportWorker=worker;
  let finished=false;const end=(error)=>{if(finished)return;finished=true;store.prepare('UPDATE bulk_exports SET state=?,updated=?,error=? WHERE id=?').run(error?'error':'complete',Date.now(),error?'Não foi possível gerar a planilha. As respostas do lote foram preservadas.':null,item.id);};
  worker.on('message',message=>{if(message.progress){store.prepare('UPDATE bulk_exports SET updated=? WHERE id=?').run(Date.now(),item.id);return;}if(message.done&&Number.isInteger(message.revision))store.prepare('UPDATE bulk_exports SET revision=? WHERE id=?').run(message.revision,item.id);end(message.error);});
  worker.on('error',()=>end('Falha no gerador'));worker.on('exit',code=>{if(!finished)end(code?'Falha no gerador':'Gerador interrompido');exportWorker=null;});
 }
 return{store,runner,start(){if(started)return;started=true;for(const job of store.prepare("SELECT id,owner,login FROM bulk_jobs WHERE state IN ('active','paused')").all())store.ensureSources(job.owner,job.id,requiredSources({sub:job.owner,login:job.login}));runner.start();exportTimer=setInterval(tickExports,2000);exportTimer.unref();tickExports();},async close(){started=false;clearInterval(exportTimer);await runner.stop();if(exportWorker)await exportWorker.terminate();store.close();}};
}
