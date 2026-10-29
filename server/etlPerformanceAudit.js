// Recover the user's already-requested failed export. Source/IOC/task tables remain read-only.
// The detached child writes only this account's existing export row and private workbook files.
import fs from 'node:fs';import path from 'node:path';import {pathToFileURL} from 'node:url';import {spawn} from 'node:child_process';
const root=path.resolve(process.argv[2]),login=String(process.argv[3]).toLowerCase();if(!/^[a-z0-9-]{1,39}$/.test(login))throw Error('Invalid account');
const users=JSON.parse(fs.readFileSync(path.join(root,'server/.users.json'),'utf8')),owner=Object.keys(users).find(id=>users[id].login?.toLowerCase()===login);if(!owner)throw Error('Account unavailable');
const {parse}=await import(pathToFileURL(path.join(root,'server/node_modules/dotenv/lib/main.js'))),env=parse(fs.readFileSync(path.join(root,'.env'))),{default:Database}=await import(pathToFileURL(path.join(root,'server/node_modules/better-sqlite3/lib/index.js')));
const filePath=env.BULK_JOBS_PATH||path.join(root,'server/.bulk-enrichment.sqlite'),db=new Database(filePath,{fileMustExist:true});db.pragma('busy_timeout=1000');
const id='d283dbb8-fe6b-4d96-886b-fd6641276f2f',item=db.prepare('SELECT id,job,state,filters FROM bulk_exports WHERE id=? AND owner=?').get(id,owner);
if(!item||item.state!=='error')throw Error('The requested failed export is unavailable for recovery');
const filters=JSON.parse(item.filters||'{}');if(filters.waitForComplete||filters.type&&filters.type!=='all'||filters.state&&filters.state!=='all'||filters.query)throw Error('Unexpected export scope');
if(db.prepare('SELECT COUNT(*) n FROM bulk_items WHERE job=?').get(item.job).n!==5614)throw Error('Unexpected batch count');
const dir=env.BULK_EXPORTS_PATH||path.join(root,'server/.bulk-exports'),workerPath=path.join(dir,id+'.recovery-worker.mjs'),runnerPath=path.join(dir,id+'.recovery-runner.mjs');
let source=fs.readFileSync(path.join(root,'server/bulkExportWorker.js'),'utf8').replace(/from '\.\/([^']+)'/g,(_,name)=>`from '${pathToFileURL(path.join(root,'server',name)).href}'`);
source=source.replace('let spoolStream,sequence=0,localSnapshot;','let spoolStream,sequence=0,localSnapshot,phase="initial",lastOrdinal=null;');
source=source.replace('const row=exportRowFor(job,item),a=analyzeBulkRow(row);','lastOrdinal=item.ordinal;const row=exportRowFor(job,item),a=analyzeBulkRow(row);');
for(const [anchor,phase]of [['for(const item of store.items','analysis'],['lean.sort(','aggregate'],['const wb=new ExcelJS','dashboard'],["spoolStream=fs.createWriteStream",'analytical'],["let table=rawTable(wb,'Fontes'",'sources'],["table=rawTable(wb,'Publicações'",'publications'],["table=rawTable(wb,'Evidências'",'evidence'],["table=rawTable(wb,'Relações'",'relations'],['await wb.commit();','commit'],['const bytes=await fsp.readFile(tmp)','charts']])source=source.replace(anchor,`phase=${JSON.stringify(phase)};parentPort.postMessage({progress:1,phase});${anchor}`);
source=source.replace("parentPort.postMessage({error:error?.message||'Falha ao gerar a planilha.'});","parentPort.postMessage({error:error?.message||'Falha ao gerar a planilha.',phase,lastOrdinal,name:error?.name,code:error?.code,stack:String(error?.stack).split('\\n').slice(1,6)});");
fs.writeFileSync(workerPath,source,{mode:0o600});
const data={root,filePath,exportId:id,jobId:item.job,owner,outputDir:dir,intelligencePath:env.IOC_INTELLIGENCE_PATH||path.join(root,'server/.ioc-intelligence.sqlite'),workerPath};
const runner=`import fs from 'node:fs';import path from 'node:path';import {Worker} from 'node:worker_threads';import {pathToFileURL} from 'node:url';
const data=${JSON.stringify(data)},Database=(await import(pathToFileURL(path.join(data.root,'server/node_modules/better-sqlite3/lib/index.js')))).default,db=new Database(data.filePath);db.pragma('busy_timeout=3000');
const diag=path.join(data.outputDir,data.exportId+'.recovery-status.json');let phase='initial',finished=false;const report=value=>fs.writeFileSync(diag,JSON.stringify({at:new Date().toISOString(),exportId:data.exportId,phase,...value}),{mode:0o600});
const worker=new Worker(pathToFileURL(data.workerPath),{workerData:data,resourceLimits:{maxOldGenerationSizeMb:192},execArgv:[]});
const heartbeat=setInterval(()=>{if(!finished){db.prepare("UPDATE bulk_exports SET updated=? WHERE id=? AND owner=? AND state='running'").run(Date.now(),data.exportId,data.owner);report({state:'running'});}},15000);
const finish=(error,message={})=>{if(finished)return;finished=true;clearInterval(heartbeat);if(!error&&message.summary?.total!==5614)error='Unexpected workbook count';
 if(error){const safe=String(error).replaceAll(data.root,'<app>').replace(/https?:\\/\\/\\S+/g,'[url]').replace(/\\b[a-f0-9]{32,}\\b/gi,'[redacted]');report({state:'error',name:message.name,code:message.code,error:safe,lastOrdinal:message.lastOrdinal,stack:message.stack?.map(line=>line.replaceAll(data.root,'<app>'))});db.prepare("UPDATE bulk_exports SET state='error',updated=?,error=? WHERE id=? AND owner=?").run(Date.now(),'Não foi possível gerar a planilha. As respostas do lote foram preservadas.',data.exportId,data.owner);}
 else{db.prepare("UPDATE bulk_exports SET state='complete',updated=?,error=NULL,revision=?,summary=? WHERE id=? AND owner=?").run(Date.now(),message.revision,JSON.stringify(message.summary),data.exportId,data.owner);report({state:'complete',summary:message.summary});}db.close();};
worker.on('message',message=>{if(message.phase)phase=message.phase;if(message.progress){report({state:'running',progress:message.progress});return;}if(message.done)finish(null,message);else if(message.error)finish(message.error,message);});worker.on('error',error=>finish(error.message,{name:error.name,code:error.code}));worker.on('exit',code=>{if(!finished)finish('Worker exited before completion: '+code);});
`;
fs.writeFileSync(runnerPath,runner,{mode:0o600});
const changed=db.prepare("UPDATE bulk_exports SET state='running',updated=?,error=NULL WHERE id=? AND owner=? AND state='error'").run(Date.now(),id,owner).changes;if(changed!==1)throw Error('Export state changed before recovery');db.close();
const log=fs.openSync(path.join(dir,id+'.recovery.log'),'a',0o600),child=spawn(process.execPath,[runnerPath],{detached:true,stdio:['ignore',log,log]});child.unref();fs.closeSync(log);
console.log(JSON.stringify({readOnly:false,sourceDataUnchanged:true,recoveredExport:id,state:'running',pid:child.pid,indicators:5614,externalRequests:0}));
