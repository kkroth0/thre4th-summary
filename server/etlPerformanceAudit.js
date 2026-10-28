// Read-only export progress. No indicator values, source payloads or credentials.
import fs from 'node:fs';import path from 'node:path';import {pathToFileURL} from 'node:url';
const root=path.resolve(process.argv[2]),login=String(process.argv[3]).toLowerCase();
if(!/^[a-z0-9-]{1,39}$/.test(login))throw Error('Invalid account');
const users=JSON.parse(fs.readFileSync(path.join(root,'server/.users.json'),'utf8')),owner=Object.keys(users).find(id=>users[id].login?.toLowerCase()===login);if(!owner)throw Error('Account unavailable');
const {parse}=await import(pathToFileURL(path.join(root,'server/node_modules/dotenv/lib/main.js'))),env=parse(fs.readFileSync(path.join(root,'.env')));
const {default:Database}=await import(pathToFileURL(path.join(root,'server/node_modules/better-sqlite3/lib/index.js')));
const db=new Database(env.BULK_JOBS_PATH||path.join(root,'server/.bulk-enrichment.sqlite'),{readonly:true,fileMustExist:true});db.pragma('query_only=ON');db.pragma('busy_timeout=1000');
const item=db.prepare('SELECT id,job,file,state,created,updated,error,summary FROM bulk_exports WHERE owner=? ORDER BY created DESC LIMIT 1').get(owner);if(!item)throw Error('No export');
const folder=env.BULK_EXPORTS_PATH||path.join(root,'server/.bulk-exports'),files=[];
for(const name of fs.readdirSync(folder).filter(name=>name.startsWith(item.id+'.'))){const file=path.join(folder,name),stat=fs.statSync(file),value={part:name.slice(item.id.length+1),bytes:stat.size,updatedAt:stat.mtime.toISOString()};if(name.includes('.context.')){let cache;try{cache=new Database(file,{readonly:true,fileMustExist:true});cache.pragma('busy_timeout=100');value.localContexts=cache.prepare('SELECT COUNT(*) n FROM contexts').get().n;}catch{value.localContexts='busy';}finally{cache?.close();}}files.push(value);}
const sources=db.prepare("SELECT provider,SUM(state='done') completed,SUM(state='error') errors,SUM(state='blocked') blocked,SUM(state IN ('pending','waiting','running')) pending,COUNT(*) total FROM bulk_tasks WHERE job=? GROUP BY provider").all(item.job);
const sourceErrors=db.prepare("SELECT provider,http_status,error_code,COUNT(*) count FROM bulk_tasks WHERE job=? AND state IN ('blocked','error') GROUP BY provider,http_status,error_code").all(item.job);
const checks={};
const finalFile=path.join(folder,item.id+'.xlsx');
if(item.state==='complete'&&fs.existsSync(finalFile)){
 const {createRequire}=await import('node:module'),require=createRequire(path.join(root,'server/package.json')),unzipper=require('unzipper');
 const zip=await unzipper.Open.file(finalFile);checks.charts=zip.files.filter(f=>/(?:^|\/)charts\/chart\d+\.xml$/.test(f.path)).length;checks.sheets=[];
 const workbook=(await zip.files.find(f=>f.path==='xl/workbook.xml').buffer()).toString(),names=[...workbook.matchAll(/<sheet\b[^>]*\bname="([^"]+)"/g)].map(m=>m[1]);
 const sheets=zip.files.filter(f=>/^xl\/worksheets\/sheet\d+\.xml$/.test(f.path)).sort((a,b)=>Number(a.path.match(/sheet(\d+)/)[1])-Number(b.path.match(/sheet(\d+)/)[1]));
 for(const [i,f]of sheets.entries()){let rows=0,errors=0,carry='';for await(const chunk of f.stream()){const data=carry+chunk.toString();const end=data.lastIndexOf('>')+1,part=data.slice(0,end);rows+=(part.match(/<row\b/g)||[]).length;errors+=(part.match(/<c\b[^>]*\bt="e"/g)||[]).length;carry=data.slice(end);}checks.sheets.push({name:names[i],rows,formulaErrors:errors});}
}
console.log(JSON.stringify({at:new Date().toISOString(),readOnly:true,state:item.state,created:new Date(item.created).toISOString(),updated:new Date(item.updated).toISOString(),error:item.error,summary:item.summary?JSON.parse(item.summary):null,sources,sourceErrors,files,checks},null,2));db.close();
