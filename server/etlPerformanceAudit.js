// Read-only export progress. No indicator values, source payloads or credentials.
import fs from 'node:fs';import path from 'node:path';import {pathToFileURL} from 'node:url';
const root=path.resolve(process.argv[2]),login=String(process.argv[3]).toLowerCase();
if(!/^[a-z0-9-]{1,39}$/.test(login))throw Error('Invalid account');
const users=JSON.parse(fs.readFileSync(path.join(root,'server/.users.json'),'utf8')),owner=Object.keys(users).find(id=>users[id].login?.toLowerCase()===login);if(!owner)throw Error('Account unavailable');
const {parse}=await import(pathToFileURL(path.join(root,'server/node_modules/dotenv/lib/main.js'))),env=parse(fs.readFileSync(path.join(root,'.env')));
const {default:Database}=await import(pathToFileURL(path.join(root,'server/node_modules/better-sqlite3/lib/index.js')));
const db=new Database(env.BULK_JOBS_PATH||path.join(root,'server/.bulk-enrichment.sqlite'),{readonly:true,fileMustExist:true});db.pragma('query_only=ON');db.pragma('busy_timeout=1000');
const item=db.prepare('SELECT id,state,created,updated,error,summary FROM bulk_exports WHERE owner=? ORDER BY created DESC LIMIT 1').get(owner);if(!item)throw Error('No export');
const folder=env.BULK_EXPORTS_PATH||path.join(root,'server/.bulk-exports'),files=[];
for(const name of fs.readdirSync(folder).filter(name=>name.startsWith(item.id+'.'))){const file=path.join(folder,name),stat=fs.statSync(file),value={part:name.slice(item.id.length+1),bytes:stat.size,updatedAt:stat.mtime.toISOString()};if(name.includes('.context.')){let cache;try{cache=new Database(file,{readonly:true,fileMustExist:true});cache.pragma('busy_timeout=100');value.localContexts=cache.prepare('SELECT COUNT(*) n FROM contexts').get().n;}catch{value.localContexts='busy';}finally{cache?.close();}}files.push(value);}
console.log(JSON.stringify({at:new Date().toISOString(),readOnly:true,state:item.state,created:new Date(item.created).toISOString(),updated:new Date(item.updated).toISOString(),error:item.error,summary:item.summary?JSON.parse(item.summary):null,files},null,2));db.close();
