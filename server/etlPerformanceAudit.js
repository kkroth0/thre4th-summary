// Read-only export diagnostics. Emits counts and reason codes, never IOC values.
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const root=path.resolve(process.argv[2]),login=String(process.argv[3]).toLowerCase();
if(!/^[a-z0-9-]{1,39}$/.test(login))throw Error('Invalid account');
const users=JSON.parse(fs.readFileSync(path.join(root,'server/.users.json'),'utf8')),owner=Object.keys(users).find(id=>users[id].login?.toLowerCase()===login);
if(!owner)throw Error('Account unavailable');
const {parse}=await import(pathToFileURL(path.join(root,'server/node_modules/dotenv/lib/main.js'))),env=parse(fs.readFileSync(path.join(root,'.env')));
const {default:Database}=await import(pathToFileURL(path.join(root,'server/node_modules/better-sqlite3/lib/index.js'))),{normalizeIndicator}=await import(pathToFileURL(path.join(root,'server/indicatorIdentity.js')));
const db=new Database(env.BULK_JOBS_PATH||path.join(root,'server/.bulk-enrichment.sqlite'),{readonly:true,fileMustExist:true});db.pragma('query_only=ON');db.pragma('busy_timeout=1000');
const item=db.prepare('SELECT id,job,state,created,updated,error,summary FROM bulk_exports WHERE owner=? ORDER BY created DESC LIMIT 1').get(owner);
const rows=db.prepare('SELECT ordinal,query,kind,state FROM bulk_items WHERE job=? ORDER BY ordinal').all(item.job);
const invalid=[];for(const row of rows)if(!normalizeIndicator(row.query))invalid.push({ordinal:row.ordinal,kind:row.kind,state:row.state});
const folder=env.BULK_EXPORTS_PATH||path.join(root,'server/.bulk-exports'),files=fs.readdirSync(folder).filter(name=>name.startsWith(item.id+'.')).map(name=>{const stat=fs.statSync(path.join(folder,name));return{part:name.slice(item.id.length+1),bytes:stat.size};});
console.log(JSON.stringify({readOnly:true,at:new Date().toISOString(),export:item,indicators:rows.length,invalidIdentityCount:invalid.length,invalidOrdinals:invalid,files}));db.close();
