// Read only this account's workbook-repair status; no source requests or IOC values.
import fs from 'node:fs';import path from 'node:path';import crypto from 'node:crypto';import {createRequire} from 'node:module';
const root=path.resolve(process.argv[2]),login=String(process.argv[3]).toLowerCase();if(!/^[a-z0-9-]{1,39}$/.test(login))throw Error('Invalid account');
const users=JSON.parse(fs.readFileSync(path.join(root,'server/.users.json'),'utf8')),owner=Object.keys(users).find(id=>users[id].login?.toLowerCase()===login);if(!owner)throw Error('Account unavailable');
const require=createRequire(path.join(root,'server/package.json')),env=require('dotenv').parse(fs.readFileSync(path.join(root,'.env'))),Database=require('better-sqlite3'),db=new Database(env.BULK_JOBS_PATH||path.join(root,'server/.bulk-enrichment.sqlite'),{readonly:true,fileMustExist:true});db.pragma('busy_timeout=1000');
const id='d283dbb8-fe6b-4d96-886b-fd6641276f2f',item=db.prepare('SELECT state,updated,error,summary FROM bulk_exports WHERE id=? AND owner=?').get(id,owner);if(!item)throw Error('Workbook unavailable');db.close();
const folder=path.resolve(env.BULK_EXPORTS_PATH||path.join(root,'server/.bulk-exports'));
const file=part=>path.join(folder,id+'.'+part),status=fs.existsSync(file('hyperlink-repair-status.json'))?JSON.parse(fs.readFileSync(file('hyperlink-repair-status.json'),'utf8')):null;
let running=false;if(status?.pid)try{process.kill(status.pid,0);running=true;}catch{}
const log=fs.existsSync(file('hyperlink-repair.log'))?fs.readFileSync(file('hyperlink-repair.log'),'utf8').trim().split('\n').filter(line=>line.startsWith('{')).slice(-3).map(line=>{try{return JSON.parse(line);}catch{return{invalidLogLine:true};}}):[];
const validation=fs.existsSync(file('hyperlink-validation.json'))?JSON.parse(fs.readFileSync(file('hyperlink-validation.json'),'utf8')):null;
const files=['xlsx','hyperlink-repair.tmp.xlsx'].filter(part=>fs.existsSync(file(part))).map(part=>{const s=fs.statSync(file(part));return{part,bytes:s.size,updated:s.mtime.toISOString()};});
const runtime=['bulkExportWorker.js','bulkRawTable.js'].map(name=>{const file=path.join(root,'server',name);return{name,present:fs.existsSync(file),sha256:fs.existsSync(file)?crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'):null};});
console.log(JSON.stringify({readOnly:true,providerRequests:0,at:new Date().toISOString(),export:{...item,summary:JSON.parse(item.summary||'{}')},status,running,progress:log,validation,files,runtime},null,2));
