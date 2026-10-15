// Lightweight read-only cycle diagnostics; deliberately avoids full snapshots.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
const root = path.resolve(process.argv[2] || process.cwd()), service = process.argv[3];
const { default: Database } = await import(pathToFileURL(path.join(root, 'server/node_modules/better-sqlite3/lib/index.js')));
const report = { readOnly: true, lightweight: true, at: new Date().toISOString() };
const db = new Database(path.join(root, 'server/.ioc-intelligence.sqlite'), { readonly: true, fileMustExist: true });
db.pragma('query_only=ON');
report.cycles = db.prepare('SELECT at,status,payload FROM phishing_collection_cycles ORDER BY at DESC LIMIT 3').all().map(row => {
    const value = JSON.parse(row.payload);
    return { at: row.at, status: row.status, elapsedMs: value.elapsedMs, stages: value.stages, extraction: value.extraction, bodies: value.bodies };
});
report.generation = JSON.parse(db.prepare("SELECT payload FROM news_storage_state WHERE id='primary'").get()?.payload || 'null')?.generation;
report.currentCycle = JSON.parse(db.prepare("SELECT value FROM intelligence_state WHERE id='news-current-cycle'").get()?.value || 'null');
report.versionRepair = JSON.parse(db.prepare("SELECT value FROM intelligence_state WHERE id='news-version-lists-v1'").get()?.value || 'null');
report.versionSamples = db.prepare("SELECT payload FROM news_documents WHERE kind='archive' AND payload LIKE '%25.1.2.2%'").all().map(row=>JSON.parse(row.payload)).reduce((counts,row)=>{
    counts.publications++;
    counts.retainedIpMentions+=(row.iocs?.ips||[]).filter(ip=>['25.1.2.2','25.1.1.1','25.1.3.0','25.1.1.2','25.1.3.1'].includes(ip)).length;
    counts.realIpMentions+=(row.iocs?.ips||[]).filter(ip=>ip==='108.165.147.64').length;
    return counts;
},{publications:0,retainedIpMentions:0,realIpMentions:0});
report.c2Agent = db.prepare("SELECT kind,payload FROM news_documents WHERE payload LIKE '%C2Agent%'").all().flatMap(row=>{
    const value=JSON.parse(row.payload);
    const sources=row.kind==='archive'?[value]:(value.sources||[]);
    return sources.filter(source=>source.repository?.repo?.includes('Unit42')&&/C2Agent/i.test(source.title||'')).map(source=>({kind:row.kind,hashes:source.iocs?.hashes?.length||0}));
});
report.c2AgentInventory = db.prepare("SELECT COUNT(DISTINCT o.indicator) hashes FROM observations o JOIN entity_links e ON e.observation=o.id JOIN indicators i ON i.id=o.indicator WHERE o.scope='global' AND e.kind='malware' AND e.name='C2Agent' AND i.type='hash'").get();
const {isSoftwareVersionAt}=await import(pathToFileURL(path.join(root,'server/ctiIntel.js')));
report.versionContexts=db.prepare("SELECT id,payload FROM news_documents WHERE kind='archive' AND payload LIKE '%25.1.2.2%'").all().map(record=>{
    const row=JSON.parse(record.payload);
    const saved=db.prepare('SELECT payload FROM news_body_versions WHERE link=? ORDER BY collected DESC,rowid DESC LIMIT 1').get(record.id);
    const body=saved?JSON.parse(saved.payload).text||'':'';
    const text=[row.title,row.text||row.description,body].filter(Boolean).join('\n');
    return {source:row.source,title:row.title,ips:row.iocs?.ips||[],matches:[...text.matchAll(/\b25\.1\.(?:1\.[12]|2\.2|3\.[01])\b/g)].filter(match=>!isSoftwareVersionAt(text,match.index,match[0])).slice(0,20).map(match=>({value:match[0],context:text.slice(Math.max(0,match.index-140),match.index+80)}))};
});
db.close();
report.code = Object.fromEntries(['feedEnrichment.js','feedExtractionCache.js'].map(name => [name,createHash('sha256').update(fs.readFileSync(path.join(root,'server',name))).digest('hex')]));
try {
    const data=JSON.parse(fs.readFileSync(path.join(root,'server/.cti-fyi.json'),'utf8'));
    const names=(data.groups||[]).flatMap(row=>[row.name,...(row.aliases||[])]).filter(value=>typeof value==='string');
    report.ctiActorCatalog={groups:data.groups?.length,groupsAt:data.groupsAt,aliases:names.length,maxWords:Math.max(0,...names.map(name=>name.trim().split(/\s+/).length)),maxChars:Math.max(0,...names.map(name=>name.length))};
}catch{report.ctiActorCatalog={unavailable:true};}
report.processes = execFileSync('ps',['-eo','pid=,ppid=,pcpu=,rss=,comm=,wchan='],{encoding:'utf8',timeout:10000}).trim().split('\n').flatMap(line=>{
    const [pid,ppid,cpu,rss,command,wait]=line.trim().split(/\s+/);
    return /^(node|npm|nodejs)/.test(command)?[{pid:Number(pid),ppid:Number(ppid),cpu:Number(cpu),rssKiB:Number(rss),command,wait}]:[];
});
report.diskCaches = Object.fromEntries(['rss','articles'].map(kind=>{
    const times=fs.readdirSync(path.join(root,'server/.feed-cache',kind)).filter(file=>/^[a-f0-9]{64}\.json$/.test(file)).map(file=>fs.statSync(path.join(root,'server/.feed-cache',kind,file)).mtimeMs);
    return [kind,{files:times.length,updatedLast5m:times.filter(time=>Date.now()-time<300000).length,latest:new Date(Math.max(...times)).toISOString()}];
}));
if (service) {
    try {
        const state = execFileSync('systemctl', ['show', service, '--property=ActiveState,ExecMainStartTimestamp'], { encoding: 'utf8', timeout: 10000, stdio: ['ignore','pipe','ignore'] });
        report.service = Object.fromEntries(state.trim().split('\n').map(line => {const i=line.indexOf('=');return [line.slice(0,i),line.slice(i+1)];}));
        const lines = execFileSync('journalctl', ['-u',service,'--since','30 minutes ago','--grep','\\[feed\\] cycle|Failed to background refresh newsletter feeds:|Server running on port|news evidence review failed:', '-n','30','-o','json','--no-pager'], {encoding:'utf8',timeout:20000,maxBuffer:1024*1024,stdio:['ignore','pipe','ignore']}).trim().split('\n').filter(Boolean).map(line=>JSON.parse(line));
        report.completed = lines.filter(row=>row.MESSAGE.includes('[feed] cycle ')).flatMap(row=>{try{
            const value=JSON.parse(row.MESSAGE.slice(row.MESSAGE.indexOf('[feed] cycle ')+13));
            return [{at:new Date(Number(row.__REALTIME_TIMESTAMP)/1000).toISOString(),elapsedMs:value.elapsedMs,stages:value.stages,extraction:value.extraction,correlationMs:value.correlation?.elapsedMs,publications:value.correlation?.publications}];
        }catch{return [];}});
        report.failures=lines.filter(row=>/Failed to background refresh newsletter feeds:|news evidence review failed:/.test(row.MESSAGE)).length;
    } catch(error) { report.diagnosticUnavailable={code:error.code||null,status:error.status||null,signal:error.signal||null}; }
}
console.log(JSON.stringify(report,null,2));
