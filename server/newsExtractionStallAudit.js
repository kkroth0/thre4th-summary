// Bounded isolated replay of recently collected public bodies and headlines.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
const root=path.resolve(process.argv[2]||process.cwd());
const read=file=>{try{return JSON.parse(fs.readFileSync(file,'utf8'));}catch{return null;}};
const digest=value=>createHash('sha256').update(value).digest('hex');
const directory=kind=>path.join(root,'server/.feed-cache',kind);
const files=kind=>fs.readdirSync(directory(kind)).filter(file=>/^[a-f0-9]{64}\.json$/.test(file));
const raw=new Map();
for(const file of files('rss').filter(file=>file!==digest('newsletter:snapshot')+'.json'))for(const item of read(path.join(directory('rss'),file))?.items||[])if(item.link)raw.set(item.link,item);
const bodies=files('articles').map(file=>({file,time:fs.statSync(path.join(directory('articles'),file)).mtimeMs})).sort((a,b)=>b.time-a.time).slice(0,40).map(row=>read(path.join(directory('articles'),row.file))).filter(row=>row?.text&&raw.has(row.link));
const selected=new Map(bodies.map(body=>[body.link,{item:raw.get(body.link),bodyText:body.text,supplementalIocs:body.supplementalIocs}]));
for(const item of [...raw.values()].sort((a,b)=>String(b.pubDate).localeCompare(String(a.pubDate))).slice(0,30))if(!selected.has(item.link))selected.set(item.link,{item,bodyText:''});
const child=`import fs from 'node:fs';import path from 'node:path';import{pathToFileURL}from'node:url';const root=process.argv[1];const load=name=>import(pathToFileURL(path.join(root,'server',name)));const input=JSON.parse(fs.readFileSync(0,'utf8'));const {enrichFeedItems}=await load('feedEnrichment.js');const{createFeedExtractionCache}=await load('feedExtractionCache.js');const{buildActorIndex,matchActors}=await load('actorMatch.js');const{buildMalwareIndex,matchMalware}=await load('malwareMatch.js');const{buildCampaignIndex,matchCampaigns}=await load('campaignMatch.js');const{categorize}=await load('newsCategories.js');const{extractSellerHandle}=await load('darkWebHandle.js');const catalog=(name,key)=>{const data=JSON.parse(fs.readFileSync(path.join(root,'server/data',name)));return Array.isArray(data)?data:data[key];};const actors=buildActorIndex(catalog('actors.json','actors')),malware=buildMalwareIndex(catalog('malware.json','malware')),campaigns=buildCampaignIndex(catalog('campaigns.json','campaigns'));const mark=name=>process.stderr.write(name+'\\n');mark('start');const rows=enrichFeedItems([input.item],{texts:new Map([[input.item.link,input.bodyText]]),supplementalIocs:new Map([[input.item.link,input.supplementalIocs]]),actors:text=>{mark('actors');return matchActors(text,actors);},malware:text=>{mark('malware');return matchMalware(text,malware,{news:true});},campaigns:text=>{mark('campaigns');return matchCampaigns(text,campaigns);},seller:text=>{mark('seller');return extractSellerHandle(text);},categorize:item=>{mark('categorize');return categorize(item);},extractionCache:createFeedExtractionCache(),catalogRevision:'audit'});mark('done');process.stdout.write(JSON.stringify({rows:rows.length}));`;
const results=[],started=Date.now();
for(const input of selected.values()){
    if(Date.now()-started>110000)break;
    const at=Date.now(),result=spawnSync(process.execPath,['--input-type=module','-e',child,root],{input:JSON.stringify(input),encoding:'utf8',timeout:2500,maxBuffer:1024*1024});
    results.push({linkHash:digest(input.item.link),title:input.item.title,bodyChars:input.bodyText.length,textChars:(input.item.text||'').length,elapsedMs:Date.now()-at,status:result.status,code:result.error?.code||null,phase:result.stderr?.trim().split('\n').at(-1)});
}
console.log(JSON.stringify({readOnly:true,at:new Date().toISOString(),sampled:results.length,selected:selected.size,elapsedMs:Date.now()-started,timeouts:results.filter(row=>row.code==='ETIMEDOUT'),slowest:results.sort((a,b)=>b.elapsedMs-a.elapsedMs).slice(0,8)},null,2));
