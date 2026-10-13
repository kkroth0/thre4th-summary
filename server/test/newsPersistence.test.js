import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { publishNewsSnapshot } from '../publishNewsSnapshot.js';
import { persistNewsEvidence } from '../persistNewsEvidence.js';
import { createStoryStore } from '../newsStoryStore.js';
import { createNewsArchiveStore } from '../newsArchiveStore.js';
import { actorPublications, buildActorEvidence } from '../actorEvidence.js';
import { collectArticleTexts } from '../articleCollector.js';
import { enrichFeedItems } from '../feedEnrichment.js';
const now=new Date('2026-10-13T12:00:00Z');
const writeJsonAtomic=(file,value)=>fs.writeFileSync(file,JSON.stringify(value),'utf8');
const row=(extra={})=>({link:'https://lab.example/a',title:'APT42 malware campaign',pubDate:now.toISOString(),source:'Research lab',layer:3,
  actors:[{id:'G1',name:'APT42'}],malware:[],campaigns:[],cves:[],iocs:{ips:['9.9.9.10'],domains:[],hashes:[],urls:[]},...extra});
const memory=()=>{const data=new Map();return {get:key=>data.get(key),set:(key,value)=>data.set(key,value)};};
const stores=()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'news-evidence-test-'));
  const deps={readFileSync:fs.readFileSync,writeJsonAtomic};
  return {dir,archive:createNewsArchiveStore({filePath:path.join(dir,'archive.json'),...deps}),stories:createStoryStore({filePath:path.join(dir,'stories.json'),...deps}),articleCache:memory()};
};

test('historical repository import archives evidence without aborting the live snapshot',async()=>{
  const deps=stores();
  const older=row({link:'https://github.com/wolf/historical',pubDate:'2026-06-01T00:00:00Z',repositoryReport:true});
  const result=await publishNewsSnapshot([row(),older],{...deps,now});
  assert.equal(result.items.length,1);assert.equal(result.items[0].link,row().link);
  assert.equal(deps.archive.size(),2);assert.equal(result.stats.unassigned,0);
  assert.equal(deps.archive.all().find(item=>item.link===older.link).pubDate,older.pubDate);
});

test('manual enrichment persists per-source IOCs through disk reload and actor evidence',async()=>{
  const deps=stores();
  const first=row({text:'Malware evidence '.repeat(200),iocs:{ips:['9.9.9.10'],domains:[],hashes:['a'.repeat(64)],urls:[]}});
  const other=row({link:'https://lab.example/b',title:'Unrelated ransomware research',actors:[{id:'G2',name:'Other actor'}],text:'Second source '.repeat(200),iocs:{ips:['9.9.9.11'],domains:[],hashes:[],urls:[]}});
  await persistNewsEvidence([first,other],{...deps,now,originalFor:()=>({text:'RSS summary'})});
  const archive=createNewsArchiveStore({filePath:path.join(deps.dir,'archive.json'),readFileSync:fs.readFileSync,writeJsonAtomic});
  const stories=createStoryStore({filePath:path.join(deps.dir,'stories.json'),readFileSync:fs.readFileSync,writeJsonAtomic});
  const profile=buildActorEvidence(actorPublications(archive.all(),stories.all()),'G1',{now:now.getTime()});
  assert.deepEqual(profile.counts,{ips:1,domains:0,hashes:1,posts:1});
  assert.ok(!profile.indicators.some(item=>item.value==='9.9.9.11'));
  const body=await collectArticleTexts([{...first,text:'RSS summary'}],{cache:deps.articleCache,now,fetchText:()=>{throw Error('must reuse body');}});
  const [enriched]=enrichFeedItems([{...first,text:'RSS summary'}],{texts:body.texts,supplementalIocs:body.supplementalIocs,actors:()=>first.actors,malware:()=>[],campaigns:()=>[],seller:()=>null,categorize:()=>({categories:['Malware'],primary:'Malware'})});
  assert.ok(enriched.iocs.hashes.includes('a'.repeat(64)),'later feed refresh must retain appendix evidence');
});

test('article body cache retains discovered appendix links for later enrichment',async()=>{
  const cache=memory(); const entry=row({text:'short summary'});
  await collectArticleTexts([entry],{cache,now,fetchText:async()=>({text:'Source text '.repeat(300),artifactLinks:['https://github.com/vendor/reports/blob/main/iocs.csv']})});
  assert.equal(cache.get(entry.link).artifactLinks.length,1);
});
