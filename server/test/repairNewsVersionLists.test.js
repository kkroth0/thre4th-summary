import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import { createIocIntelligence } from '../iocIntelligence.js';
import { createNewsPersistence } from '../newsPersistence.js';
import { createSqliteNewsStores } from '../sqliteNewsStores.js';
import { createNewsArchiveStore } from '../newsArchiveStore.js';
import { createStoryStore } from '../newsStoryStore.js';
import { publishNewsSnapshot } from '../publishNewsSnapshot.js';
import { mergeIntoStories } from '../newsStories.js';
import { repairNewsVersionLists } from '../repairNewsVersionLists.js';

const now=new Date('2026-10-15T12:00:00Z');
const stores=(persistence,rows=[],events=[])=>createSqliteNewsStores({persistence,
  archive:createNewsArchiveStore({initialRows:rows,writeJsonAtomic:()=>{}}),
  stories:createStoryStore({initialRows:events,writeJsonAtomic:()=>{}}),
});
const row=(id,extra={})=>({link:'https://lab.example/'+id,title:'Ivanti software security report '+id,description:'Affected versions 25.1.1.1 and prior, 25.1.2.2 and prior. C2 IP: 108.165.147.64',
  pubDate:now.toISOString(),cves:['CVE-2026-104935'],actors:[],malware:[],campaigns:[],
  iocs:{ips:['25.1.1.1','25.1.2.2','108.165.147.64'],hashes:Array.from({length:32},(_,index)=>index.toString(16).padStart(64,'a'))},...extra});

test('repair persists archive/event corrections, all 32 hashes, old links and independent private API evidence',async()=>{
  const inventory=createIocIntelligence(),news=stores(inventory.news);
  await publishNewsSnapshot([row('a'),row('b')],{...news,now});
  const id=news.stories.all()[0].id;
  await inventory.ingestNews(news.archive.all());
  await inventory.ingest([{value:'25.1.2.2',scope:'owner-one',provider:'OTX',externalId:'independent'}]);
  const result=await repairNewsVersionLists({...news,now});
  await inventory.ingestNews(news.archive.all());
  assert.equal(result.changedPublications,2);assert.equal(result.retiredMentions,4);
  for(const publication of news.archive.all()){assert.deepEqual(publication.iocs.ips,['108.165.147.64']);assert.equal(publication.iocs.hashes.length,32);}
  assert.ok(news.stories.get(id));assert.ok(news.stories.all().flatMap(story=>story.sources).every(source=>source.iocs.ips.length===1&&source.iocs.hashes.length===32));
  assert.equal(inventory.detail('25.1.1.1'),null);assert.equal(inventory.detail('25.1.2.2','owner-two'),null);
  assert.deepEqual(inventory.detail('25.1.2.2','owner-one').evidence.map(item=>item.provider),['OTX']);
  assert.equal(inventory.detail('108.165.147.64').total,2);
  // A crash between the snapshot commit and inventory replacement can be
  // retried by replaying the canonical archive; no retired news link returns.
  assert.equal((await repairNewsVersionLists({...news,now})).retiredMentions,0);
  await inventory.ingestNews(news.archive.all());assert.equal(inventory.detail('25.1.1.1'),null);
  assert.equal(inventory.news.compare(news.archive.all(),news.stories.all()).readyForReadPilot,true);
  inventory.close();
});

test('correcting a legacy aggregate can split it without losing aliases, source-only hashes or real repeated IPs',async()=>{
  const first=row('one',{title:'First unrelated security investigation',cves:[]});
  const second=row('two',{title:'Different security bulletin',cves:[],description:'Version 25.1.1.1 is affected. Separately IOC: 25.1.2.2:443',iocs:{ips:['25.1.1.1','25.1.2.2'],hashes:['f'.repeat(64)]}});
  const [a]=mergeIntoStories([],[first],now),[b]=mergeIntoStories([],[second],now);
  const legacy={...a,aliases:[b.id,'old-aggregate'],sources:[...a.sources,...b.sources]};
  legacy.sources[0].iocs={...legacy.sources[0].iocs,hashes:[...first.iocs.hashes,'e'.repeat(64)]};
  const db=new Database(':memory:'),persistence=createNewsPersistence(db),news=stores(persistence,[{...first,storyId:a.id},{...second,storyId:a.id}],[legacy]);
  await repairNewsVersionLists({...news,now});
  assert.equal(news.stories.all().length,2);assert.ok(news.stories.get('old-aggregate'));
  assert.equal(news.stories.get(a.id).sources[0].iocs.hashes.length,33);
  assert.deepEqual(news.archive.all().find(item=>item.link===second.link).iocs.ips,['25.1.2.2']);
  for(const publication of news.archive.all())assert.ok(news.stories.get(publication.storyId).sources.some(source=>source.link===publication.link));
  assert.equal(persistence.compare(news.archive.all(),news.stories.all()).readyForReadPilot,true);db.close();
});

test('a failed SQLite story update rolls back archive corrections and can be retried',async()=>{
  const db=new Database(':memory:'),persistence=createNewsPersistence(db),news=stores(persistence);
  await publishNewsSnapshot([row('a')],{...news,now});const before=persistence.readSnapshot();
  db.exec("CREATE TRIGGER reject_version_repair BEFORE INSERT ON news_documents WHEN NEW.kind='stories' BEGIN SELECT RAISE(ABORT,'simulated failure'); END");
  await assert.rejects(repairNewsVersionLists({...news,now}),/simulated failure/);
  assert.deepEqual(persistence.readSnapshot(),before);
  db.exec('DROP TRIGGER reject_version_repair');await repairNewsVersionLists({...news,now});
  assert.deepEqual(news.archive.all()[0].iocs.ips,['108.165.147.64']);db.close();
});
