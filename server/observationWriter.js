import crypto from 'node:crypto';
import { normalizeIndicator } from './indicatorIdentity.js';
const idFor = value => crypto.createHash('sha256').update(value).digest('hex');
export function createObservationWriter(db, news, now = () => Date.now()) {
  const putIoc=db.prepare('INSERT OR IGNORE INTO indicators VALUES(?,?,?)');
  const putObservation=db.prepare('INSERT INTO observations VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET published=excluded.published,collected=excluded.collected,details=excluded.details');
  const clearLinks=db.prepare('DELETE FROM entity_links WHERE observation=?');
  const putLink=db.prepare('INSERT OR REPLACE INTO entity_links VALUES(?,?,?,?,?)');
  return db.transaction(rows=>{
    const names = new Map();
    for(const row of rows) {
      const indicator=normalizeIndicator(row.value,row.type);if(!indicator)continue;
      const scope=String(row.scope||'global'),provider=String(row.provider||'news');
      const key=idFor(`${indicator.type}:${indicator.value}`);
      const observation=idFor(JSON.stringify([scope,provider,row.externalId||row.link||indicator.value,key]));
      const published=Number.isFinite(Date.parse(row.published))?new Date(row.published).toISOString():new Date(now()).toISOString();
      putIoc.run(key,indicator.type,indicator.value);
      const details={title:String(row.title||provider).slice(0,300),source:String(row.source||provider).slice(0,200),link:row.link||'',confidence:row.confidence??null,reputation:row.reputation||null,port:row.port||null,storyId:row.storyId||null,tags:(row.tags||[]).slice(0,50),...(row.payload?{payload:row.payload}:{})};
      putObservation.run(observation,key,scope,provider,String(row.externalId||row.link||indicator.value),published,new Date(now()).toISOString(),JSON.stringify(details));
      clearLinks.run(observation);
      for(const kind of ['actor','malware','cve'])for(const entity of row[kind+'s']||[])if(entity?.id&&entity?.name){putLink.run(observation,kind,String(entity.id).slice(0,180),String(entity.name).slice(0,200),row.relation||'mentioned-with');names.set(JSON.stringify([scope,provider,kind,entity.id,entity.name,entity.aliases||[]]),{entity:{...entity,kind},scope,provider});}
    }
    for (const { entity, scope, provider } of names.values()) news.registerEntities([entity], scope, provider);
  });
}
