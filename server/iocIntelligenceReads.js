// Shared, read-only queries. Both the synchronous ingestion helpers and the
// isolated HTTP reader use these exact projections and account predicates.
import crypto from 'node:crypto';
export function createIocIntelligenceReads(db, normalizeIndicator) {
  const idFor = value => crypto.createHash('sha256').update(value).digest('hex');
  const scopes=owner=>owner?['global',String(owner)]:['global'];
  const scopeSql=owner=>({sql:owner?'o.scope IN (?,?)':'o.scope=?',args:scopes(owner)});
  const coveringIndex = () => db.prepare("SELECT 1 FROM sqlite_master WHERE type='index' AND name='observations_inventory'").get() ? ' INDEXED BY observations_inventory' : '';
  const actorIndexReady = () => !!db.prepare("SELECT 1 FROM intelligence_state WHERE id='actor-observations-v1'").get();
  function list({owner='',type='',query='',page=1,size=50,actor='',malware=''}={}) {
    size=Math.min(100,Math.max(1,Number(size)||50));page=Math.max(1,Number(page)||1);
    const scope=scopeSql(owner),clauses=[scope.sql],args=[...scope.args];
    const indexed = coveringIndex();
    if (indexed && !type && !query && !actor && !malware) {
      const total = db.prepare(`SELECT COUNT(DISTINCT o.indicator) count FROM observations o${indexed} WHERE ${scope.sql}`).get(...args).count;
      const items = db.prepare(`SELECT i.*,p.lastSeen,p.firstSeen,p.evidenceCount,p.providers FROM
        (SELECT o.indicator,MAX(o.published) lastSeen,MIN(o.published) firstSeen,COUNT(*) evidenceCount,GROUP_CONCAT(DISTINCT o.provider) providers
         FROM observations o${indexed} WHERE ${scope.sql} GROUP BY o.indicator ORDER BY lastSeen DESC,o.indicator LIMIT ? OFFSET ?) p
        JOIN indicators i ON i.id=p.indicator ORDER BY p.lastSeen DESC,i.id`).all(...args,size,(page-1)*size);
      for(const item of items){item.providers=item.providers.split(',');item.entities=db.prepare(`SELECT DISTINCT e.kind,e.entity id,e.name,e.relation FROM entity_links e JOIN observations o ON o.id=e.observation WHERE o.indicator=? AND ${scope.sql} LIMIT 50`).all(item.id,...scope.args);}
      return {total,page,size,items};
    }
    if(type){clauses.push('i.type=?');args.push(type);}
    if(query){clauses.push('i.value LIKE ? ESCAPE \'\\\'');args.push('%'+String(query).slice(0,200).replace(/[\\%_]/g,'\\$&')+'%');}
    for(const [kind,id]of [['actor',actor],['malware',malware]])if(id){clauses.push('EXISTS(SELECT 1 FROM entity_links e WHERE e.observation=o.id AND e.kind=? AND e.entity=?)');args.push(kind,id);}
    const where=clauses.join(' AND '),from=`FROM indicators i JOIN observations o ON o.indicator=i.id WHERE ${where}`;
    const total=db.prepare(`SELECT COUNT(DISTINCT i.id) count ${from}`).get(...args).count;
    const items=db.prepare(`SELECT i.*,MAX(o.published) lastSeen,MIN(o.published) firstSeen,COUNT(*) evidenceCount,GROUP_CONCAT(DISTINCT o.provider) providers ${from} GROUP BY i.id ORDER BY lastSeen DESC,i.id LIMIT ? OFFSET ?`).all(...args,size,(page-1)*size);
    for(const item of items){item.providers=item.providers.split(',');item.entities=db.prepare(`SELECT DISTINCT e.kind,e.entity id,e.name,e.relation FROM entity_links e JOIN observations o ON o.id=e.observation WHERE o.indicator=? AND ${scope.sql} LIMIT 50`).all(item.id,...scope.args);}
    return {total,page,size,items};
  }
  function detail(value,owner='',{offset=0,size=100}={}) {
    const indicator=normalizeIndicator(value);if(!indicator)return null;
    const key=idFor(`${indicator.type}:${indicator.value}`),scope=scopeSql(owner);
    offset=Math.max(0,Number(offset)||0);size=Math.min(100,Math.max(1,Number(size)||100));
    const total=db.prepare(`SELECT COUNT(*) count FROM observations o WHERE o.indicator=? AND ${scope.sql}`).get(key,...scope.args).count;
    if(!total)return null;
    const observations=db.prepare(`SELECT o.* FROM observations o WHERE o.indicator=? AND ${scope.sql} ORDER BY published DESC,id LIMIT ? OFFSET ?`).all(key,...scope.args,size,offset);
    return {...indicator,id:key,total,offset,size,evidence:observations.map(row=>({...JSON.parse(row.details),provider:row.provider,published:row.published,collectedAt:row.collected,entities:db.prepare('SELECT kind,entity id,name,relation FROM entity_links WHERE observation=?').all(row.id)}))};
  }
  function publications({owner='',kind,id,ids}={}){
    const scope=scopeSql(owner),args=[...scope.args],clauses=[scope.sql];
    const matchingIds=ids===undefined?(id?[String(id)]:[]):[...new Set((Array.isArray(ids)?ids:[]).filter(value=>typeof value==='string'&&value.length>0&&value.length<=180))].slice(0,1000);
    if(ids!==undefined&&(!kind||!matchingIds.length))return [];
    // Start with the small set of linked observations instead of probing
    // entity_links once for every IOC imported from large provider catalogs.
    if(kind&&matchingIds.length){clauses.push('o.id IN (SELECT observation FROM entity_links WHERE kind=? AND entity IN ('+matchingIds.map(()=>'?').join(',')+'))');args.push(kind,...matchingIds);}
    else if (kind) { clauses.push('o.id IN (SELECT observation FROM entity_links WHERE kind=?)'); args.push(kind); }
    else clauses.push('o.id IN (SELECT DISTINCT observation FROM entity_links)');
    // Catalog correlation needs reference metadata, not full provider payloads.
    // Iterate all matching evidence so older relationships survive growth beyond 10k.
    // Production EXPLAIN chose observations_scope even with the IN filter:
    // 20 actor matches took 10.9s. Require primary-key probes for the linked IDs
    // rather than scanning every observation in the owner's scope.
    const projected=kind==='actor'&&actorIndexReady();
    const records=db.prepare(projected?`SELECT o.provider,o.external_id,o.published,o.link,o.title,o.type,o.value,
      (SELECT json_group_array(json_object('kind',e.kind,'id',e.entity,'name',e.name)) FROM entity_links e WHERE e.observation=o.observation) entities
      FROM actor_observations o WHERE ${clauses.join(' AND ').replaceAll('o.id IN','o.observation IN')} AND o.provider<>'news' AND o.link<>'' ORDER BY o.published DESC`:
      `SELECT o.provider,o.external_id,o.published,json_extract(o.details,'$.link') link,json_extract(o.details,'$.title') title,i.type,i.value,
      (SELECT json_group_array(json_object('kind',e.kind,'id',e.entity,'name',e.name)) FROM entity_links e WHERE e.observation=o.id) entities
      FROM observations o INDEXED BY sqlite_autoindex_observations_1 JOIN indicators i ON i.id=o.indicator WHERE ${clauses.join(' AND ')} AND o.provider<>'news' ORDER BY o.published DESC`).iterate(...args);
    const grouped=new Map();
    for(const record of records){const key=record.provider+':'+record.external_id;let row=grouped.get(key);
      if(!row){row={link:record.link,title:record.title,source:record.provider,pubDate:record.published,actors:[],malware:[],cves:[],iocs:{ips:[],domains:[],hashes:[],urls:[]}};grouped.set(key,row);}
      const values=row.iocs[{ip:'ips',domain:'domains',hash:'hashes',url:'urls'}[record.type]];
      if(!values.includes(record.value))values.push(record.value);
      for(const link of JSON.parse(record.entities)) {
        const field={actor:'actors',malware:'malware',cve:'cves'}[link.kind];if(field&&!row[field].some(item=>item.id===link.id))row[field].push({id:link.id,name:link.name});
      }
    }
    return [...grouped.values()].filter(row=>row.link);
  }

  function entities(kind,owner='') {
    const scope=scopeSql(owner);
    if(kind==='actor'&&actorIndexReady())return db.prepare(`SELECT e.entity id,e.name,MAX(o.published) updated,GROUP_CONCAT(DISTINCT o.source) source
      FROM entity_links e INDEXED BY entity_lookup JOIN actor_observations o ON o.observation=e.observation
      WHERE e.kind=? AND ${scope.sql} GROUP BY e.entity,e.name LIMIT 10000`).all(kind,...scope.args).map(row=>({...row,references:[]}));
    return db.prepare(`SELECT e.entity id,e.name,MAX(o.published) updated,GROUP_CONCAT(DISTINCT COALESCE(json_extract(o.details,'$.source'),o.provider)) source FROM entity_links e JOIN observations o INDEXED BY sqlite_autoindex_observations_1 ON o.id=e.observation WHERE e.kind=? AND ${scope.sql} GROUP BY e.entity,e.name LIMIT 10000`).all(kind,...scope.args).map(row=>({...row,references:[]}));
  }

  const status=owner=>{const scope=scopeSql(owner),index=coveringIndex();return {indicators:db.prepare(`SELECT COUNT(DISTINCT o.indicator) count FROM observations o${index} WHERE ${scope.sql}`).get(...scope.args).count,evidence:db.prepare(`SELECT COUNT(*) count FROM observations o${index} WHERE ${scope.sql}`).get(...scope.args).count,sources:db.prepare(`SELECT o.provider,COUNT(*) evidence,MAX(o.collected) lastCollected FROM observations o${index} WHERE ${scope.sql} GROUP BY o.provider`).all(...scope.args)};};
  function* actorActivityRows(owner='') {
    if(!actorIndexReady()){yield* publications({owner,kind:'actor'});return;}
    const scope=scopeSql(owner);
    const rows=db.prepare(`SELECT e.entity id,o.type,o.value,o.link,o.published FROM entity_links e INDEXED BY entity_lookup
      JOIN actor_observations o ON o.observation=e.observation WHERE e.kind='actor' AND ${scope.sql} AND o.provider<>'news' AND o.link<>''`).iterate(...scope.args);
    for(const row of rows)yield{actors:[{id:row.id}],link:row.link,pubDate:row.published,iocs:{[{ip:'ips',domain:'domains',hash:'hashes',url:'urls'}[row.type]]:[row.value]}};
  }
  return {list,detail,publications,entities,status,actorActivityRows};
}
