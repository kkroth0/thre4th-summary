import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import net from 'node:net';
import { setImmediate as yieldLoop } from 'node:timers/promises';

const idFor = value => crypto.createHash('sha256').update(value).digest('hex');
const refang = value => String(value || '').trim().replace(/^hxxp/i,'http').replace(/\[\.\]|\(\.\)|\{\.\}/g,'.').replace(/\[:\]/g,':');
export function normalizeIndicator(value, hint) {
  let text=refang(value);
  if (text.length>2048 || /[\u0000-\u0020]/.test(text)) return null;
  if (hint==='ip:port') text=text.replace(/^\[([^\]]+)\]:\d+$/,'$1').replace(/^(\d+\.\d+\.\d+\.\d+):\d+$/,'$1');
  const family=net.isIP(text);
  if(family) {
    if(family===4){const [a,b]=text.split('.').map(Number);if(a===0||a===10||a===127||a>=224||(a===172&&b>=16&&b<=31)||(a===192&&b===168)||(a===169&&b===254)||(a===100&&b>=64&&b<=127))return null;}
    if(family===6){text=new URL(`http://[${text}]/`).hostname.slice(1,-1);if(/^(::|f[cd]|fe[89ab]|ff|2001:db8)/i.test(text))return null;}
    return {type:'ip',value:text.toLowerCase()};
  }
  if (/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(text)) return {type:'hash',value:text.toLowerCase()};
  try {
    if (/^https?:\/\//i.test(text)) {const url=new URL(text),host=url.hostname.replace(/^\[|\]$/g,'');if(url.username||url.password||(net.isIP(host)?!normalizeIndicator(host):!host.includes('.')||/\.(?:localhost|local|internal|invalid|test)$/i.test(host)))return null;url.hash='';return {type:'url',value:url.href};}
    if(/[/:?#@]/.test(text))return null;
    const domain=new URL('https://'+text).hostname.toLowerCase();
    if(!domain.includes('.')||/\.(?:localhost|local|internal|arpa|invalid|test)$/i.test(domain)||! /^[a-z0-9.-]+\.[a-z0-9-]{2,}$/i.test(domain))return null;
    return {type:'domain',value:domain};
  }catch{return null;}
}
const iocValues = row => ['ips','domains','hashes','urls'].flatMap(type => (row.iocs?.[type] || []).map(value=>({value})));

export function createIocIntelligence({filePath=':memory:',now=()=>Date.now()}={}) {
  const db=new Database(filePath); db.pragma('journal_mode = WAL');db.pragma('busy_timeout = 5000');db.pragma('cache_size = -8000');
  db.exec(`CREATE TABLE IF NOT EXISTS indicators(id TEXT PRIMARY KEY,type TEXT NOT NULL,value TEXT NOT NULL UNIQUE);
    CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY,indicator TEXT NOT NULL,scope TEXT NOT NULL,provider TEXT NOT NULL,external_id TEXT NOT NULL,published TEXT NOT NULL,collected TEXT NOT NULL,details TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS observations_indicator ON observations(indicator,scope,published DESC);
    CREATE INDEX IF NOT EXISTS observations_scope ON observations(scope,provider,published DESC);
    CREATE TABLE IF NOT EXISTS entity_links(observation TEXT NOT NULL,kind TEXT NOT NULL,entity TEXT NOT NULL,name TEXT NOT NULL,relation TEXT NOT NULL,PRIMARY KEY(observation,kind,entity));
    CREATE INDEX IF NOT EXISTS entity_lookup ON entity_links(kind,entity,observation);
    CREATE TABLE IF NOT EXISTS intelligence_state(id TEXT PRIMARY KEY,value TEXT NOT NULL);`);
  const putIoc=db.prepare('INSERT OR IGNORE INTO indicators VALUES(?,?,?)');
  const putObservation=db.prepare('INSERT INTO observations VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET published=excluded.published,collected=excluded.collected,details=excluded.details');
  const clearLinks=db.prepare('DELETE FROM entity_links WHERE observation=?');
  const putLink=db.prepare('INSERT OR REPLACE INTO entity_links VALUES(?,?,?,?,?)');
  const putState=db.prepare('INSERT OR REPLACE INTO intelligence_state VALUES(?,?)');
  const chunk=db.transaction(rows=>{
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
      for(const kind of ['actor','malware','cve'])for(const entity of row[kind+'s']||[])if(entity?.id&&entity?.name){putLink.run(observation,kind,String(entity.id).slice(0,180),String(entity.name).slice(0,200),row.relation||'mentioned-with');}
    }
  });
  let flight=Promise.resolve();
  const ingest = rows => {
    const work=flight.then(async()=>{for(let i=0;i<rows.length;i+=200){chunk(rows.slice(i,i+200));await yieldLoop();}return rows.length;});
    flight=work.catch(()=>{});return work;
  };
  const scopes=owner=>owner?['global',String(owner)]:['global'];
  const scopeSql=owner=>({sql:owner?'o.scope IN (?,?)':'o.scope=?',args:scopes(owner)});
  function list({owner='',type='',query='',page=1,size=50,actor='',malware=''}={}) {
    size=Math.min(100,Math.max(1,Number(size)||50));page=Math.max(1,Number(page)||1);
    const scope=scopeSql(owner),clauses=[scope.sql],args=[...scope.args];
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
  function publications({owner='',kind,id}={}){
    const scope=scopeSql(owner),args=[...scope.args],clauses=[scope.sql];
    if(kind&&id){clauses.push('EXISTS(SELECT 1 FROM entity_links e WHERE e.observation=o.id AND e.kind=? AND e.entity=?)');args.push(kind,id);}
    const records=db.prepare(`SELECT o.id,o.provider,o.external_id,o.published,o.details,i.type,i.value FROM observations o JOIN indicators i ON i.id=o.indicator WHERE ${clauses.join(' AND ')} AND o.provider<>'news' ORDER BY o.published DESC LIMIT 10000`).all(...args);
    const grouped=new Map();
    for(const record of records){const info=JSON.parse(record.details),key=record.provider+':'+record.external_id;let row=grouped.get(key);
      if(!row){row={link:info.link,title:info.title,source:record.provider,pubDate:record.published,actors:[],malware:[],cves:[],iocs:{ips:[],domains:[],hashes:[],urls:[]}};grouped.set(key,row);}
      row.iocs[{ip:'ips',domain:'domains',hash:'hashes',url:'urls'}[record.type]].push(record.value);
      for(const link of db.prepare('SELECT kind,entity id,name FROM entity_links WHERE observation=?').all(record.id)) {
        const field={actor:'actors',malware:'malware',cve:'cves'}[link.kind];if(field&&!row[field].some(item=>item.id===link.id))row[field].push({id:link.id,name:link.name});
      }
    }
    return [...grouped.values()].filter(row=>row.link);
  }
  async function ingestNews(rows) {
    const changed=rows.map(row=>({row,key:'news:'+idFor(row.link),hash:idFor(JSON.stringify([row.title,row.pubDate,row.iocs,row.actors,row.malware,row.cves,row.storyId]))}))
      .filter(entry=>db.prepare('SELECT value FROM intelligence_state WHERE id=?').get(entry.key)?.value!==JSON.stringify(entry.hash));
    await ingest(changed.flatMap(({row})=>iocValues(row).map(ioc=>({...ioc,provider:'news',source:row.source,externalId:row.link,title:row.title,link:row.link,published:row.pubDate,actors:row.actors,malwares:row.malware,cves:(row.cves||[]).map(id=>({id,name:id})),storyId:row.storyId,relation:'mentioned-with'}))));
    db.transaction(()=>{for(const entry of changed)putState.run(entry.key,JSON.stringify(entry.hash));})();
    putState.run('news-sync',JSON.stringify({lastSuccessfulAt:new Date(now()).toISOString(),publications:rows.length,changed:changed.length}));
  }
  function entities(kind,owner='') {
    const scope=scopeSql(owner);
    return db.prepare(`SELECT e.entity id,e.name,MAX(o.published) updated,GROUP_CONCAT(DISTINCT COALESCE(json_extract(o.details,'$.source'),o.provider)) source FROM entity_links e JOIN observations o ON o.id=e.observation WHERE e.kind=? AND ${scope.sql} GROUP BY e.entity,e.name LIMIT 10000`).all(kind,...scope.args).map(row=>({...row,references:[]}));
  }
  return {ingest,list,detail,publications,
    exportRows:({owner='',from,to})=>{
      const scope=scopeSql(owner);
      return db.prepare(`SELECT o.*,i.value,i.type FROM observations o JOIN indicators i ON i.id=o.indicator WHERE ${scope.sql} AND o.published>=? AND o.published<=? ORDER BY o.published DESC,o.id`).all(...scope.args,from,to).map(row=>{
        const details=JSON.parse(row.details),entities=db.prepare('SELECT kind,entity id,name FROM entity_links WHERE observation=?').all(row.id);
        return {type:row.type,indicator:row.value,title:details.title,source:row.provider,url:details.link,date:row.published,dateBasis:'source-observation',storyId:details.storyId||'',categories:[],
          actors:entities.filter(entity=>entity.kind==='actor').map(entity=>entity.name),malware:entities.filter(entity=>entity.kind==='malware').map(entity=>entity.name),cves:entities.filter(entity=>entity.kind==='cve').map(entity=>entity.id)};
      });
    },
    ingestNews,
    families:owner=>entities('malware',owner),entities,
    state:key=>{const row=db.prepare('SELECT value FROM intelligence_state WHERE id=?').get(key);return row?JSON.parse(row.value):null;},
    setState:(key,value)=>putState.run(key,JSON.stringify(value)),
    status:owner=>{const scope=scopeSql(owner);return {indicators:db.prepare(`SELECT COUNT(DISTINCT o.indicator) count FROM observations o WHERE ${scope.sql}`).get(...scope.args).count,evidence:db.prepare(`SELECT COUNT(*) count FROM observations o WHERE ${scope.sql}`).get(...scope.args).count,sources:db.prepare(`SELECT o.provider,COUNT(*) evidence,MAX(o.collected) lastCollected FROM observations o WHERE ${scope.sql} GROUP BY o.provider`).all(...scope.args)};},
    close:()=>db.close()};
}
