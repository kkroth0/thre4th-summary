import * as cheerio from 'cheerio';

export const ACTOR_SOURCES = {
  mitre: 'https://attack.mitre.org/groups/',
  etda: 'https://apt.etda.or.th/cgi-bin/getcard.cgi?g=all&o=j',
  rapid7: 'https://docs.rapid7.com/insightidr/apt-groups/',
  icic: 'https://instituteforcriticalinfrastructurecybersecurity.org/apt-profiles',
  domains: 'https://github.com/marktsec/Ransomware_Official_Domains',
};
export const actorNameKey = value => String(value || '').normalize('NFKD').toLowerCase().replace(/[^a-z0-9]/g, '');
const validName = value => typeof value === 'string' && value.trim().length >= 3 && value.length <= 180 && !/[<>\r\n]/.test(value) && !/^[GST]\d{3,4}$|^\[|^operation\b|^unknown$|^none$|^n\/a$/i.test(value);

export function parseEtda(data) {
  if (!Array.isArray(data?.values)) throw new Error('ETDA format changed');
  return data.values.map(row => ({ source:'ETDA', url:`https://apt.etda.or.th/cgi-bin/showcard.cgi?g=${encodeURIComponent(row.actor)}&n=1`,
    name:row.names?.[0]?.name || row.actor, actorIds:(row['mitre-attack'] || []).flatMap(url=>String(url).match(/G\d{4}/g)||[]),
    aliases:(row.names || []).filter(value=>validName(value.name)).map(value=>({name:value.name,declaredBy:value['name-giver'] || ''})),
    sourceUpdatedAt:row['last-card-change'] || data['last-db-change'], relation:'source-declared-name' }));
}

export function parseRapid7(html) {
  const $=cheerio.load(html), rows=[];
  $('h2,h3').each((_, heading)=>{
    const node=$(heading), name=node.clone().children().remove().end().text().trim();
    const section=node.nextUntil('h2,h3');
    const aliases=[];
    section.filter('p').each((_,paragraph)=>{
      if (!/other names|also known as|also goes by|aliases|known by.*names/i.test($(paragraph).text())) return;
      $(paragraph).next('ul').children('li').each((_,item)=>{const name=$(item).text().trim();if(validName(name))aliases.push({name});});
    });
    if(validName(name)&&aliases.length) rows.push({name,aliases,source:'Rapid7',url:`${ACTOR_SOURCES.rapid7}#${node.attr('id') || ''}`,relation:'source-declared-name'});
  });
  if(!rows.length) throw new Error('Rapid7 alias sections unavailable');
  return rows;
}

export function parseIcic(script) {
  // Parse string literals only. Never evaluate the site's JavaScript.
  const rows=[...script.matchAll(/\{name:("(?:\\.|[^"\\])*"),aliases:("(?:\\.|[^"\\])*")/g)].map(match=>({
    name:JSON.parse(match[1]),aliases:JSON.parse(match[2]).split(',').map(name=>({name:name.trim()})).filter(value=>validName(value.name)),
    source:'ICIC',url:ACTOR_SOURCES.icic,relation:'source-association',
  }));
  if(!rows.length) throw new Error('ICIC profiles unavailable');
  return rows;
}

export function parseRansomwareDomains(markdown, {commit='',collectedAt=''}={}) {
  const rows=[];let name='',historical=false;
  for(const rawLine of markdown.split(/\r?\n/)) {
    const line=rawLine.replace(/hxxp/gi,'http').replace(/\[\.\]|\(\.\)/g,'.').replace(/\[:\]/g,':');
    const heading=/^##\s+(.+?)\s*$/.exec(line);if(heading){if(/^(?:new|old)$/i.test(heading[1]))historical=/^old$/i.test(heading[1]);else{historical=/^old\s/i.test(heading[1]);name=heading[1].replace(/^(?:new|old)\s+/i,'').replace(/\s+blog$/i,'');}continue;}
    if(!validName(name))continue;
    for(const match of line.matchAll(/(?<![a-z0-9@])(?:https?:\/\/)?(?:[a-z0-9-]+\.)*(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion(?:\/[^\s<>\\]*)?/gi)){
      let url;try{url=new URL(/^https?:/i.test(match[0])?match[0]:`http://${match[0]}`);}catch{continue;}
      if(url.username||url.password||url.port||!/^(?:[a-z0-9-]+\.)*(?:[a-z2-7]{56}|[a-z2-7]{16})\.onion$/i.test(url.hostname))continue;
      // Store the site root, never access keys, contact identities or paths.
      const host=url.hostname.toLowerCase();
      rows.push({name,host,url:`${url.protocol}//${host}/`,type:'onion',source:'Ransomware Official Domains',sourceUrl:ACTOR_SOURCES.domains,
        sourceCommit:commit,collectedAt,reportedStatus:/seized|apreendido/i.test(line)?'reported-seized':/offline|not found|down\b|defunct|inactive/i.test(line)?'reported-offline':historical?'historical':'listed',
        addressVersion:host.split('.').at(-2).length===16?2:3,relation:'listed-in-source'});
    }
  }
  if(!rows.length)throw new Error('Ransomware domain list unavailable');
  return rows;
}

function nameIndex(actors) {
  const index=new Map();
  for(const actor of actors)for(const name of [actor.name,...(actor.aliases || [])]){
    const key=actorNameKey(name);if(!key)continue;
    const ids=index.get(key)||new Set();ids.add(actor.id);index.set(key,ids);
  }
  return index;
}

export function enrichActorCatalog(actors, snapshot = {}) {
  const copies=actors.map(actor=>({...actor,aliases:[...(actor.aliases || [])],aliasEvidence:[],relatedNames:[],infrastructure:[],refs:[...(actor.refs || [])]}));
  const byId=new Map(copies.map(actor=>[actor.id,actor])), index=nameIndex(copies);
  const softwareNames=new Set((snapshot.nonActorNames || []).map(actorNameKey));
  function resolve(record) {
    const explicit=[...new Set(record.actorIds || [])].filter(id=>byId.has(id));
    if(record.actorIds?.length)return explicit.length===1&&new Set(record.actorIds).size===1?explicit[0]:null;
    const ids=index.get(actorNameKey(record.name));
    return ids?.size===1?[...ids][0]:null;
  }
  const records=(snapshot.records || []).map(row=>({...row,target:resolve(row)}));
  const claims=new Map();
  for(const row of records)if(row.relation!=='source-association')for(const alias of row.aliases || []){
    if(!validName(alias.name))continue;
    const key=actorNameKey(alias.name), ids=claims.get(key)||new Set();ids.add(row.target || `unresolved:${row.source}:${actorNameKey(row.name)}`);claims.set(key,ids);
  }
  for(const record of records){
    const actor=byId.get(record.target);if(!actor)continue;
    for(const alias of record.aliases || []){
      if(!validName(alias.name))continue;
      const key=actorNameKey(alias.name), otherOwners=[...(index.get(key)||[]),...(claims.get(key)||[])].filter(id=>id!==actor.id);
      const ownNames=new Set([actor.name,...actor.aliases].map(actorNameKey));
      const accepted=record.relation!=='source-association'&&!otherOwners.length&&(!softwareNames.has(key)||ownNames.has(key));
      const evidence={name:alias.name,source:record.source,url:record.url,declaredBy:alias.declaredBy || '',sourceUpdatedAt:record.sourceUpdatedAt || '',
        relation:accepted?'source-declared-name':'source-association',relatedActorIds:[...new Set(otherOwners)].filter(id=>byId.has(id))};
      if(!actor.aliasEvidence.some(row=>actorNameKey(row.name)===key&&row.source===evidence.source))actor.aliasEvidence.push(evidence);
      if(accepted&&!new Set([actor.name,...actor.aliases].map(actorNameKey)).has(key))actor.aliases.push(alias.name);
      if(!accepted&&key!==actorNameKey(actor.name)&&!actor.relatedNames.some(row=>actorNameKey(row.name)===key&&row.source===evidence.source))actor.relatedNames.push(evidence);
    }
    if(record.url&&!actor.refs.some(ref=>(typeof ref==='string'?ref:ref.url)===record.url))actor.refs.push({name:record.source,url:record.url});
  }
  const sitesIndex=nameIndex(copies);
  for(const actor of copies)for(const alias of [actor.name,...actor.aliases])if(/\.0$/.test(alias)){
    const key=actorNameKey(alias.slice(0,-2)),ids=sitesIndex.get(key)||new Set();ids.add(actor.id);sitesIndex.set(key,ids);
  }
  for(const site of snapshot.domains || [])if(/\.0$/.test(site.name)){
    const ids=sitesIndex.get(actorNameKey(site.name.slice(0,-2)));if(ids?.size===1&&!sitesIndex.has(actorNameKey(site.name)))sitesIndex.set(actorNameKey(site.name),ids);
  }
  for(const site of snapshot.domains || []){
    const ids=sitesIndex.get(actorNameKey(site.name)),actor=ids?.size===1?byId.get([...ids][0]):null;if(!actor)continue;
    if(!actor.infrastructure.some(row=>row.host===site.host))actor.infrastructure.push({...site});
    else {const existing=actor.infrastructure.find(row=>row.host===site.host),rank={listed:0,historical:1,'reported-offline':2,'reported-seized':3};if(rank[site.reportedStatus]>rank[existing.reportedStatus])existing.reportedStatus=site.reportedStatus;}
  }
  return copies;
}
