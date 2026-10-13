import Database from 'better-sqlite3';
import { createHash } from 'node:crypto';
import { isAiNews } from './newsCategories.js';

const DAY=86400000;
const sourceDate=value=>typeof value==='string'&&/^\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+)?$/.test(value)?value.replace(' ','T')+'Z':value;
const localDay=date=>new Intl.DateTimeFormat('en-CA',{timeZone:'America/Fortaleza',year:'numeric',month:'2-digit',day:'2-digit'}).format(date);
export function weeklyWindow(now=new Date(),startDay) {
  const day=startDay||localDay(now);
  if(!/^\d{4}-\d{2}-\d{2}$/.test(day)||new Date(day+'T12:00:00Z').toISOString().slice(0,10)!==day)throw Error('Invalid week');
  let from=new Date(day+'T03:00:00Z');
  if(startDay&&from.getUTCDay()!==0)throw Error('Week must start on Sunday');
  if(!startDay)from=new Date(from.getTime()-from.getUTCDay()*DAY);
  const to=new Date(from.getTime()+7*DAY);
  return {id:from.toISOString().slice(0,10),from:from.toISOString(),to:to.toISOString(),timezone:'America/Fortaleza',exclusiveEnd:true};
}
const inWeek=(date,range,now)=>Number.isFinite(Date.parse(date))&&Date.parse(date)>=Date.parse(range.from)&&Date.parse(date)<Math.min(Date.parse(range.to),now+1);
const names=items=>(items||[]).map(item=>typeof item==='string'?item:item.name).filter(Boolean);
const frequencies=values=>Object.entries(values.reduce((counts,value)=>{if(value)counts[value]=(counts[value]||0)+1;return counts;},{})).map(([name,count])=>({name,count})).sort((a,b)=>b.count-a.count||a.name.localeCompare(b.name));
const assetMatch=(row,assets=[])=>assets.some(asset=>(!asset.vendor||`${row.vendor||''} ${row.description||''}`.toLowerCase().includes(asset.vendor.toLowerCase()))&&(!asset.product||`${row.product||''} ${row.description||''}`.toLowerCase().includes(asset.product.toLowerCase())));
export const isAiVulnerability=row=>isAiNews({title:`${row.vendor||''} ${row.product||''}`,description:row.description||''})||/\b(?:mlflow|pytorch|tensorflow|llamaindex|langflow|litellm|gradio|comfyui|flowise|open[-_ ]?webui|dify)\b/i.test(`${row.vendor} ${row.product} ${row.description}`);

export function buildWeeklyReport(inputs,{range,profile=null,now=Date.now(),selection=null,retained=null}={}) {
  const groups=new Map();
  for(const row of inputs.publications||[]) {
    const periodDate=row.publicationTimeKnown===false||row.repository?.dateBasis==='report-date'?row.pubDate?.slice(0,10)+'T12:00:00Z':row.pubDate;
    // Unknown publication dates remain searchable in the archive, but cannot
    // stand in for this week's news. Collection time is not publication time.
    if(!row.link||row.dateInferred===true||row.securityRelevant===false||!inWeek(periodDate,range,now))continue;
    const key=row.storyId||row.link;
    const relevance=(Number(row.score)||0)+(row.kev?25:0)+(profile?.sectors?.some(sector=>(row.sectors||[]).includes(sector))?15:0);
    const existing=groups.get(key);
    const dateMetadata={dateInferred:row.dateInferred===true,publicationTimeKnown:row.publicationTimeKnown,publicationDateBasis:row.publicationDateBasis,firstCollectedAt:row.firstCollectedAt,repository:row.repository};
    const source={title:row.title,source:row.source,link:row.link,published:row.pubDate,...dateMetadata};
    const signals={actors:[...new Set([...(existing?.actors||[]),...names(row.actors)])],malware:[...new Set([...(existing?.malware||[]),...names(row.malware)])],cves:[...new Set([...(existing?.cves||[]),...(row.cves||[])])],ttps:[...new Set([...(existing?.ttps||[]),...(row.ttpIds||row.ttps||[])])],iocs:Object.fromEntries(['ips','domains','hashes','urls'].map(type=>[type,[...new Set([...(existing?.iocs?.[type]||[]),...(row.iocs?.[type]||[])])]]))};
    if(existing){if(!existing.sources.some(item=>item.link===row.link))existing.sources.push(source);existing.ai ||= (row.categories||row.newsCategories||[]).includes('Artificial Intelligence')||isAiNews(row);Object.assign(existing,signals);if(relevance<=existing.score)continue;}
    groups.set(key,{id:key,title:row.title,summary:row.description||'',published:row.pubDate,...dateMetadata,score:relevance,severity:row.severity||'',sources:existing?.sources||[source],
      ai:existing?.ai||(row.categories||row.newsCategories||[]).includes('Artificial Intelligence')||isAiNews(row),categories:row.categories||row.newsCategories||[],
      ...signals});
  }
  const ranked=[...groups.values()].sort((a,b)=>b.score-a.score||b.published.localeCompare(a.published)||a.id.localeCompare(b.id));
  const candidates={news:ranked.filter(row=>!row.ai).slice(0,25),aiNews:ranked.filter(row=>row.ai).slice(0,25)};
  const pick=(ids,rows,previous)=>[...new Map(ids.map(id=>{
    const old=previous?.find(row=>row.id===id);
    return rows.find(row=>row.id===id)||rows.find(row=>old?.sources.some(source=>row.sources.some(next=>next.link===source.link)))||old;
  }).filter(Boolean).map(row=>[row.id,row])).values()];
  const news=selection?pick(selection.newsIds,ranked.filter(row=>!row.ai),retained?.news):candidates.news.slice(0,10);
  const aiNews=selection?pick(selection.aiNewsIds,ranked.filter(row=>row.ai),retained?.aiNews):candidates.aiNews.slice(0,5);
  const vulnerabilities=inputs.vulnerabilities||[];
  const newCves=vulnerabilities.filter(row=>inWeek(row.published,range,now));
  const kev=vulnerabilities.filter(row=>row.kev&&inWeek(row.dateAdded?row.dateAdded+'T12:00:00Z':null,range,now));
  const prioritize=(a,b)=>Number(b.kev)-Number(a.kev)||(b.cvss||0)-(a.cvss||0)||(b.epss||0)-(a.epss||0)||a.id.localeCompare(b.id);
  const priority=[...new Map([...kev,...newCves].map(row=>[row.id,row])).values()].sort(prioritize);
  const aiCves=newCves.filter(isAiVulnerability).sort(prioritize);
  const monitored=profile?.assets?.length?priority.filter(row=>assetMatch(row,profile.assets)):[];
  const uniqueVictims=[...new Map((inputs.victims||[]).map(row=>[row.id||row.permalink||`${row.group}:${row.name}:${row.published||row.discovered}`,row])).values()];
  const victims=uniqueVictims.filter(row=>inWeek(sourceDate(row.published||row.discovered),range,now)).map(row=>({...row,published:sourceDate(row.published),discovered:sourceDate(row.discovered),claimStatus:'unconfirmed'}));
  const latamCodes=new Set(['AR','BO','BR','CL','CO','CR','CU','DO','EC','SV','GT','HT','HN','MX','NI','PA','PY','PE','PR','UY','VE']);
  const latam=victims.filter(row=>latamCodes.has(String(row.country).toUpperCase()));
  const reports=(inputs.reports||[]).filter(row=>row.status==='done'&&inWeek(row.updatedAt||row.createdAt,range,now)).map(row=>({id:row.id,title:row.title||row.url,type:row.type,updatedAt:row.updatedAt,sources:row.urls||[row.url]}));
  const selected=[...news,...aiNews];
  const recommendations=kev.slice(0,10).map(row=>({priority:'immediate',action:row.action||'Revisar o advisory e aplicar as medidas indicadas pelo fabricante.',source:`https://www.cisa.gov/known-exploited-vulnerabilities-catalog`,cve:row.id}));
  const data={range,profile:profile?{id:profile.id,name:profile.name,assets:profile.assets,sectors:profile.sectors}:null,generatedAt:new Date(now).toISOString(),
    news,aiNews,candidates,selection:{mode:selection?'manual':'suggested',newsIds:news.map(row=>row.id),aiNewsIds:aiNews.map(row=>row.id)},vulnerabilities:{total:newCves.length,kevCount:kev.length,critical:newCves.filter(row=>row.severity==='CRITICAL').length,kev,priority:priority.slice(0,50),monitored,ai:{total:aiCves.length,critical:aiCves.filter(row=>row.severity==='CRITICAL').length,items:aiCves.slice(0,50),vendors:frequencies(aiCves.map(row=>row.vendor))}},
    ransomware:{total:victims.length,latam:latam.length,brazil:latam.filter(row=>row.country==='BR').length,victims:latam,byCountry:frequencies(latam.map(row=>row.country)),byGroup:frequencies(latam.map(row=>row.group)),bySector:frequencies(latam.map(row=>row.sector)),claimsAreUnconfirmed:true},
    reports,recommendations,actors:frequencies(selected.flatMap(row=>row.actors)),malware:frequencies(selected.flatMap(row=>row.malware)),ttps:frequencies(selected.flatMap(row=>row.ttps)),
    coverage:inputs.coverage||{},sources:[...new Map(selected.flatMap(row=>row.sources).map(row=>[row.link,row])).values()]};
  return data;
}

export function createWeeklyReports({filePath=':memory:',getInputs,getProfile=()=>null,now=()=>Date.now()}={}) {
  const db=new Database(filePath);db.pragma('journal_mode = WAL');db.pragma('cache_size = -3000');
  db.exec(`CREATE TABLE IF NOT EXISTS weekly_plans(owner TEXT PRIMARY KEY,enabled INTEGER NOT NULL,profile TEXT NOT NULL,attempted TEXT,error TEXT);
    CREATE TABLE IF NOT EXISTS weekly_reports(owner TEXT NOT NULL,week TEXT NOT NULL,updated TEXT NOT NULL,fingerprint TEXT NOT NULL,revision INTEGER NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(owner,week));
    CREATE TABLE IF NOT EXISTS ransomware_observations(id TEXT PRIMARY KEY,payload TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS weekly_selections(owner TEXT NOT NULL,week TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(owner,week));`);
  const pending=new Map();
  const ensure=owner=>{db.prepare("INSERT OR IGNORE INTO weekly_plans VALUES(?,1,'',NULL,NULL)").run(owner);return db.prepare('SELECT * FROM weekly_plans WHERE owner=?').get(owner);};
  const read=(owner,week)=>{const row=db.prepare('SELECT * FROM weekly_reports WHERE owner=? AND week=?').get(owner,week);return row?{...JSON.parse(row.payload),updatedAt:row.updated,revision:row.revision}:null;};
  const write=(owner,week,data)=>{
    const clean={...data,updatedAt:undefined,revision:undefined};
    const fingerprint=createHash('sha256').update(JSON.stringify({...clean,generatedAt:undefined,coverage:undefined})).digest('hex');
    const previous=db.prepare('SELECT fingerprint,revision FROM weekly_reports WHERE owner=? AND week=?').get(owner,week);
    if(previous?.fingerprint!==fingerprint)db.prepare(`INSERT INTO weekly_reports VALUES(?,?,?,?,?,?) ON CONFLICT(owner,week) DO UPDATE SET updated=excluded.updated,fingerprint=excluded.fingerprint,revision=excluded.revision,payload=excluded.payload`).run(owner,week,new Date(now()).toISOString(),fingerprint,(previous?.revision||0)+1,JSON.stringify(clean));
    else db.prepare('UPDATE weekly_reports SET payload=? WHERE owner=? AND week=?').run(JSON.stringify(clean),owner,week);
    return read(owner,week);
  };
  async function refresh(owner,{force=false,week}={}) {
    const range=weeklyWindow(new Date(now()),week);
    const key=owner+':'+range.id;
    if(pending.has(key))return pending.get(key);
    const plan=ensure(owner);if(!plan.enabled&&!force)return read(owner,weeklyWindow(new Date(now())).id);
    const work=(async()=>{
      try {
        const last=read(owner,range.id);
        const profile=range.id!==weeklyWindow(new Date(now())).id&&last?last.profile:(plan.profile?getProfile(owner,plan.profile):null);
        const inputs=await getInputs(owner,range,profile);
        if(inputs.victims?.length)db.transaction(()=>{const insert=db.prepare('INSERT OR REPLACE INTO ransomware_observations VALUES(?,?)');for(const row of inputs.victims)insert.run(String(row.id||row.permalink||`${row.group}:${row.name}:${row.published||row.discovered}`),JSON.stringify(row));})();
        inputs.victims=db.prepare('SELECT payload FROM ransomware_observations').all().map(row=>JSON.parse(row.payload));
        const storedSelection=db.prepare('SELECT payload FROM weekly_selections WHERE owner=? AND week=?').get(owner,range.id);
        const data=buildWeeklyReport(inputs,{range,profile,now:now(),selection:storedSelection?JSON.parse(storedSelection.payload):null,retained:read(owner,range.id)});
        if(storedSelection)db.prepare('UPDATE weekly_selections SET payload=? WHERE owner=? AND week=?').run(JSON.stringify({newsIds:data.selection.newsIds,aiNewsIds:data.selection.aiNewsIds}),owner,range.id);
        if(inputs.coverage?.vulnerabilities?.status==='error'&&last)data.vulnerabilities=last.vulnerabilities;
        write(owner,range.id,data);
        db.prepare('UPDATE weekly_plans SET attempted=?,error=NULL WHERE owner=?').run(new Date(now()).toISOString(),owner);
        return read(owner,range.id);
      }catch{db.prepare('UPDATE weekly_plans SET attempted=?,error=? WHERE owner=?').run(new Date(now()).toISOString(),'Não foi possível atualizar. A última versão foi preservada.',owner);throw Error('Weekly update failed');}
    })().finally(()=>pending.delete(key));pending.set(key,work);return work;
  }
  return {refresh,
    select:(owner,week,selection)=>{
      const report=read(owner,week);if(!report)throw Error('Report not found');
      if(Array.isArray(selection.newsIds)&&Array.isArray(selection.aiNewsIds)&&selection.newsIds.some(id=>selection.aiNewsIds.includes(id)))throw Error('Duplicate event');
      const validate=(ids,candidates,previous,max)=>{
        if(!Array.isArray(ids)||ids.length>max||ids.some(id=>typeof id!=='string')||new Set(ids).size!==ids.length)throw Error('Invalid selection');
        const pool=new Map([...previous,...candidates].map(row=>[row.id,row]));
        return ids.map(id=>{if(!pool.has(id))throw Error('Unknown candidate');return pool.get(id);});
      };
      const news=validate(selection.newsIds,report.candidates.news,report.news,10),aiNews=validate(selection.aiNewsIds,report.candidates.aiNews,report.aiNews,5);
      const selected=[...news,...aiNews];
      db.transaction(()=>{
        db.prepare('INSERT OR REPLACE INTO weekly_selections VALUES(?,?,?)').run(owner,week,JSON.stringify(selection));
        write(owner,week,{...report,news,aiNews,selection:{mode:'manual',newsIds:selection.newsIds,aiNewsIds:selection.aiNewsIds},actors:frequencies(selected.flatMap(row=>row.actors)),malware:frequencies(selected.flatMap(row=>row.malware)),ttps:frequencies(selected.flatMap(row=>row.ttps)),sources:[...new Map(selected.flatMap(row=>row.sources).map(row=>[row.link,row])).values()]});
      })();return read(owner,week);
    },
    get:(owner,week)=>{const plan=ensure(owner);return {plan:{enabled:!!plan.enabled,profileId:plan.profile,lastAttemptedAt:plan.attempted,error:plan.error},updating:pending.has(owner+':'+(week||weeklyWindow(new Date(now())).id)),report:read(owner,week||weeklyWindow(new Date(now())).id),weeks:db.prepare('SELECT week,updated,revision FROM weekly_reports WHERE owner=? ORDER BY week DESC LIMIT 104').all(owner)};},
    configure:(owner,{enabled,profileId=''})=>{ensure(owner);if(profileId&&!getProfile(owner,profileId))throw Error('Profile not found');db.prepare('UPDATE weekly_plans SET enabled=?,profile=? WHERE owner=?').run(enabled?1:0,profileId,owner);},
    tick:async()=>{const range=weeklyWindow(new Date(now()));for(const plan of db.prepare('SELECT * FROM weekly_plans WHERE enabled=1').all())if(!read(plan.owner,range.id)||!plan.attempted||Date.parse(plan.attempted)<now()-15*60000){await refresh(plan.owner).catch(()=>{});const previous=weeklyWindow(new Date(now()),new Date(Date.parse(range.from)-7*DAY).toISOString().slice(0,10));if(now()-Date.parse(range.from)<2*DAY&&read(plan.owner,previous.id))await refresh(plan.owner,{week:previous.id}).catch(()=>{});}},
    close:()=>db.close(),
  };
}
