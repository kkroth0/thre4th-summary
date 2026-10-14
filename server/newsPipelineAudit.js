// Read-only production audit: public publication evidence and aggregate counts.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import crypto from 'node:crypto';
const root = path.resolve(process.argv[2] || process.cwd());
const read = file => { try { return JSON.parse(fs.readFileSync(file,'utf8')); } catch { return null; } };
const cached = key => read(path.join(root,'server/.feed-cache/rss',crypto.createHash('sha256').update(key).digest('hex')+'.json'));
const archive = read(path.join(root,'server/.news-archive.json')) || [];
const stories = read(path.join(root,'server/.news-stories.json')) || [];
const { actorPublications,buildActorEvidence,buildActorActivity } = await import(pathToFileURL(path.join(root,'server/actorEvidence.js')));
const rows = actorPublications(archive,stories);
const activity = buildActorActivity(rows);
const c2 = archive.find(row => row.repository?.repo?.includes('Unit42') && /C2Agent/i.test(row.title));
const expected = (fs.readFileSync(path.join(root,'server/test/fixtures/c2agent-indicators.txt'),'utf8').match(/\b[a-f0-9]{64}\b/g) || []);
const counts = Object.fromEntries(['ips','domains','hashes','urls'].map(type => [type,new Set(archive.flatMap(row => row.iocs?.[type] || [])).size]));
const ranked = Object.entries(activity).sort((a,b) => b[1].posts-a[1].posts);
const selected = [...new Set(['G0032',...ranked.slice(0,3).map(([id])=>id)])];
const examples = selected.map(id => {
  const profile=buildActorEvidence(rows,id);
  return {actorId:id,counts:profile.counts,example:profile.indicators[0]?.evidence?.[0] || profile.publications[0] || null};
});
const snapshot=cached('newsletter:snapshot');
const bodyStats = Object.fromEntries(['fresh','cached','feed-body','repository-body','deferred','failed','stale'].map(status => [status,(snapshot?.items||[]).filter(row => row.articleCollectionStatus===status).length]));
const sources = stories.flatMap(story=>story.sources||[]);
const indexed=new Map(sources.map(row=>[row.link,row]));
const recent=archive.filter(row=>Date.parse(row.pubDate)>=Date.now()-30*86400000);
const hasIocs=row=>Object.values(row.iocs||{}).some(values=>values?.length);
const {mergeIntoStoriesAsync}=await import(pathToFileURL(path.join(root,'server/newsStories.js')));
const sample=(snapshot?.items||[]).filter(row=>indexed.has(row.link)).slice(0,100);
const benchmarkStart=performance.now();
const benchmarkStories=await mergeIntoStoriesAsync(stories,sample,new Date());
const correlationCheck={publications:sample.length,elapsedMs:Math.round(performance.now()-benchmarkStart),retainedStories:benchmarkStories.length,readOnly:true};
let intelligence={status:'not initialized'},flowSamples=[];
const intelligenceFile=path.join(root,'server/.ioc-intelligence.sqlite');
if(fs.existsSync(intelligenceFile)) {
  const {default:Database}=await import(pathToFileURL(path.join(root,'server/node_modules/better-sqlite3/lib/index.js')));
  const db=new Database(intelligenceFile,{readonly:true,fileMustExist:true});db.pragma('query_only = ON');
  intelligence={
    indicators:db.prepare('SELECT COUNT(*) count FROM indicators').get().count,
    observations:db.prepare('SELECT COUNT(*) count FROM observations').get().count,
    sources:db.prepare('SELECT provider,COUNT(*) observations FROM observations GROUP BY provider').all(),
    entityLinks:db.prepare('SELECT kind,COUNT(*) links,COUNT(DISTINCT entity) entities FROM entity_links GROUP BY kind').all(),
    collectors:db.prepare("SELECT id,value FROM intelligence_state WHERE id LIKE 'source:%'").all().map(row=>{const state=JSON.parse(row.value);return {source:row.id.split(':').at(-1),scope:row.id.split(':').length>2?'account':'platform',status:state.status,count:state.count,lastSuccessfulAt:state.lastSuccessfulAt,nextAt:state.nextAt};}),
    c2agent:db.prepare("SELECT COUNT(DISTINCT o.indicator) hashes FROM observations o JOIN entity_links e ON e.observation=o.id JOIN indicators i ON i.id=o.indicator WHERE e.kind='malware' AND e.name='C2Agent' AND i.type='hash'").get(),
  };
  const {normalizeIndicator}=await import(pathToFileURL(path.join(root,'server/iocIntelligence.js')));
  const {declaredRepositoryMalware}=await import(pathToFileURL(path.join(root,'server/repositorySources.js')));
  const pools=[{name:'IP e atribuição',accept:row=>row.iocs?.ips?.length&&(row.actors?.length||row.malware?.length)},
    {name:'Ator e indicadores',accept:row=>row.actors?.length&&hasIocs(row)},
    {name:'Hashes de malware',accept:row=>row.iocs?.hashes?.length},
    {name:'Vulnerabilidade',accept:row=>row.cves?.length},
    {name:'Sem indicadores declarados',accept:row=>!hasIocs(row)}];
  const chosen=new Set();
  const auditRow=(row,category)=>{
    const expected=[...new Map(Object.values(row.iocs||{}).flat().map(value=>normalizeIndicator(value)).filter(Boolean).map(value=>[value.value,value])).values()];
    const stored=db.prepare("SELECT i.value,i.type,o.id FROM observations o JOIN indicators i ON i.id=o.indicator WHERE o.provider='news' AND o.external_id=? AND o.scope='global'").all(row.link);
    const links=stored.length?db.prepare("SELECT DISTINCT e.kind,e.entity id,e.name FROM entity_links e JOIN observations o ON o.id=e.observation WHERE o.provider='news' AND o.external_id=? AND o.scope='global'").all(row.link):[];
    const actors=(row.actors||[]).map(entity=>({kind:'actor',...entity})),families=[...declaredRepositoryMalware({...row,repositoryReport:!!row.repository}),...(row.malware||[])].map(entity=>({kind:'malware',...entity}));
    const expectedEntities=[...actors,...families,...(row.cves||[]).map(id=>({kind:'cve',id,name:id}))];
    const crossSources=expected.slice(0,5).map(ioc=>({indicator:ioc.value,type:ioc.type,providers:db.prepare("SELECT o.provider,COUNT(*) evidence FROM observations o JOIN indicators i ON i.id=o.indicator WHERE i.value=? AND o.scope='global' GROUP BY o.provider ORDER BY o.provider").all(ioc.value)}));
    const actorProfiles=actors.map(actor=>({id:actor.id,name:actor.name,...buildActorEvidence(rows,actor.id).counts,publicationLinked:buildActorEvidence(rows,actor.id).publications.some(paper=>paper.link===row.link)}));
    return {selection:category,title:row.title,source:row.source,link:row.link,published:row.pubDate,storyId:row.storyId||indexed.get(row.link)?.storyId||stories.find(story=>story.sources.some(source=>source.link===row.link))?.id||null,
      rawIocs:Object.values(row.iocs||{}).flat().length,expectedPublicIocs:expected.length,persistedNewsIocs:stored.length,missingIocs:expected.filter(ioc=>!stored.some(record=>record.value===ioc.value)).map(ioc=>ioc.value),
      entities:expectedEntities.map(entity=>({...entity,linkedInIocBase:links.some(link=>link.kind===entity.kind&&link.id===entity.id)})),actorProfiles,crossSources};
  };
  for(const pool of pools)for(let n=0;n<2;n++){const available=recent.filter(row=>row.securityRelevant!==false&&!chosen.has(row.link)&&pool.accept(row));if(available.length){const row=available[crypto.randomInt(available.length)];chosen.add(row.link);flowSamples.push(auditRow(row,pool.name));}}
  for(const link of ['https://blog.nicter.jp/2026/01/aicloud_vulnerability/','https://blog.qualys.com/product-tech/2026/09/15/before-you-patch-why-patch-reliability-matters-for-confident-deployment','https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-83943']){
    const row=archive.find(item=>item.link===link);if(row&&!chosen.has(link)){chosen.add(link);flowSamples.push(auditRow(row,'Regressão da auditoria anterior'));}
  }
  if(c2&&!chosen.has(c2.link))flowSamples.push(auditRow(c2,'Controle C2Agent'));
  db.close();
  if(intelligence.collectors.some(source=>source.source==='MalwareBazaar'&&source.status==='error')) {
    const {default:dotenv}=await import(pathToFileURL(path.join(root,'server/node_modules/dotenv/lib/main.js')));
    const {default:axios}=await import(pathToFileURL(path.join(root,'server/node_modules/axios/index.js')));
    const config=dotenv.parse(fs.readFileSync(path.join(root,'.env')));
    const key=config.ABUSE_CH_API_KEY||config.THREATFOX_API_KEY||config.URLHAUS_API_KEY||config.MALWAREBAZAAR_API_KEY;
    if(key) {
      try { const response=await axios.post('https://mb-api.abuse.ch/api/v1/','query=get_recent&selector=time',{headers:{'Auth-Key':key,'Content-Type':'application/x-www-form-urlencoded'},timeout:15000,family:4,maxContentLength:8000000,maxRedirects:0});
        intelligence.malwareBazaarProbe={status:response.status,queryStatus:String(response.data?.query_status||'').replace(/[^a-z0-9_]/gi,'').slice(0,80),samples:Array.isArray(response.data?.data)?response.data.data.length:null};
      }catch(error){intelligence.malwareBazaarProbe={status:error.response?.status||null,code:String(error.code||'').replace(/[^a-z0-9_]/gi,'').slice(0,80),sizeLimit:/maxContentLength/i.test(error.message||'')};}
    }
  }
}
let weekly={status:'module not deployed'};
if(fs.existsSync(path.join(root,'server/weeklyReports.js'))){
  const {weeklyWindow,buildWeeklyReport}=await import(pathToFileURL(path.join(root,'server/weeklyReports.js')));
  const {default:Database}=await import(pathToFileURL(path.join(root,'server/node_modules/better-sqlite3/lib/index.js')));
  const range=weeklyWindow();let vulnerabilities=[];
  const catalog=path.join(root,'server/.vulnerability-catalog.sqlite');
  if(fs.existsSync(catalog)){const db=new Database(catalog,{readonly:true,fileMustExist:true});db.pragma('query_only = ON');
    vulnerabilities=db.prepare(`SELECT v.id,v.description,v.published,v.vendor,v.product,v.cvss,v.severity,k.cve kev,k.date_added dateAdded,e.score epss FROM vulnerabilities v LEFT JOIN kev k ON k.cve=v.id LEFT JOIN epss e ON e.cve=v.id WHERE v.rejected=0 AND ((v.published>=? AND v.published<?) OR (k.date_added>=? AND k.date_added<?))`).all(range.from.replace(/Z$/,''),range.to.replace(/Z$/,''),range.id,range.to.slice(0,10)).map(row=>({...row,kev:!!row.kev,published:/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?$/.test(row.published)?row.published+'Z':row.published}));db.close();}
  const report=buildWeeklyReport({publications:rows,vulnerabilities},{range});
  weekly={status:'read-only source validation',week:range.id,generalCandidates:report.candidates.news.length,aiCandidates:report.candidates.aiNews.length,newCves:report.vulnerabilities.total,newKev:report.vulnerabilities.kevCount,aiCves:report.vulnerabilities.ai.total,publicationTimesDeclared:rows.filter(row=>row.publicationTimeKnown===true).length};
  const file=path.join(root,'server/.weekly-reports.sqlite');
  if(fs.existsSync(file)){const db=new Database(file,{readonly:true,fileMustExist:true});db.pragma('query_only = ON');weekly.persistedDrafts=db.prepare('SELECT COUNT(*) count FROM weekly_reports').get().count;weekly.editorialSelections=db.prepare('SELECT COUNT(*) count FROM weekly_selections').get().count;db.close();}
}
const {auditProviderMatches}=await import(pathToFileURL(path.join(root,'server/providerMatchAudit.js')));
const providerMatches=await auditProviderMatches(root);
console.log(JSON.stringify({providerMatches,
  checkedAt:new Date().toISOString(), archivePublications:archive.length,storedStories:stories.length,
  publicationsWithIocs:archive.filter(hasIocs).length,uniqueIocs:counts,
  publicationsWithActors:archive.filter(row=>row.actors?.length).length,
  publicationsWithMalware:archive.filter(row=>row.malware?.length).length,
  publicationsWithCves:archive.filter(row=>row.cves?.length).length,
  actorProfilesWithActivity:Object.keys(activity).length,actorExamples:examples,
  recentArchivePublications:recent.length,recentWithIocs:recent.filter(hasIocs).length,
  recentWithStoryEvidence:recent.filter(row=>indexed.has(row.link)).length,
  extractionVersion:snapshot?.extractionVersion,bodyCollection:bodyStats,
  intelligence,correlationCheck,weekly,flowSamples,
  c2agent:c2 ? {link:c2.link,archivedAt:c2.archivedAt,hashes:c2.iocs?.hashes?.length||0,missingExpectedHashes:expected.filter(hash=>!c2.iocs?.hashes?.includes(hash)).length,
    storyHashes:indexed.get(c2.link)?.iocs?.hashes?.length||0,storyId:c2.storyId} : {status:'not archived yet'},
},null,2));
