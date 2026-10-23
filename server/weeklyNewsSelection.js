// Editorial preferences apply to weekly suggestions, never to ETL ingestion.
import {getDomain} from 'tldts';
export const WEEKLY_EDITORIAL_WEIGHTS={context:35,impact:25,evidence:20,quality:15,novelty:5};
const official=['cisa.gov','nist.gov','cert.br','cert.europa.eu','ctir.gov.br'];
const research=['mandiant.com','paloaltonetworks.com','talosintelligence.com','research.checkpoint.com','huntress.com','volexity.com','thedfirreport.com','nozominetworks.com','isc.sans.edu','proofpoint.com','hunt.io','claroty.com','securelist.com','welivesecurity.com','trendmicro.com','crowdstrike.com','sentinelone.com','rapid7.com','group-ib.com','recordedfuture.com','intel471.com','cofense.com','infoblox.com','silentpush.com','domaintools.com','cloudsek.com','vulncheck.com','zerodayinitiative.com','tenable.com','qualys.com','wiz.io','securitylabs.datadoghq.com','socket.dev','research.jfrog.com','snyk.io','reversinglabs.com','elastic.co','sekoia.io','sekoia.com','esentire.com','reliaquest.com','dragos.com'];
const vendor=['microsoft.com','cisco.com','fortinet.com','siemens.com','se.com','oracle.com','php.net','nodejs.org','aws.amazon.com','cloud.google.com','cloudflare.com'];
const press=['bleepingcomputer.com','thehackernews.com','securityweek.com','securityaffairs.com','securityaffairs.co','therecord.media','darkreading.com','cyberscoop.com','infosecurity-magazine.com','scworld.com','industrialcyber.co','cisoadvisor.com.br','thehack.com.br'];
const complementary=['cybersecuritynews.com','cyberpress.org','securityboulevard.com','hackread.com','dailysecurityreview.com','thecyberexpress.com'];
const belongs = (host, domain) => host === domain || host.endsWith('.' + domain);
const normalize = value => String(value || '').normalize('NFKC').toLowerCase();
const contains = (text, value) => {
  const term = normalize(value).trim();
  if (term.length < 3) return false;
  const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?<![\\p{L}\\p{N}])${escaped}(?![\\p{L}\\p{N}])`, 'u').test(text);
};
export function weeklyProfileMatches(row, profile) {
  if (!profile) return {assets:[],actors:[],sector:false,ot:false};
  const text=normalize(`${row.title||''} ${row.description||''} ${row.vendor||''} ${row.product||''} ${row.editorialText||''}`);
  const assets=(profile.assets||[]).filter(asset=>asset.product?contains(text,asset.product):contains(text,asset.vendor)).map(asset=>[asset.vendor,asset.product].filter(Boolean).join(' '));
  const model=profile.threatModel;
  const relevant=new Set(model?.actorIds||profile.actors||[]);
  const known=new Map((model?.actors||[]).map(actor=>[actor.id,actor.name]));
  const actors=[...new Set((row.actors||[]).filter(actor=>typeof actor==='string'?(relevant.has(actor)||[...known].some(([id,name])=>relevant.has(id)&&normalize(name)===normalize(actor))):relevant.has(actor.id)).map(actor=>typeof actor==='string'?(known.get(actor)||actor):known.get(actor.id)||actor.name||actor.id))];
  return {assets:[...new Set(assets)],actors,sector:!!profile.sectors?.some(value=>(row.sectors||[]).includes(value)),ot:!!profile.ot?.present&&(row.categories||row.newsCategories||[]).includes('OT/ICS')};
}
export function weeklyNewsPriority(row, profile, {now=Date.now(),body=''}={}) {
  let url;
  try {url=new URL(row.link);if(!['https:','http:'].includes(url.protocol))return null;}catch{return null;}
  const host=url.hostname.toLowerCase();
  if(belongs(host,'medium.com'))return null;
  const text=normalize(`${row.title||''} ${row.description||''} ${String(body).slice(0,24000)}`);
  const script=text.match(/[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\p{Script=Thai}]/gu)?.length||0;
  if(script>=8&&script/Math.max(1,text.match(/\p{L}/gu)?.length||0)>.2)return null;
  const isResearch=research.some(domain=>belongs(host,domain));
  const isVendor=vendor.some(domain=>belongs(host,domain));
  const kind=official.some(domain=>belongs(host,domain))?'official':isResearch?'research':isVendor?'vendor':press.some(domain=>belongs(host,domain))?'press':complementary.some(domain=>belongs(host,domain))?'complementary':'other';
  const sourceTier=['official','vendor','research'].includes(kind)?'official':kind==='press'?'press':'other';
  const read=String(body).trim().length>=900;
  const ownResearch=read&&/\b(?:we (?:observed|discovered|investigated|analy[sz]ed|identified)|our (?:research|investigation|analysis|telemetry)|nossa (?:pesquisa|análise|investigação)|identificamos|observamos)\b/i.test(text);
  const advisory=(kind==='official'||isVendor)&&(/advisori|advisory|psirt|productcert|security[-_/]alerts|security[-_/]updates/i.test(url.pathname)||(row.cves||[]).length>0);
  const primary=((isResearch||isVendor)&&ownResearch)||advisory;
  const sourceRole=primary?'primary':kind==='press'||kind==='complementary'?'coverage':'unclassified';
  const context=weeklyProfileMatches({...row,editorialText:read?String(body).slice(0,24000):''},profile);
  const contextPoints=Math.min(35,(context.assets.length?25:0)+(context.actors.length?15:0)+(context.sector?10:0)+(context.ot?10:0));
  const exploitationPattern=/\b(?:actively exploited|exploited in the wild|exploitation in the wild|exploração ativa|explorada ativamente|exploradas ativamente|under active exploitation)\b/gi;
  const reportedExploitation=[...text.matchAll(exploitationPattern)].some(match=>{
    const before=text.slice(Math.max(0,match.index-100),match.index).split(/[.!?\n]/).pop();
    return !/\b(?:not|never|isn't|wasn't|não|nao)\s+(?:(?:currently|being|known to be|yet|sendo|conhecida como)\s+)*$/i.test(before)&&!/\b(?:(?:no|without|sem|nenhuma)\s+(?:public\s+)?(?:evidence|evidência|evidencia)|(?:não|nao)\s+(?:há|ha|existe|existem)\s+(?:evidência|evidencia)|not aware|could|might|may|poderia|pode)\b[^.!?\n]{0,90}$/i.test(before);
  });
  const knownExploitation=row.kev===true;
  const disruption=/\b(?:ransomware|operational disruption|shutdown|outage|interrupção|paralisação|production stopped|data theft|credential theft|roubo de credenciais|supply[- ]chain (?:attack|compromise))\b/i.test(text);
  const technicalImpact=/\b(?:remote code execution|authentication bypass|execução remota|bypass de autenticação|privilege escalation|elevação de privilégio)\b/i.test(text);
  const raw=Number(row.score);const signal=Number.isFinite(raw)?Math.max(0,Math.min(100,raw)):0;
  const impact=Math.min(25,(disruption?15:technicalImpact?12:0)+(knownExploitation?8:reportedExploitation?5:0)+signal*.02);
  const technical=Object.values(row.iocs||{}).some(values=>Array.isArray(values)&&values.length>0)||(row.ttpIds||row.ttps||[]).length>0;
  const evidence=knownExploitation?20:reportedExploitation?12:read&&ownResearch&&technical?10:technical?5:/\b(?:proof.of.concept|public exploit|poc disponível)\b/i.test(text)?4:0;
  const trust={official:8,research:8,vendor:7,press:6,complementary:2,other:1}[kind];
  const quality=Math.min(15,trust+(primary?5:0)+(read?2:0));
  const published=Date.parse(row.pubDate);const age=Number.isFinite(published)?Math.max(0,now-published)/86400000:Infinity;
  const novelty=Number.isFinite(age)?Math.max(0,5-age*5/14):0;
  const breakdown={context:contextPoints,impact:Math.round(impact*100)/100,evidence,quality,novelty:Math.round(novelty*100)/100};
  const score=Math.round(Object.values(breakdown).reduce((sum,value)=>sum+value,0)*100)/100;
  const selectionReasons=[];
  if(context.assets.length)selectionReasons.push(`Ativo do perfil: ${context.assets.slice(0,3).join(', ')}`);
  if(context.actors.length)selectionReasons.push(`Ator relacionado ao perfil: ${context.actors.slice(0,3).join(', ')}`);
  if(context.sector)selectionReasons.push('Setor monitorado');
  if(context.ot)selectionReasons.push('Ambiente OT/ICS do perfil');
  if(kind==='official')selectionReasons.push('Comunicado oficial');
  if(kind==='research')selectionReasons.push('Equipe de pesquisa especializada');
  if(kind==='press')selectionReasons.push('Veículo especializado reconhecido');
  if(kind==='complementary')selectionReasons.push('Fonte complementar');
  if(primary)selectionReasons.push(advisory?'Advisory do órgão ou fabricante':'Sinais de pesquisa própria no conteúdo');
  if(knownExploitation)selectionReasons.push('Exploração conhecida · KEV');
  else if(reportedExploitation)selectionReasons.push('Exploração relatada na fonte');
  selectionReasons.push(read?'Conteúdo coletado analisado':'Avaliação pelo título e resumo');
  const eligible=!advisory||knownExploitation||reportedExploitation||(contextPoints>0&&(technicalImpact||disruption));
  const topic=(row.categories||row.newsCategories||[]).find(category=>['OT/ICS','Ransomware','Phishing','Artificial Intelligence','Malware','Vulnerabilities','Data Leaks'].includes(category))||'General';
  return {score,selectionReasons,sourceTier,sourceKind:kind,sourceRole,publisherGroup:getDomain(host)||host,scoreBreakdown:breakdown,bodyStatus:read?'read':'summary',contextMatched:contextPoints>0,editorialEligible:eligible,editorialTopic:topic};
}

// Soft penalties promote diversity without filling quotas or dropping a strong
// story solely because the same publisher has already appeared.
export function diverseWeeklySuggestions(rows, limit=25) {
  const remaining=rows.filter(row=>row.editorialEligible!==false).slice();
  const result=[],publishers=new Map(),topics=new Map();
  while(result.length<limit&&remaining.length){
    let best=0,bestValue=-Infinity;
    for(let index=0;index<remaining.length;index++){
      const row=remaining[index];
      const value=row.score-Math.max(0,(publishers.get(row.publisherGroup)||0)-1)*8-(row.editorialTopic==='General'?0:(topics.get(row.editorialTopic)||0)*2);
      if(value>bestValue){best=index;bestValue=value;}
    }
    const [row]=remaining.splice(best,1);result.push(row);
    publishers.set(row.publisherGroup,(publishers.get(row.publisherGroup)||0)+1);
    topics.set(row.editorialTopic,(topics.get(row.editorialTopic)||0)+1);
  }
  return result;
}
