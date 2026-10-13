import { extractIOCs, isSoftwareVersionAt } from './ctiIntel.js';
import { sanitizeStoredMalware } from './malwareMatch.js';
import { isAiNews } from './newsCategories.js';
import { declaredRepositoryMalware } from './repositorySources.js';

export function removeVersionIndicators(iocs, text) {
  const body=String(text||'').replace(/\[\.\]|\(\.\)|\{\.\}/g,'.');
  return {...iocs,ips:(iocs?.ips||[]).filter(ip=>{
    const matches=[...body.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)].filter(match=>match[0]===ip);
    return !matches.length||matches.some(match=>!isSoftwareVersionAt(body,match.index,ip));
  })};
}
export function isRelevantNews(row) {
  if(row.securityRelevant===false)return false;
  if(Number(row.layer)===1||row.repository||row.repositoryReport)return true;
  const text=[row.title,row.description,row.text].filter(Boolean).join('\n');
  return Boolean(row.cves?.length||row.actors?.length||row.malware?.length||isAiNews(row)
    || /(?:\b(?:cyber\w*|secur\w*|threat\w*|vulnerab\w*|exploit\w*|malware|ransomware|phishing|breach\w*|hacker\w*|attack\w*|advisory|advisories|infosec|privacy|credential\w*|backdoor|botnet|spyware|zero.day|patch\w*|pentest\w*)\b|уязвим|безопасност|кибератак|脆弱性|マルウェア|安全漏洞)/i.test(text));
}
export function reviewNewsEvidence(row,body='',matchMalware) {
  const text=[row.title,row.text||row.description,body].filter(Boolean).join('\n');
  const iocs=removeVersionIndicators(row.iocs||extractIOCs(text),text);
  const matches=body&&matchMalware?matchMalware(text):sanitizeStoredMalware(row.malware,text);
  const malware=[...new Map([...declaredRepositoryMalware({...row,repositoryReport:!!row.repository}),...matches].map(family=>[family.id,family])).values()];
  const next={...row,iocs,malware,securityRelevant:undefined};
  return {...next,securityRelevant:isRelevantNews(next)};
}
// The archive owns evidence revisions. Serve archived publications even when
// their RSS entry has rotated out of the live snapshot.
export function completeNewsFeed(current,archive) {
  const rows=new Map(current.map(row=>[row.link,row]));
  for(const row of archive)rows.set(row.link,{...rows.get(row.link),...row,description:row.description||rows.get(row.link)?.description||'',newsCategories:row.categories});
  return [...rows.values()].filter(isRelevantNews).map(({text,archivedAt,...row})=>row);
}
