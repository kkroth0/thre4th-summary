import { extractIOCs, isSoftwareVersionAt } from './ctiIntel.js';
import { sanitizeStoredMalware } from './malwareMatch.js';
import { isAiNews } from './newsCategories.js';
import { declaredRepositoryMalware } from './repositorySources.js';

export function removeVersionIndicators(iocs, text) {
  const body=String(text||'').replace(/\[\.\]|\(\.\)|\{\.\}/g,'.');
  const seen=new Set(),valid=new Set();
  for(const match of body.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)){seen.add(match[0]);if(!isSoftwareVersionAt(body,match.index,match[0]))valid.add(match[0]);}
  return {...iocs,ips:(iocs?.ips||[]).filter(ip=>{
    return !seen.has(ip)||valid.has(ip);
  })};
}
export function recoverJoinedTableIps(row,text='') {
  // Older cached HTML collapsed an inline address and its next column label
  // into e.g. "204.8.96.109Tor Exit". Recover only those affected bodies.
  if(!/(?:\b(?:\d{1,3}\.){3}\d{1,3}[A-Z][a-z]|[A-Za-z](?:\d{1,3}\.){3}\d{1,3})/.test(text))return row;
  const ips=[...new Set([...(row.iocs?.ips||[]),...extractIOCs(text).ips])];
  if(ips.length===(row.iocs?.ips||[]).length)return row;
  return {...row,iocs:{...row.iocs,ips}};
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
