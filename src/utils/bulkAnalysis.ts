import type { BulkRow } from './bulkEnrichment';
import { bulkField, bulkVerdictLabel } from './bulkEnrichment';
import type { VendorData } from '../types/threat-intelligence';
import { detectAnalyzerQueryType } from './iocExtract';
import attack from './bulkAttackTactics.json';
import { scrubXml } from './deckTemplate';

export type Count = { name: string; count: number };
export type AnalysisRecord = Record<string, string | number | null>;
export const PUBLIC_RESOLVERS = new Set(['8.8.8.8','8.8.4.4','1.1.1.1','1.0.0.1','9.9.9.9','149.112.112.112','208.67.222.222','208.67.220.220','94.140.14.14','94.140.15.15']);
const key = (s: string) => s.normalize('NFKC').toLocaleLowerCase('en-US').replace(/\s+/g,' ').trim();
const names = (value: unknown): string[] => Array.isArray(value) ? value.flatMap(names) : typeof value === 'string' && !/^(unknown|none|n\/a|—)$/i.test(value.trim()) ? [value.trim()] : [];
const distinct = (values: string[]) => [...new Map(values.filter(Boolean).map(value => scrubXml(value)).map(value => [key(value),value])).values()];
const join = (values: string[]) => distinct(values).join('; ');
const list = (value: unknown) => Array.isArray(value) ? value : [];
const num = (value: unknown): number | null => value == null || value === '' || !Number.isFinite(Number(String(value).replace(/%$/,''))) ? null : Number(String(value).replace(/%$/,''));
export function canonicalBulkRows(rows: BulkRow[]) {
  const result = new Map<string, BulkRow>();
  for (const row of rows) {
    const id = detectAnalyzerQueryType(row.query) === 'url' ? row.query : row.query.toLowerCase();
    // Keep the latest occurrence, preserving its source statuses instead of
    // accidentally promoting an older successful attempt over a newer failure.
    result.set(id,row);
  }
  return [...result.values()];
}
export interface IocAnalysis {
  row: BulkRow; record: AnalysisRecord; excluded: boolean; fp: boolean;
  priority: string; actors: string[]; families: string[]; techniques: string[];
  pairs: { actor: string; technique: string }[]; mentions: string[]; asn: string;
}
export const PRIORITIES = ['Investigar','Atenção','Revisar','Sem sinal nas fontes','Infraestrutura pública','Teste','Pendente'];
const TACTICS: Record<string,string> = {TA0001:'Acesso inicial',TA0002:'Execução',TA0003:'Persistência',TA0004:'Escalação de privilégios',TA0005:'Evasão de defesa',TA0112:'Comprometimento de defesas',TA0006:'Acesso a credenciais',TA0007:'Descoberta',TA0008:'Movimento lateral',TA0009:'Coleta',TA0010:'Exfiltração',TA0011:'Comando e controle',TA0040:'Impacto',TA0042:'Desenvolvimento de recursos',TA0043:'Reconhecimento'};
const techs = (value: unknown) => distinct(names(value).flatMap(s => s.match(/\bT\d{4}(?:\.\d{3})?\b/g) || []));
// Community fields can contain a whole newsletter instead of one entity.
// Preserve that text in the source columns; do not invent an actor from it.
const actorLabel = (s: string) => s.length <= 80 && !/[;,|/\n]/.test(s) && !/^(?:global|unattributed|unknown actor|desconhecido)$/i.test(s);
const familyLabel = (s: string) => s.length <= 100 && !/^(?:generic(?:\s|$)|unknown|unclassified|susp[._-]|heur[.:_/-]|_{2,}|win\.(?:trojan|malware|packed|dropper))/i.test(s) && !/[:\\/!]|\.(?:exe|dll|zip|bin|js|md)$/i.test(s);
const clean = (v?: VendorData) => v && !v.error && !v.isLoading ? v.data : {};
const value = (d: Record<string,unknown>, ...keys: string[]) => {for(const k of keys)if(d[k]!=null&&d[k]!==''&&!/^(unknown|none|n\/a)$/i.test(String(d[k])))return typeof d[k]==='number'?d[k] as number:join(names(d[k]));return null;};
export function analyzeBulkRow(row: BulkRow): IocAnalysis {
  const vendors=row.result?.vendorData || [], vendor=(name:string)=>vendors.find(v=>v.name===name);
  const vt=clean(vendor('VirusTotal')),ab=clean(vendor('AbuseIPDB')),otx=clean(vendor('AlienVault OTX')),tf=clean(vendor('ThreatFox')),uh=clean(vendor('URLhaus')),mb=clean(vendor('MalwareBazaar')),dns=vendor('DNS / Team Cymru')?.data||{},whois=clean(vendor('WHOIS')),hunt=clean(vendor('abuse.ch Hunting'));
  const evidence=row.context?.evidence||[],type=detectAnalyzerQueryType(row.query),query=row.query.toLowerCase();
  const publicResolver=type==='ip'&&PUBLIC_RESOLVERS.has(query);
  const reserved=type==='domain'&&/^(?:[^.]+\.)*example\.(?:com|org|net)$/.test(query);
  const eicar=type==='hash'&&query==='44d88612fea8a8f36de82e1278abb02f';
  const excluded=publicResolver||reserved||eicar;
  const fpRecords=list(hunt['FP Matches']);
  const fp=fpRecords.some((m:any)=>m.matchRelation==='exact'||(m.entry_value&&key(m.entry_value)===key(row.query)));
  const declared:string[]=[],contextual:string[]=[],families:string[]=[],techniques:string[]=[],tactics:string[]=[],pairs:{actor:string;technique:string}[]=[];
  const cves:string[]=[],reportTitles:string[]=[],reportLinks:string[]=[],reportDates:string[]=[];
  const ax=evidence.filter(e=>e.provider==='Axur');
  for(const e of evidence){
    const entities=e.entities||[];contextual.push(...entities.filter(x=>x.kind==='actor').map(x=>x.name));
    cves.push(...entities.filter(x=>x.kind==='cve').map(x=>x.name));
    const attributed=entities.filter(x=>x.relation==='attributed-by-source');
    if(!excluded&&!(fp&&['ThreatFox','URLhaus','MalwareBazaar'].includes(e.provider))){
      declared.push(...attributed.filter(x=>x.kind==='actor').map(x=>x.name));
      families.push(...attributed.filter(x=>x.kind==='malware').map(x=>x.name));
    }
    const payload:any=(e as any).payload||{};
    const patterns=[...list(payload.relatedTTPs),...list(payload.attacks)];
    const ids=techs([...names(payload.relatedTTPs),...patterns.map((t:any)=>t?.code||t?.id||t?.name||'')]);
    tactics.push(...patterns.flatMap((t:any)=>String(t?.code||t?.id||t||'').match(/\bTA\d{4}\b/g)||[]));
    techniques.push(...ids);
    if(!excluded)for(const actor of attributed.filter(x=>x.kind==='actor'))for(const technique of ids)pairs.push({actor:actor.name,technique});
    if(e.provider==='Axur'){reportTitles.push(e.title);if(e.link)reportLinks.push(e.link);if(e.published)reportDates.push(e.published);}
  }
  const pulses=list(otx['Pulse Details']);
  for(const p of pulses){
    const ids=techs(p.attackIds);techniques.push(...ids);
    tactics.push(...names(p.attackIds).flatMap(s=>s.match(/\bTA\d{4}\b/g)||[]));
    if(!excluded&&p.adversary){declared.push(...names(p.adversary));for(const technique of ids)for(const actor of names(p.adversary))pairs.push({actor,technique});}
    if(!excluded)families.push(...names(p.malwareFamilies));
  }
  if(!excluded&&!fp)families.push(...names(tf['All Malware']),...names(tf.Malware),...names(mb.Malware),...names(mb.Signature),...names(uh['All Malware']));
  // Vendor summary strings often repeat the full list; prefer exact array labels.
  const declaredLabels=distinct(declared),familyLabels=distinct(families.flatMap(s=>s.split(/,\s*/)));
  const declaredActors=excluded?[]:declaredLabels.filter(actorLabel);
  const normalizedFamilies=excluded?[]:familyLabels.filter(familyLabel);
  contextual.push(...declaredLabels.filter(s=>!actorLabel(s)));
  for(const technique of distinct(techniques))tactics.push(...((attack.techniques as Record<string,string[]>)[technique]||[]));
  const directPositive=row.result?.threatLevel==='malicious'||(!fp&&(/malicious|malware|phishing/i.test(String(tf.Status||''))||Number(uh['URL Count']||0)>0||/malware payload found/i.test(String(uh.Status||''))||/sample found|malicious/i.test(String(mb.Status||''))))||Number(vt.Malicious||0)>0;
  const abuseHigh=(num(ab['Abuse Confidence Score'])||0)>=75;
  const errors=vendors.filter(v=>v.error||v.isLoading);
  const pending=['queued','running'].includes(row.state)||row.contextLoading||vendors.some(v=>v.isLoading);
  const priority=publicResolver?'Infraestrutura pública':reserved||eicar?'Teste':!row.result?'Pendente':directPositive?'Investigar':pending?'Pendente':fp?'Revisar':abuseHigh||row.result.threatLevel==='suspicious'?'Atenção':errors.length||row.context?.errors.length?'Revisar':row.result.threatLevel==='safe'?'Sem sinal nas fontes':'Revisar';
  const notes=[...(row.result?.signals||[]).map(s=>s.source+': '+s.reason),publicResolver?'Resolvedor DNS público conhecido; fora das contagens de atribuição.':reserved?'Domínio reservado para exemplos; fora dos rankings de ameaça.':eicar?'Arquivo de teste EICAR; detecções de antivírus são esperadas.':'',fp?'Correspondência exata na revisão da abuse.ch; sinais dessas bases exigem revisão. Evidências independentes foram preservadas.':fpRecords.length?'Revisão de falso positivo apenas contextual; validar IP, porta ou URL.':'',!declaredActors.length&&contextual.length&&!excluded?'Há entidades citadas em relatórios, sem atribuição específica recebida para o indicador.':'',declaredLabels.some(s=>!actorLabel(s))?'Campos agregados de adversários foram mantidos como contexto, fora do ranking de atores.':'',familyLabels.some(s=>!familyLabel(s))?'Rótulos genéricos de detecção e nomes de arquivos foram preservados nos dados da fonte, fora do ranking de famílias.':'',errors.length?`${errors.length} fonte(s) com erro ou consulta pendente.`:''].filter(Boolean);
  const sources=vendors.map(v=>v.name),as=bulkField(row,['ASN','AS']).value;
  const record:AnalysisRecord={rank:null,priority,indicator:row.query,type:({ip:'IP',domain:'Domínio',hash:'Hash',url:'URL',unknown:'Outro'})[type],score:row.result?.overallScore??null,
    verdict:bulkVerdictLabel(row),state:({complete:'Concluído',partial:'Parcial',error:'Falha',running:'Consultando',queued:'Na fila',stopped:'Interrompido',unsupported:'Sem fonte compatível'})[row.state],
    actors:join(declaredActors),families:join(normalizedFamilies),mentions:join(contextual),basis:excluded?'Excluído dos rankings':declaredActors.length?'Declaração explícita da fonte':'Somente contexto ou reputação',notes:notes.join(' '),
    axLocalStatus:row.context?.localSnapshot?(row.context.localSnapshot.axurEvidence?`${row.context.localSnapshot.axurEvidence} ${row.context.localSnapshot.axurEvidence===1?'evidência':'evidências'} na base importada`:row.context.localSnapshot.axurImportStatus==='complete'?'Sem registro na base importada':'Sem registro na parcela importada'):'Não conferida neste recorte',axImportAt:row.context?.localSnapshot?.axurImportAt||null,localReadAt:row.context?.localSnapshot?.asOf||null,
    axReports:join(reportTitles),axLinks:join(reportLinks),axActors:join(ax.flatMap(e=>e.entities.filter(x=>x.kind==='actor').map(x=>x.name))),axMalware:join(ax.flatMap(e=>e.entities.filter(x=>x.kind==='malware').map(x=>x.name))),axCves:join(ax.flatMap(e=>e.entities.filter(x=>x.kind==='cve').map(x=>x.name))),axDates:join(reportDates),
    techniques:join(techniques),tactics:join(tactics.map(t=>`${t} ${TACTICS[t]||''}`)),publications:row.context?.publications.length??0,evidence:evidence.length,completedAt:row.completedAt||null,
    vtStatus:value(vt,'Status'),vtDetections:value(vt,'Detection Rate'),vtMalicious:num(vt.Malicious),vtReputation:num(vt.Reputation),vtNames:value(vt,'Threat Names','Threat Classification'),vtTags:value(vt,'All Tags','Tags'),
    abScore:num(ab['Abuse Confidence Score']),abReports:num(ab['Total Reports']),abReporters:num(ab['Distinct Reporters']),abLast:value(ab,'Last Report','Last Reported'),abUsage:value(ab,'Usage Type'),abWhitelisted:value(ab,'Is Whitelisted','Whitelisted'),
    otxStatus:value(otx,'Status'),otxPulses:pulses.length||(otx['Pulse Count']!=null?parseInt(String(otx['Pulse Count']),10)||0:null),otxActors:join(pulses.flatMap((p:any)=>names(p.adversary))),otxFamilies:join(pulses.flatMap((p:any)=>names(p.malwareFamilies))),otxTags:value(otx,'All Tags','Tags'),
    tfStatus:value(tf,'Status'),tfMalware:value(tf,'All Malware','Malware'),tfType:value(tf,'Threat Type'),tfConfidence:num(tf.Confidence),tfMatches:num(tf['IOC Matches']),tfFirst:value(tf,'First Seen'),tfLast:value(tf,'Last Seen'),tfReference:value(tf,'Reference'),
    uhStatus:value(uh,'Status'),uhUrls:num(uh['URL Count']),uhActive:num(uh['Online URLs']),uhMalware:value(uh,'All Malware','Malware','Signature'),uhTags:value(uh,'All Tags','Tags'),
    mbStatus:value(mb,'Status'),mbFile:value(mb,'File Name'),mbType:value(mb,'File Type'),mbSignature:value(mb,'Signature','Malware'),mbTags:value(mb,'Tags'),mbFirst:value(mb,'First Seen'),
    fpStatus:value(hunt,'FP Review'),fpScope:fp?'Exata':fpRecords.length?'Contextual':vendor('abuse.ch Hunting')?.error?'Indisponível':vendor('abuse.ch Hunting')?.isLoading?'Consultando':vendor('abuse.ch Hunting')?'Sem correspondência':'Não consultada',
    country:bulkField(row,['Country']).value,asn:as,organization:bulkField(row,['Organization','AS Owner','ISP']).value,isp:value(ab,'ISP'),prefix:value(dns,'Prefix')||value(ab,'CIDR')||value(vt,'Network'),rdns:value(dns,'Reverse Hostname')||bulkField(row,['Reverse Hostname']).value,
    registrar:value(whois,'Registrar'),created:value(whois,'Created'),sources:join(sources),failedSources:join(errors.map(v=>v.name)),sourceErrors:[...errors.map(v=>`${v.name}: ${v.error||'Consulta em andamento'}`),...(row.context?.errors||[]),...(row.error?[row.error]:[])].join('; ')};
  for(const name of ['Axur','VirusTotal','AbuseIPDB','AlienVault OTX','ThreatFox','URLhaus','MalwareBazaar','DNS / Team Cymru','abuse.ch Hunting','WHOIS']){
    const v=vendor(name);record['status:'+name]=!v?'Não consultada':v.isLoading?'Consultando':v.error?'Indisponível':name==='Axur'&&String(v.data.Origem||'').startsWith('Base Axur importada')?'Base importada':'Respondida';
  }
  return {row,record,excluded,fp,priority,actors:declaredActors,families:normalizedFamilies,techniques:distinct(techniques),pairs:excluded?[]:pairs.map(p=>({...p,actor:scrubXml(p.actor)})).filter(p=>declaredActors.some(a=>key(a)===key(p.actor))),mentions:distinct(contextual),asn:as==='—'?'':as};
}
export function counts(rows:{name:string;indicator:string}[]):Count[]{
  const groups=new Map<string,{name:string;values:Set<string>}>();
  for(const row of rows){const id=key(row.name);if(!id)continue;if(!groups.has(id))groups.set(id,{name:row.name,values:new Set()});groups.get(id)!.values.add(row.indicator);}
  return [...groups.values()].map(g=>({name:g.name,count:g.values.size})).sort((a,b)=>b.count-a.count||a.name.localeCompare(b.name));
}
export function analyzeBulkRows(rows:BulkRow[]){
  const analyses=canonicalBulkRows(rows).map(analyzeBulkRow).sort((a,b)=>PRIORITIES.indexOf(a.priority)-PRIORITIES.indexOf(b.priority)||Number(b.record.score||0)-Number(a.record.score||0)||a.row.query.localeCompare(b.row.query));
  return aggregateBulkAnalyses(analyses);
}
export function aggregateBulkAnalyses(analyses:IocAnalysis[]){
  analyses.forEach((a,i)=>a.record.rank=i+1);
  const eligible=analyses.filter(a=>!a.excluded),entries=(f:(a:IocAnalysis)=>string[])=>counts(eligible.flatMap(a=>f(a).map(name=>({name,indicator:a.row.query}))));
  const sourceNames=distinct(analyses.flatMap(a=>a.row.result?.vendorData.map(v=>v.name)||[]));
  return {analyses,total:analyses.length,excluded:analyses.filter(a=>a.excluded).length,partial:analyses.filter(a=>a.row.state!=='complete'||a.row.result?.vendorData.some(v=>v.error||v.isLoading)||a.row.contextLoading||!!a.row.context?.errors.length).length,
    attributed:eligible.filter(a=>a.actors.length).length,actors:entries(a=>a.actors),families:entries(a=>a.families),techniques:entries(a=>a.techniques),tactics:entries(a=>String(a.record.tactics||'').split('; ').filter(Boolean)),
    priorities:PRIORITIES.map(name=>({name,count:analyses.filter(a=>a.priority===name).length})),types:counts(analyses.map(a=>({name:String(a.record.type),indicator:a.row.query}))),asns:entries(a=>a.asn?[a.asn]:[]),
    coverage:sourceNames.map(name=>({name,count:analyses.filter(a=>a.row.result?.vendorData.some(v=>v.name===name&&!v.error&&!v.isLoading)).length})),
    evidence:analyses.reduce((sum,a)=>sum+(a.row.context?.evidence.length||0),0)};
}
export type BulkAnalysis = ReturnType<typeof analyzeBulkRows>;
