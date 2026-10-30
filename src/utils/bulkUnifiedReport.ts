import type { BulkRow } from './bulkEnrichment';
import { analyzeBulkRow, aggregateBulkAnalyses, type IocAnalysis } from './bulkAnalysis';
import { bulkEntityLookup } from './bulkEntityResolution';

export const BULK_REPORT_VERSION = '2026-10-30-unified-v1';
export type UnifiedColumn = [string, string, number];
export type UnifiedRecord = Record<string, string | number | null>;
const labels = (value: unknown): string[] => Array.isArray(value) ? value.flatMap(labels) : typeof value === 'string' && value.trim() ? [value.trim()] : [];
const unique = (values: string[]) => [...new Map(values.filter(Boolean).map(value => [value.normalize('NFKC').toLowerCase(), value])).values()];
const joined = (values: string[]) => unique(values).join('; ');
const techniques = (value: unknown) => unique(labels(value).flatMap(item => item.match(/\bT\d{4}(?:\.\d{3})?\b/g) || []));
const dates = (values: string[]) => unique(values).filter(value => Number.isFinite(Date.parse(value))).map(value => new Date(value).toISOString()).sort();
function reference(value: unknown) {
  try {
    const url = new URL(String(value || ''));
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) return '';
    url.hash = '';
    for (const key of [...url.searchParams.keys()]) if (/^utm_|^(fbclid|gclid)$/i.test(key)) url.searchParams.delete(key);
    return url.href;
  } catch { return ''; }
}
const split = (value: unknown) => labels(value).flatMap(item => item.split(';').map(s => s.trim()).filter(Boolean));

export const UNIFIED_INDICATOR_COLUMNS: UnifiedColumn[] = [
  ['indicator','Indicador',43],['type','Tipo',13],['verdict','Classificação',22],['context','Contexto da análise',70],
  ['actors','Atores relacionados',46],['actorIds','IDs dos atores',30],['malware','Malwares e ferramentas',46],['softwareIds','IDs dos malwares e ferramentas',32],
  ['techniques','Técnicas ATT&CK',38],['mentions','Menções em publicações e feeds',24],['firstMention','Primeira menção',25],['lastMention','Última menção',25],
  ['abuseReports','Relatos de abuso',18],['country','País',19],['asn','ASN',20],['organization','Organização da rede',40],['prefix','Prefixo de rede',24],['rdns','Nome reverso (rDNS)',43],
  ['registrar','Registrador',32],['created','Criação do domínio',26],
];
export const UNIFIED_PUBLICATION_COLUMNS: UnifiedColumn[] = [
  ['id','Publicação',17],['title','Título',75],['date','Data da publicação',26],['actors','Atores relacionados',45],['malware','Malwares e ferramentas',45],['techniques','Técnicas ATT&CK',38],['count','Indicadores citados',22],['link','Referência',75],
];
export const UNIFIED_MENTION_COLUMNS: UnifiedColumn[] = [
  ['indicator','Indicador',43],['publication','Publicação',17],['title','Título da publicação',75],['actors','Atores relacionados',45],['malware','Malwares e ferramentas',45],['association','Associação registrada',32],
];
export const UNIFIED_RELATION_COLUMNS: UnifiedColumn[] = [
  ['indicator','Indicador',43],['kind','Tipo de entidade',25],['name','Nome normalizado',42],['catalogId','ID no catálogo',30],['association','Associação registrada',32],['publication','Publicação',17],['title','Título da publicação',75],
];
export const UNIFIED_TECHNIQUE_COLUMNS: UnifiedColumn[] = [
  ['id','Técnica ATT&CK',22],['count','Indicadores relacionados',25],['actors','Atores citados na mesma publicação',52],['link','Referência MITRE ATT&CK',70],
];

type Association = { kind: string; name: string; catalogId: string; association: string };
export type UnifiedMention = { link: string; title: string; date: string; actors: string[]; malware: string[]; techniques: string[]; entities: Association[] };
export interface UnifiedProjection { record: UnifiedRecord; mentions: UnifiedMention[]; analysis: IocAnalysis }

/** A feed's publication is one document, even if several local observations repeat it. */
export function projectUnifiedBulkRow(row: BulkRow, analysis = analyzeBulkRow(row)): UnifiedProjection {
  const resolve = bulkEntityLookup(row.context), documents = new Map<string, UnifiedMention>();
  const association = (relation: string) => relation === 'attributed-by-source' ? 'Associação descrita na publicação' : 'Menção em publicação';
  const add = (title: string, link: string, date: string, entities: {kind:string;name:string;id?:string;relation?:string}[] = [], ids: string[] = []) => {
    link = reference(link); if (!link) return;
    const current = documents.get(link) || {link,title: title || 'Registro de inteligência',date:'',actors:[],malware:[],techniques:[],entities:[]};
    if (title && (!current.title || current.title === 'Registro de inteligência')) current.title = title;
    const stamp = dates([date]); if (stamp.length && (!current.date || stamp[0] < current.date)) current.date = stamp[0];
    current.techniques = unique([...current.techniques,...ids]);
    for (const entity of entities) {
      const identity = resolve(entity.kind, entity.name, entity.id || '');
      if (identity.kind === 'actor' && identity.verification === 'catalog' && !analysis.excluded) current.actors.push(identity.name);
      else if (identity.kind === 'software' && !analysis.excluded) current.malware.push(identity.name);
      else if (identity.kind !== 'cve') continue;
      current.entities.push({kind:identity.kind === 'actor' ? 'Ator de ameaça' : identity.kind === 'software' ? 'Malware / ferramenta' : 'Vulnerabilidade',name:identity.name,catalogId:identity.id,association:association(entity.relation || '')});
    }
    current.actors = unique(current.actors); current.malware = unique(current.malware);
    current.entities = [...new Map(current.entities.map(entity => [JSON.stringify([entity.kind,entity.catalogId || entity.name,entity.association]),entity])).values()];
    documents.set(link,current);
  };
  for (const publication of row.context?.publications || []) add(publication.title,publication.link,publication.pubDate || '',labels(publication.actors).map(name => ({kind:'actor',name})));
  for (const evidence of row.context?.evidence || []) {
    // Reputation/lookup pages do not constitute publications mentioning an IOC.
    const actualRecord = ['news','OTX','Axur'].includes(evidence.provider) || /(?:threatfox\.abuse\.ch\/ioc\/|urlhaus\.abuse\.ch\/url\/|bazaar\.abuse\.ch\/sample\/)/i.test(evidence.link);
    if (!actualRecord) continue;
    const payload = (evidence as unknown as {payload?:Record<string,unknown>}).payload || {};
    const ids = techniques([...(Array.isArray(payload.relatedTTPs) ? payload.relatedTTPs : []),...(Array.isArray(payload.attacks) ? payload.attacks : [])].flatMap(item => typeof item === 'string' ? [item] : item && typeof item === 'object' ? [String((item as any).code || (item as any).id || '')] : []));
    add(evidence.title,evidence.link,evidence.published,evidence.entities || [],ids);
  }
  for (const vendor of row.result?.vendorData || []) {
    if (vendor.name !== 'AlienVault OTX' || vendor.error || vendor.isLoading || vendor.unsupported) continue;
    const pulses = vendor.data?.['Pulse Details'];
    for (const pulse of Array.isArray(pulses) ? pulses : []) {
      if (!pulse.id) continue;
      const entities = [...labels(pulse.adversary).map(name => ({kind:'actor',name,relation:'attributed-by-source'})),...labels(pulse.malwareFamilies).map(name => ({kind:'malware',name,relation:'mentioned-by-source'}))];
      add(String(pulse.name || 'Publicação de inteligência'),`https://otx.alienvault.com/pulse/${encodeURIComponent(pulse.id)}`,String(pulse.created || pulse.modified || ''),entities,techniques(pulse.attackIds));
    }
  }
  const mentions = [...documents.values()];
  const actors = analysis.excluded ? [] : unique([...analysis.actors,...analysis.mentions,...mentions.flatMap(item => item.actors)]);
  const software = analysis.excluded ? [] : unique([...analysis.families,...split(analysis.record.softwareMentions),...mentions.flatMap(item => item.malware)]);
  const known = row.context?.entityResolutions || [];
  const actorIds = unique(known.filter(entity => entity.kind === 'actor' && entity.verification === 'catalog' && actors.includes(entity.name)).map(entity => entity.id));
  const softwareIds = unique(known.filter(entity => entity.kind === 'software' && entity.verification === 'catalog' && software.includes(entity.name)).map(entity => entity.id));
  const stamps = dates(mentions.map(item => item.date));
  const context = [mentions.length ? `Citado em ${mentions.length.toLocaleString('pt-BR')} ${mentions.length === 1 ? 'publicação ou registro de feed' : 'publicações e registros de feeds'}.` : 'Sem menções identificadas no histórico disponível.',actors.length ? `${actors.length.toLocaleString('pt-BR')} ${actors.length === 1 ? 'ator relacionado' : 'atores relacionados'} nas publicações.` : '',software.length ? `${software.length.toLocaleString('pt-BR')} ${software.length === 1 ? 'malware ou ferramenta relacionado' : 'malwares e ferramentas relacionados'}.` : ''].filter(Boolean).join(' ');
  const verdict = analysis.excluded ? analysis.priority : ['Malicioso','Suspeito'].includes(String(analysis.record.verdict)) ? String(analysis.record.verdict) : 'Sem evidência suficiente';
  const record: UnifiedRecord = {indicator:row.query,type:analysis.record.type,verdict,context,actors:joined(actors),actorIds:joined(actorIds),malware:joined(software),softwareIds:joined(softwareIds),techniques:joined(analysis.techniques),mentions:mentions.length,firstMention:stamps[0] || null,lastMention:stamps.at(-1) || null,abuseReports:analysis.record.abReports,country:analysis.record.country,asn:analysis.record.asn,organization:analysis.record.organization,prefix:analysis.record.prefix,rdns:analysis.record.rdns,registrar:analysis.record.registrar,created:analysis.record.created};
  return {record,mentions,analysis};
}

/** The registry stores each publication once; indicator-to-publication edges stay complete. */
export function createUnifiedBulkRegistry() {
  const documents = new Map<string,{id:string;title:string;date:string;link:string;actors:Set<string>;malware:Set<string>;techniques:Set<string>;indicators:Set<string>}>();
  const analyses: IocAnalysis[] = [], techniquesToActors = new Map<string,Set<string>>(); let mentions = 0;
  return {
    add(projection: UnifiedProjection) {
      const {record,analysis} = projection, records:UnifiedRecord[] = [], relations:UnifiedRecord[] = [];
      const actors = split(record.actors), families = split(record.malware);
      analyses.push({...analysis,actors,families,record:{type:record.type,tactics:analysis.record.tactics,publications:projection.mentions.length},row:{query:analysis.row.query,state:analysis.row.state,contextLoading:analysis.row.contextLoading,context:{evidence:[],publications:[],errors:analysis.row.context?.errors||[]},result:analysis.row.result ? {query:analysis.row.query,threatLevel:analysis.row.result.threatLevel,vendorData:analysis.row.result.vendorData.map(item=>({name:item.name,error:item.error,isLoading:item.isLoading,unsupported:item.unsupported,data:{}}))} : undefined} as BulkRow});
      for (const mention of projection.mentions) {
        let publication = documents.get(mention.link);
        if (!publication) { publication = {id:`PUB-${String(documents.size + 1).padStart(5,'0')}`,title:mention.title,date:mention.date,link:mention.link,actors:new Set(),malware:new Set(),techniques:new Set(),indicators:new Set()}; documents.set(mention.link,publication); }
        publication.indicators.add(String(record.indicator));
        for (const name of mention.actors) publication.actors.add(name);
        for (const name of mention.malware) publication.malware.add(name);
        for (const id of mention.techniques) {publication.techniques.add(id);const names=techniquesToActors.get(id)||new Set<string>();for(const actor of mention.actors)names.add(actor);techniquesToActors.set(id,names);}
        records.push({indicator:record.indicator,publication:publication.id,title:mention.title,actors:joined(mention.actors),malware:joined(mention.malware),association:mention.entities.some(entity=>entity.association==='Associação descrita na publicação')?'Associação descrita na publicação':'Menção em publicação'});
        for (const entity of mention.entities) relations.push({indicator:record.indicator,...entity,publication:publication.id,title:mention.title});
        mentions++;
      }
      return {record,mentions:records,relations};
    },
    finish() {
      const analysis=aggregateBulkAnalyses(analyses);
      const publications:UnifiedRecord[]=[...documents.values()].map(item=>({id:item.id,title:item.title,date:item.date,link:item.link,actors:joined([...item.actors]),malware:joined([...item.malware]),techniques:joined([...item.techniques]),count:item.indicators.size}));
      const techniqueRows:UnifiedRecord[]=analysis.techniques.map(item=>({id:item.name,count:item.count,actors:joined([...(techniquesToActors.get(item.name)||[])]),link:`https://attack.mitre.org/techniques/${item.name.replace('.','/')}/`}));
      return {analysis,publications,techniques:techniqueRows,mentions,publicationCount:documents.size,mentionedIndicators:analyses.filter(item=>Number(item.record.publications)>0).length};
    },
  };
}
