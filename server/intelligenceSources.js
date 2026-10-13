import { normalizeIndicator } from './iocIntelligence.js';
import { createHash } from 'node:crypto';

const utc=value=>typeof value==='string'&&/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?: UTC)?$/.test(value)?value.replace(' ','T').replace(' UTC','')+'Z':value;
const strings=value=>Array.isArray(value)?value.filter(item=>typeof item==='string'):typeof value==='string'?[value]:[];
const cves=text=>(String(text||'').match(/\bCVE-\d{4}-\d{4,}\b/gi)||[]).map(id=>({id:id.toUpperCase(),name:id.toUpperCase()}));
const publicPulse=pulse=>pulse.public!==false&&pulse.public!==0&&(pulse.public===true||pulse.public===1||/^(?:white|clear|tlp:clear|tlp:white)$/i.test(pulse.tlp||''))&&(!pulse.tlp||/^(?:white|clear|tlp:clear|tlp:white)$/i.test(pulse.tlp));
const sourceEntityId=(prefix,name)=>prefix+createHash('sha256').update(name.trim().normalize('NFC').toLowerCase()).digest('hex').slice(0,24);

export function sourceObservations(provider,payload,{scope='global',query,matchActors=()=>[],matchMalware=()=>[]}={}) {
  const entities=text=>({actors:matchActors('Threat actors: '+text),malwares:matchMalware(text),cves:cves(text)});
  if(provider==='ThreatFox')return (Array.isArray(payload?.data)?payload.data:[]).flatMap(row=>{
    const value=normalizeIndicator(row.ioc,row.ioc_type);if(!value)return [];
    if(query&&normalizeIndicator(query)?.value!==value.value)return [];
    const labels=[...strings(row.tags),row.malware_printable,row.malware_alias].filter(Boolean).join(' ');
    const attribution=entities(labels);
    if(row.malware&&row.malware_printable)attribution.malwares=[{id:row.malware,name:row.malware_printable}];
    return [{value:value.value,type:value.type,scope,provider,externalId:String(row.id||value.value),published:utc(row.last_seen||row.first_seen),
      title:row.malware_printable?`${row.malware_printable} · ThreatFox`:'ThreatFox IOC',link:`https://threatfox.abuse.ch/ioc/${encodeURIComponent(row.id||'')}/`,
      confidence:Number(row.confidence_level)||0,tags:strings(row.tags),port:row.ioc_type==='ip:port'?row.ioc.split(':').at(-1):null,...attribution,relation:'attributed-by-source'}];
  });
  if(provider==='OTX') {
    const pulses=payload?.results||payload?.pulse_info?.pulses||[];
    return (Array.isArray(pulses)?pulses:[]).flatMap(pulse=>{
      if (!pulse.id) return [];
      if(scope==='global'&&!publicPulse(pulse))return [];
      const labels=[pulse.adversary,...strings(pulse.tags),...strings(pulse.malware_families),pulse.name].filter(Boolean).join(' ');
      const attribution=entities(labels);
      if(typeof pulse.adversary==='string'&&pulse.adversary.trim()&&!attribution.actors.length)attribution.actors=[{id:sourceEntityId('otx:',pulse.adversary),name:pulse.adversary.trim().slice(0,120)}];
      for(const name of strings(pulse.malware_families))if(!attribution.malwares.some(family=>family.name.toLowerCase()===name.toLowerCase()))attribution.malwares.push({id:sourceEntityId('otx-malware:',name),name:name.slice(0,120)});
      const metadata={scope,provider,externalId:String(pulse.id),published:utc(pulse.modified||pulse.created),title:String(pulse.name||'OTX pulse'),
        link:`https://otx.alienvault.com/pulse/${encodeURIComponent(pulse.id)}`,tags:strings(pulse.tags),...attribution,relation:'mentioned-by-source'};
      const indicators=Array.isArray(pulse.indicators)?pulse.indicators:query?[{indicator:query}]:[];
      return indicators.flatMap(row=>{if(!['IPv4','IPv6','domain','hostname','URL','FileHash-MD5','FileHash-SHA1','FileHash-SHA256',undefined].includes(row.type))return [];const value=normalizeIndicator(row.indicator);return value?[{...metadata,value:value.value,type:value.type}]:[];});
    });
  }
  if(provider==='AbuseIPDB') {
    const data=Array.isArray(payload?.data)?payload.data:Array.isArray(payload?.data?.reportedAddress)?payload.data.reportedAddress:payload?.data?.ipAddress?[payload.data]:[];
    return data.flatMap(row=>{
      const value=normalizeIndicator(row.ipAddress);if(value?.type!=='ip'||(normalizeIndicator(query)&&value.value!==normalizeIndicator(query)?.value))return [];
      return [{value:value.value,type:'ip',scope,provider,externalId:value.value,published:utc(row.lastReportedAt||row.mostRecentReport),title:'AbuseIPDB reputation',link:`https://www.abuseipdb.com/check/${encodeURIComponent(value.value)}`,
        confidence:Number(row.abuseConfidenceScore)||0,reputation:{abuseConfidenceScore:Number(row.abuseConfidenceScore)||0,totalReports:Number(row.totalReports)||0,countryCode:row.countryCode||'',isp:row.isp||''},actors:[],malwares:[],relation:'reputation'}];
    });
  }
  if(provider==='MalwareBazaar')return (Array.isArray(payload?.data)?payload.data:[]).flatMap(row=>{
    const labels=[row.signature,...strings(row.tags)].filter(Boolean).join(' '),attribution=entities(labels);
    if(row.signature&&!attribution.malwares.length)attribution.malwares=[{id:'bazaar:'+row.signature.toLowerCase().replace(/[^a-z0-9]+/g,'-'),name:row.signature}];
    return [row.sha256_hash,row.sha1_hash,row.md5_hash].filter(Boolean).flatMap(hash=>{const value=normalizeIndicator(hash);return value?.type==='hash'?[{value:value.value,type:'hash',scope,provider,externalId:row.sha256_hash||hash,published:utc(row.last_seen||row.first_seen),title:`${row.signature||'Malware sample'} · MalwareBazaar`,link:`https://bazaar.abuse.ch/sample/${encodeURIComponent(row.sha256_hash||hash)}/`,tags:strings(row.tags),...attribution,relation:'attributed-by-source'}]:[];});
  });
  if(provider==='VirusTotal') {
    const attributes=payload?.data?.attributes;
    const value=normalizeIndicator(query);if(!value||!attributes)return [];
    const labels=[...strings(attributes.tags),...strings(attributes.popular_threat_classification?.popular_threat_name?.map(row=>row.value)),attributes.popular_threat_classification?.suggested_threat_label].filter(Boolean).join(' ');
    return [{...value,scope,provider,externalId:value.value,title:'VirusTotal analysis',link:`https://www.virustotal.com/gui/${value.type==='ip'?'ip-address':value.type==='hash'?'file':value.type}/${encodeURIComponent(value.value)}`,
      published:attributes.last_analysis_date?new Date(attributes.last_analysis_date*1000).toISOString():undefined,
      reputation:{stats:attributes.last_analysis_stats||{},reputation:attributes.reputation??null,asn:attributes.asn??null,country:attributes.country||''},tags:strings(attributes.tags),...entities(labels),relation:'reported-label'}];
  }
  if(provider==='Shodan') {
    const value=normalizeIndicator(query);if(!value)return [];
    return [{...value,scope,provider,externalId:value.value,title:'Shodan observed infrastructure',link:`https://www.shodan.io/host/${encodeURIComponent(value.value)}`,
      published:payload?.last_update,reputation:{ports:payload?.ports||[],organization:payload?.org||'',asn:payload?.asn||''},cves:cves(Object.keys(payload?.vulns||{}).join(' ')),actors:[],malwares:[],relation:'observed-on-host'}];
  }
  // Other provider queries still become attributable, persistent observations
  // without inventing malware/actor associations from vendor detection names.
  const value=normalizeIndicator(query);
  if(!value)return [];
  return [{...value,scope,provider,externalId:value.value,title:`${provider} lookup`,link:'',relation:'lookup',actors:[],malwares:[]}];
}

export function createIntelligenceCollector({store,http,getKeys,matchActors,matchMalware,scope='global',now=()=>Date.now()}={}) {
  let flight=null;
  const options=headers=>({headers:{Accept:'application/json',...headers},timeout:15000,maxContentLength:8000000,maxRedirects:0,family:4});
  const stateKey=id=>scope==='global'?'source:'+id:`source:${scope}:${id}`;
  const record=(provider,data)=>store.ingest(sourceObservations(provider,data,{scope,matchActors,matchMalware}));
  const definitions=[
    {id:'ThreatFox',interval:3600000,key:()=>getKeys('abuse_ch'),load:key=>http.post('https://threatfox-api.abuse.ch/api/v1/',{query:'get_iocs',days:7},options({'Auth-Key':key}))},
    {id:'MalwareBazaar',interval:1800000,key:()=>getKeys('abuse_ch'),load:key=>http.post('https://mb-api.abuse.ch/api/v1/','query=get_recent&selector=time',options({'Auth-Key':key,'Content-Type':'application/x-www-form-urlencoded'}))},
    {id:'AbuseIPDB',interval:6*3600000,key:()=>getKeys('abuseipdb'),load:key=>http.get('https://api.abuseipdb.com/api/v2/blacklist',{...options({Key:key}),params:{confidenceMinimum:90,limit:1000}})},
    {id:'OTX',interval:15*60000,key:()=>getKeys('otx')},
  ];
  function otxUrl(next){const url=new URL(next);if(url.origin!=='https://otx.alienvault.com'||url.pathname.replace(/\/$/,'')!=='/api/v1/pulses/subscribed'||url.username||url.password)throw Error('Unsafe OTX cursor');return url.href;}
  async function collectOtx(key,previous){
    let cursor=previous.cursor||`https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20&modified_since=${encodeURIComponent(previous.watermark||new Date(now()-7*86400000).toISOString())}`;
    let count=0,high=previous.pendingWatermark||previous.watermark||'';
    for(let page=0;page<2&&cursor;page++){
      const response=await http.get(otxUrl(cursor),options({'X-OTX-API-KEY':key}));
      if(!Array.isArray(response.data?.results))throw Error('Invalid OTX result');
      count+=await record('OTX',response.data);
      for(const pulse of response.data.results)if(Date.parse(pulse.modified)>Date.parse(high||'1970-01-01'))high=new Date(pulse.modified).toISOString();
      cursor=response.data.next?otxUrl(response.data.next):null;
    }
    return {count,cursor,watermark:cursor?previous.watermark:high?new Date(Date.parse(high)-30*60000).toISOString():previous.watermark,pendingWatermark:cursor?high:null};
  }
  async function cycle(){
    // Sequential sources and bounded pages keep CPU, RAM and upstream calls
    // separate from the news request path. Every cursor is persisted.
    for(const definition of definitions){
      let previous=store.state(stateKey(definition.id))||{};
      const key=String(definition.key()||'').trim();
      if(!key){store.setState(stateKey(definition.id),{...previous,status:'missing_key',configured:false});continue;}
      const credentialRevision=createHash('sha256').update(key).digest('hex');
      if(previous.credentialRevision!==credentialRevision||previous.status==='missing_key')previous={credentialRevision};
      if(previous.nextAt&&Date.parse(previous.nextAt)>now())continue;
      try{
        let progress;
        if(definition.id==='OTX')progress=await collectOtx(key,previous);
        else{
          const response=await definition.load(key);
          if(response.data?.query_status&&!['ok','no_results','no_iocs'].includes(response.data.query_status))throw Error('Provider rejected query');
          progress={count:await record(definition.id,response.data)};
        }
        store.setState(stateKey(definition.id),{...previous,...progress,status:'ready',configured:true,lastSuccessfulAt:new Date(now()).toISOString(),error:null,nextAt:new Date(now()+definition.interval).toISOString()});
      }catch(error){
        const status=error.response?.status;
        const reset=Number(error.response?.headers?.['x-ratelimit-reset'])*1000;
        const retry=Number(error.response?.headers?.['retry-after'])*1000;
        const delay=status===429?Math.max(definition.interval,Number.isFinite(reset)?reset-now():0,Number.isFinite(retry)?retry:0):definition.interval;
        store.setState(stateKey(definition.id),{...previous,configured:true,status:status===429?'rate_limited':[401,403].includes(status)?'auth_error':'error',error:status?`HTTP ${status}`:'Provider unavailable',nextAt:new Date(now()+delay).toISOString()});
      }
    }
  }
  return {run:()=>flight||(flight=cycle().finally(()=>{flight=null;})),status:()=>definitions.map(source=>{
    const saved=store.state(stateKey(source.id))||{};
    return {id:source.id,status:saved.status,configured:saved.configured,count:saved.count,lastSuccessfulAt:saved.lastSuccessfulAt,nextAt:saved.nextAt,error:saved.error,hasMore:!!saved.cursor};
  })};
}
