import { normalizeIndicator } from './iocIntelligence.js';
import { createHash } from 'node:crypto';

const utc=value=>typeof value==='string'&&/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?: UTC)?$/.test(value)?value.replace(' ','T').replace(' UTC','')+'Z':value;
const strings=value=>Array.isArray(value)?value.filter(item=>typeof item==='string'):typeof value==='string'?[value]:[];
const familyLabels=value=>(Array.isArray(value)?value:[]).flatMap(item=>typeof item==='string'?[item]:typeof item?.display_name==='string'?[item.display_name]:typeof item?.id==='string'?[item.id]:[]);
const cves=text=>(String(text||'').match(/\bCVE-\d{4}-\d{4,}\b/gi)||[]).map(id=>({id:id.toUpperCase(),name:id.toUpperCase()}));
const publicPulse=pulse=>{const tlp=pulse.TLP||pulse.tlp||'';return pulse.public!==false&&pulse.public!==0&&(pulse.public===true||pulse.public===1||/^(?:white|clear|tlp:clear|tlp:white)$/i.test(tlp))&&(!tlp||/^(?:white|clear|tlp:clear|tlp:white)$/i.test(tlp));};
const sourceEntityId=(prefix,name)=>prefix+createHash('sha256').update(name.trim().normalize('NFC').toLowerCase()).digest('hex').slice(0,24);
export function threatFoxDays(previous,at){
  const last=Date.parse(previous.lastSuccessfulAt||'');
  return Number.isFinite(last)?Math.min(7,Math.max(1,Math.ceil((at-last+3600000)/86400000))):7;
}

export function sourceObservations(provider,payload,{scope='global',query,matchActors=()=>[],matchMalware=()=>[]}={}) {
  const entities=(text,labels=[])=>({actors:matchActors('Threat actors: '+text),malwares:[...new Map([...matchMalware(text),...labels.flatMap(label=>matchMalware(label,{structured:true}))].map(row=>[row.id,row])).values()],cves:cves(text)});
  const signature=(name,prefix)=>typeof name==='string'&&name.trim()?matchMalware(name,{structured:true}).length?matchMalware(name,{structured:true}):[{id:sourceEntityId(prefix,name),name:name.trim().slice(0,120)}]:[];
  if(['ThreatFox','MalwareBazaar','URLhaus'].includes(provider)&&payload?.query_status&&payload.query_status!=='ok')return [];
  if(provider==='ThreatFox')return (Array.isArray(payload?.data)?payload.data:[]).flatMap(row=>{
    const value=normalizeIndicator(row.ioc,row.ioc_type);if(!value)return [];
    if(query&&normalizeIndicator(query)?.value!==value.value)return [];
    const labels=[...strings(row.tags),row.malware_printable,row.malware_alias].filter(Boolean).join(' ');
    const attribution=entities(labels,strings(row.tags));
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
      const families=familyLabels(pulse.malware_families);
      const labels=[pulse.adversary,...strings(pulse.tags),...families,pulse.name,pulse.description].filter(Boolean).join('\n');
      const attribution=entities(labels,[...strings(pulse.tags),...families]);
      if(typeof pulse.adversary==='string'&&pulse.adversary.trim()&&!attribution.actors.length)attribution.actors=[{id:sourceEntityId('otx:',pulse.adversary),name:pulse.adversary.trim().slice(0,120)}];
      for(const name of families)for(const family of signature(name,'otx-malware:'))if(!attribution.malwares.some(row=>row.id===family.id))attribution.malwares.push(family);
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
    const labels=[row.signature,...strings(row.tags)].filter(Boolean).join(' '),attribution=entities(labels,strings(row.tags));
    if(typeof row.signature==='string'&&row.signature.trim())attribution.malwares=signature(row.signature,'bazaar:');
    // A sample's signature names malware, not its operator. Only separate
    // actor tags may contribute actor evidence (e.g. Lazarus, not WannaCry).
    const familyIds=new Set(attribution.malwares.map(family=>family.id));
    const actorTags=strings(row.tags).filter(tag=>tag.trim().toLowerCase()!==String(row.signature||'').trim().toLowerCase()&&!matchMalware(tag,{structured:true}).some(family=>familyIds.has(family.id)));
    attribution.actors=matchActors('Threat actors: '+actorTags.join('\n'));
    return [row.sha256_hash,row.sha1_hash,row.md5_hash].filter(Boolean).flatMap(hash=>{const value=normalizeIndicator(hash);return value?.type==='hash'?[{value:value.value,type:'hash',scope,provider,externalId:row.sha256_hash||hash,published:utc(row.last_seen||row.first_seen),title:`${row.signature||'Malware sample'} · MalwareBazaar`,link:`https://bazaar.abuse.ch/sample/${encodeURIComponent(row.sha256_hash||hash)}/`,tags:strings(row.tags),...attribution,relation:'attributed-by-source'}]:[];});
  });
  if(provider==='URLhaus') {
    const value=normalizeIndicator(query);if(!value)return [];
    const rows=[], urls=Array.isArray(payload?.urls)?payload.urls:[], payloads=Array.isArray(payload?.payloads)?payload.payloads:[];
    const attribution=(row)=>{
      const tags=strings(row?.tags),names=[...strings(row?.signature),...(row?.payloads||[]).flatMap(item=>strings(item.signature))];
      const result=entities([...tags,...names].join(' '),tags);
      for(const name of names)for(const family of signature(name,'urlhaus:'))if(!result.malwares.some(item=>item.id===family.id))result.malwares.push(family);
      return result;
    };
    const add=(ioc,row,extra={},id)=>{if(!ioc)return;rows.push({...ioc,scope,provider,externalId:id||row.id||ioc.value,title:'URLhaus indicator lookup',link:row.urlhaus_reference||payload?.urlhaus_reference||`https://urlhaus.abuse.ch/browse/search/${encodeURIComponent(ioc.value)}/`,published:utc(row.lastseen||row.firstseen||row.date_added||payload?.lastseen||payload?.firstseen),tags:strings(row.tags),...attribution(row),...extra,relation:'reported-by-source'});};
    // Preserve the queried indicator and each URL's own labels; do not spread
    // one URL's family across other payloads merely sharing a host.
    if(urls.length){
      for(const row of urls){
        const merged=value.type==='hash'?{...row,signature:payload.signature}:row;
        add(value,merged,{},`lookup:${value.value}:${row.id||row.url||row.urlhaus_reference}`);
        const url=normalizeIndicator(row.url);add(url,merged,{},`url:${row.id||row.url}`);
        if(url)add(normalizeIndicator(new URL(url.value).hostname.replace(/^\[|\]$/g,'')),merged,{},`url:${row.id||row.url}`);
      }
    }else {
      add(value,payload);
      if(value.type==='url')add(normalizeIndicator(new URL(value.value).hostname.replace(/^\[|\]$/g,'')),payload,{},value.value);
    }
    for(const row of payloads){
      const extra=typeof row.signature==='string'&&row.signature.trim()?{...attribution(row),malwares:signature(row.signature,'urlhaus:')}:{...attribution(row)};
      for(const hash of [row.sha256_hash||row.response_sha256,row.md5_hash||row.response_md5])add(normalizeIndicator(hash),row,extra,`payload:${row.sha256_hash||row.response_sha256||hash}`);
    }
    return rows;
  }
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

export function createIntelligenceCollector({store,http,getKeys,matchActors,matchMalware,onQuota=()=>{},scope='global',now=()=>Date.now()}={}) {
  let flight=null;
  const options=headers=>({headers:{Accept:'application/json',...headers},timeout:15000,maxContentLength:8000000,maxRedirects:0,family:4});
  const stateKey=id=>scope==='global'?'source:'+id:`source:${scope}:${id}`;
  const record=(provider,data)=>store.ingest(sourceObservations(provider,data,{scope,matchActors,matchMalware}));
  const definitions=[
    {id:'ThreatFox',interval:3600000,key:()=>getKeys('abuse_ch'),load:(key,previous)=>http.post('https://threatfox-api.abuse.ch/api/v1/',{query:'get_iocs',days:threatFoxDays(previous,now())},{...options({'Auth-Key':key}),maxContentLength:32000000})},
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
      if(previous.collectorVersion!==3){previous={...previous,collectorVersion:3,
        nextAt:['rate_limited','auth_error'].includes(previous.status)?previous.nextAt:null,
        ...(definition.id==='OTX'?{cursor:null,pendingWatermark:null,watermark:new Date(now()-7*86400000).toISOString()}:{} )};}
      if(previous.nextAt&&Date.parse(previous.nextAt)>now())continue;
      try{
        let progress;
        if(definition.id==='OTX')progress=await collectOtx(key,previous);
        else{
          const response=await definition.load(key,previous);
          if(definition.id==='AbuseIPDB')onQuota('AbuseIPDB',response.headers,key,'blacklist');
          if(response.data?.query_status&&!['ok','no_results','no_iocs'].includes(response.data.query_status))throw Error('Provider rejected query');
          progress={count:await record(definition.id,response.data)};
        }
        store.setState(stateKey(definition.id),{...previous,...progress,status:'ready',configured:true,failures:0,lastSuccessfulAt:new Date(now()).toISOString(),error:null,nextAt:new Date(now()+definition.interval).toISOString()});
      }catch(error){
        const status=error.response?.status;
        if(definition.id==='AbuseIPDB'&&status===429)onQuota('AbuseIPDB',error.response.headers,key,'blacklist');
        const reset=Number(error.response?.headers?.['x-ratelimit-reset'])*1000;
        const retry=Number(error.response?.headers?.['retry-after'])*1000;
        const failures=(previous.failures||0)+1;
        const transient=status>=500||['ECONNABORTED','ETIMEDOUT','ECONNRESET','EAI_AGAIN'].includes(error.code);
        const delay=status===429?Math.max(definition.interval,Number.isFinite(reset)?reset-now():0,Number.isFinite(retry)?retry:0):transient?Math.min(definition.interval,300000,60000*2**Math.min(failures-1,3)):definition.interval;
        store.setState(stateKey(definition.id),{...previous,configured:true,failures,status:status===429?'rate_limited':[401,403].includes(status)?'auth_error':'error',error:status?`HTTP ${status}`:/maxContentLength/.test(error.message||'')?'Response exceeds size limit':'Provider unavailable',nextAt:new Date(now()+delay).toISOString()});
      }
    }
  }
  return {run:()=>flight||(flight=cycle().finally(()=>{flight=null;})),status:()=>definitions.map(source=>{
    const saved=store.state(stateKey(source.id))||{};
    return {id:source.id,status:saved.status,configured:saved.configured,count:saved.count,lastSuccessfulAt:saved.lastSuccessfulAt,nextAt:saved.nextAt,error:saved.error,hasMore:!!saved.cursor};
  })};
}
