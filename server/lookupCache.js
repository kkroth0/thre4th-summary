import { createHash } from 'node:crypto';
import { createLookupSnapshots } from './lookupSnapshots.js';
import { detectQueryType } from './iocValidation.js';

export function canonicalLookupQuery(provider,query){
    const normalize=value=>{const kind=detectQueryType(value);if(kind==='url')return new URL(value).href;if(kind==='domain'||kind==='hash')return value.toLowerCase();if(kind==='ip'&&value.includes(':'))return new URL(`http://[${value}]/`).hostname.slice(1,-1);return value;};
    if(provider==='urlhaus'&&!/^https?:/i.test(query)&&query.includes('=')){const params=new URLSearchParams(query);for(const [name,value]of params)params.set(name,normalize(value));return params.toString();}
    return normalize(query);
}

// Only passive provider lookups use this cache. Keys include the account and
// credential fingerprint; errors never become successful cached answers.
export function createLookupCache({ now = () => Date.now(), ttlMs = 300000, maxBytes = 16 * 1024 * 1024, maxEntries = 1000, maxPending = 128, filePath, readArchive } = {}) {
    const saved = new Map(), pending = new Map();
    const snapshots=filePath?createLookupSnapshots(filePath):null;
    let bytes = 0;
    const stats = { hits: 0, misses: 0, coalesced: 0, errors: 0 };
    const remove = key => { bytes -= saved.get(key)?.bytes || 0; saved.delete(key); };
    const reusable = value => value?.data && typeof value.data === 'object' && (value.httpStatus===404 || value.data.success !== false && !value.data.error && !value.data.errors && !/invalid|unauthorized|unknown_query|rate_limit|too_many/i.test(String(value.data.query_status || '')));
    const validPayload=(provider,value)=>{
        if(value.httpStatus===404)return true;const data=value.data;
        if(provider==='virustotal')return !!data?.data?.attributes;
        if(provider==='abuseipdb')return !!data?.data?.ipAddress&&data.data.abuseConfidenceScore!=null;
        if(provider==='otx')return !!data?.pulse_info&&(data.pulse_info.count!=null||Array.isArray(data.pulse_info.pulses));
        if(['threatfox','urlhaus','malwarebazaar'].includes(provider))return /^(no_results?|hash_not_found|url_not_found|host_not_found)$/.test(data?.query_status||'') || data?.query_status==='ok'&&(provider==='urlhaus'||Array.isArray(data.data));
        return true;
    };
    const remember=(key,snapshot)=>{const size=Buffer.byteLength(JSON.stringify(snapshot.value));if(size<=Math.min(maxBytes,1024*1024)){remove(key);saved.set(key,{...snapshot,value:structuredClone(snapshot.value),expiresAt:now()+ttlMs,bytes:size});bytes+=size;while(bytes>maxBytes||saved.size>maxEntries)remove(saved.keys().next().value);}};
    return {
        async get({ provider, query, owner = '', credentials = '', fresh = false, archiveQuery }, load) {
            const normalized=canonicalLookupQuery(provider,query);
            const key = createHash('sha256').update(JSON.stringify(snapshots?[provider,normalized,owner]:[provider,normalized,owner,credentials])).digest('hex');
            const request={provider,query,owner};
            const entry = saved.get(key);
            if (!fresh && entry && entry.expiresAt > now()) {
                stats.hits++; saved.delete(key); saved.set(key, entry);
                return { value: structuredClone(entry.value), state: 'hit', collectedAt: entry.collectedAt };
            }
            if (entry?.expiresAt <= now()) remove(key);
            if (pending.has(key)) { stats.coalesced++; return { ...await pending.get(key), state: 'shared' }; }
            if (pending.size >= maxPending) throw Object.assign(new Error('Lookup capacity reached'), { response: { status: 503 } });
            const flight = Promise.resolve().then(async()=>{
                if(!fresh&&snapshots){
                    const stored=snapshots.get(key);
                    if(stored&&(ttlMs===Infinity||Date.parse(stored.collectedAt)+ttlMs>now())){stats.hits++;remember(key,stored);return{...stored,state:'persistent-hit'};}
                    const archived=await readArchive?.({provider,query:archiveQuery||query,owner});
                    if(archived&&reusable(archived.value)&&validPayload(provider,archived.value)){snapshots.save(key,request,archived);stats.hits++;remember(key,archived);return{...archived,state:'archive-hit'};}
                }
                stats.misses++;
                let value;try{value=await load();}catch(error){
                    if(!snapshots||!['virustotal','shodan'].includes(provider)||error.response?.status!==404)throw error;
                    value={data:error.response.data||{error:'Resource not found'},headers:{},httpStatus:404};
                }
                const collectedAt = new Date(now()).toISOString();
                if(snapshots&&reusable(value)&&!validPayload(provider,value))throw Object.assign(Error('A fonte devolveu uma resposta incompleta; nenhuma ausência foi registrada.'),{response:{status:502}});
                if (reusable(value)) {
                    snapshots?.save(key,request,{value,collectedAt});
                    remember(key,{value,collectedAt});
                }
                return { value, state: 'miss', collectedAt };
            }).catch(error => { stats.errors++; throw error; }).finally(() => pending.delete(key));
            pending.set(key, flight);
            return flight;
        },
        stats: () => ({ ...stats, entries: saved.size, pending: pending.size, bytes, ttlMs:Number.isFinite(ttlMs)?ttlMs:null, maxBytes,policy:ttlMs===Infinity?'manual_refresh':'ttl',storedSnapshots:snapshots?.count()||0 }),
        close:()=>snapshots?.close(),
    };
}
