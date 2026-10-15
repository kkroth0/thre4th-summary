import axios from 'axios';
import dns from 'node:dns/promises';
import net from 'node:net';

const privateIp = address => {
  if (net.isIP(address) === 4) {
    const [a,b,c] = address.split('.').map(Number);
    return a===0 || a===10 || a===127 || (a===100 && b>=64 && b<=127) || (a===169 && b===254) || (a===172 && b>=16 && b<=31) || (a===192 && b===168) || (a===192 && b===0 && [0,2].includes(c)) || (a===198 && [18,19].includes(b)) || (a===198 && b===51 && c===100) || (a===203 && b===0 && c===113) || a>=224;
  }
  if (net.isIP(address) === 6) return /^(::|fc|fd|fe[89ab]|ff|2001:db8)/i.test(address);
  return true;
};

async function abortable(task, signal) {
  signal.throwIfAborted();
  let abort;
  const cancelled=new Promise((_,reject)=>{abort=()=>reject(signal.reason);signal.addEventListener('abort',abort,{once:true});});
  try { return await Promise.race([task,cancelled]); }
  finally { signal.removeEventListener('abort',abort); }
}

// Public DNS queries avoid occupying libuv's shared getaddrinfo thread pool.
// Each lookup owns its resolver, so cancellation never cancels another source.
export async function resolvePublicationHost(host,{signal,createResolver=()=>new dns.Resolver()}={}) {
  signal.throwIfAborted();
  const family=net.isIP(host);
  if(family)return [{address:host,family}];
  const resolver=createResolver(),cancel=()=>resolver.cancel();
  signal.addEventListener('abort',cancel,{once:true});
  try {
    const results=await abortable(Promise.allSettled([resolver.resolve4(host),resolver.resolve6(host)]),signal);
    const records=results.flatMap((result,index)=>result.status==='fulfilled'?result.value.map(address=>({address,family:index?6:4})):[]);
    if(!records.length)throw results.find(result=>result.status==='rejected')?.reason||new Error('Publication DNS returned no addresses');
    return records;
  } finally { signal.removeEventListener('abort',cancel); resolver.cancel(); }
}

// Pin validated DNS records to the socket, and validate every redirect hop.
// One deadline covers DNS, sockets and all hops, including stalled lookups.
export function createPublicationRequest({ http=axios, lookup=resolvePublicationHost, timeoutMs=12000 }={}) {
  return async function request(address,{headers={},maxContentLength=8000000}={}) {
    const controller=new AbortController(),signal=controller.signal;
    const timer=setTimeout(()=>controller.abort(Object.assign(new Error('Publication request timed out'),{code:'ETIMEDOUT'})),timeoutMs);
    try {
      let current=address;
      for(let hop=0;hop<=3;hop++) {
        const target=new URL(current);
        if(!['http:','https:'].includes(target.protocol)||target.username||target.password||(target.port&&!['80','443'].includes(target.port))) throw new Error('Unsafe publication URL');
        const host=target.hostname.replace(/^\[|\]$/g,'');
        const records=await abortable(lookup(host,{all:true,signal}),signal);
        if(!records.length||records.some(record=>privateIp(record.address))) throw new Error('Non-public publication host');
        const record=records.find(row=>row.family===4)||records[0];
        const response=await abortable(http.get(target.href,{
          headers:{'User-Agent':'Mozilla/5.0 (compatible; ThreatSumm4ry/1.0; public publication collector)',Accept:'application/rss+xml,application/atom+xml,text/html,application/xml;q=0.9,*/*;q=0.5',...headers},
          timeout:7000,signal,responseType:'text',maxContentLength:Math.min(8000000,maxContentLength),maxRedirects:0,proxy:false,
          family:record.family,lookup:(name,options,callback)=>name===host?options?.all?callback(null,[record]):callback(null,record.address,record.family):callback(new Error('Unexpected DNS target')),
          validateStatus:status=>status>=200&&status<400,
        }),signal);
        if([301,302,303,307,308].includes(response.status)) {
          if(!response.headers?.location||hop===3) throw new Error('Publication redirect limit');
          current=new URL(response.headers.location,target).href; continue;
        }
        return {...response,url:target.href};
      }
      throw new Error('Publication redirect limit');
    } finally { clearTimeout(timer); }
  };
}
