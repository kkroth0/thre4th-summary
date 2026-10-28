import { normalizeBulkVendor } from './bulkShared.generated.mjs';
export const BULK_PRINCIPAL=Symbol('authenticated bulk owner');

/** Invoke the existing read-only lookup handlers without cookies or loopback HTTP. */
export function createBulkProviderBridge(app,limiter){
 const handlers=new Map();
 return{
  register(route,name,handler){handlers.set(name,handler);app.post(route,limiter,handler);},
  async lookup(task){
   const handler=handlers.get(task.provider);if(!handler)throw Object.assign(Error('Fonte não disponível para o lote.'),{status:400});
   const principal={sub:task.owner,login:task.login,premiumViaOrg:task.org_until>Date.now(),exp:Math.floor(task.org_until/1000)},controller=new AbortController(),headers={};
   const req={headers:{},body:{query:task.query,fresh:Boolean(task.fresh)},user:principal,[BULK_PRINCIPAL]:principal,signal:controller.signal};
   let status=200,body,settled=false;
   const res={set(name,value){if(typeof name==='object')Object.assign(headers,name);else headers[String(name).toLowerCase()]=value;return res;},status(value){status=value;return res;},json(value){body=value;settled=true;return res;},getHeader(name){return headers[String(name).toLowerCase()];}};
   let timeout;try{
    await Promise.race([handler(req,res),new Promise((_,reject)=>{timeout=setTimeout(()=>{controller.abort();reject(Object.assign(Error('A fonte excedeu o tempo de consulta; nova tentativa agendada.'),{status:504}));},70000);timeout.unref();})]);
    if(!settled)throw Object.assign(Error('A fonte não concluiu a resposta.'),{status:502});
    if(status<400&&(!body||typeof body!=='object'||Array.isArray(body)||typeof body.data==='string'&&/^\s*(?:<!doctype|<html|<head)/i.test(body.data)))throw Object.assign(Error('A fonte devolveu uma resposta inválida; nova tentativa agendada.'),{status:502});
    const queryStatus=body?.query_status||body?.data?.query_status;
    if(/invalid_auth|unknown_auth_key|unauthorized|invalid_api_key/i.test(queryStatus||'')){status=403;body={error:'A fonte recusou a credencial.',code:'PROVIDER_AUTH_FAILED'};}
    if(/rate_limit|too_many/i.test(queryStatus||'')){status=429;body={error:'A fonte atingiu o limite de consultas.'};}
    if(status>=400&&!(status===404&&task.provider==='VirusTotal')){
     const auth=body?.code==='PROVIDER_AUTH_FAILED'||/API Key missing|authentication|configuration/i.test(body?.error||'');
     const retry=headers['retry-after'];let retryAt=Number(body?.retryAt)||undefined;
     if(!retryAt&&retry)retryAt=/^\d+$/.test(String(retry))?Date.now()+Number(retry)*1000:Date.parse(retry);
     throw Object.assign(Error(auth?'A fonte recusou a credencial. Revise a conexão em Chaves de API.':status===429?'Fonte aguardando renovação da cota.':'Fonte temporariamente indisponível; nova tentativa agendada.'),{status,code:auth?'PROVIDER_AUTH_FAILED':body?.code,retryAt});
    }
    return {...normalizeBulkVendor(task.query,task.provider,body,status),...(headers['x-lookup-collected-at']?{collectedAt:headers['x-lookup-collected-at'],cacheState:headers['x-lookup-cache']}:{})};
   }finally{clearTimeout(timeout);}
  },
 };
}
