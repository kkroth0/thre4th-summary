import crypto from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { normalizeIndicator } from './iocIntelligence.js';
import { actorNameKey } from './actorIdentity.js';

const BASE = 'https://api.axur.com/gateway/1.0/api';
const REQUEST_POLICY = 'latency-v2';
const IOC_TIMEOUT_MS = 240000;
const INSIGHT_TIMEOUT_MS = 55000;
const PAGE_SIZES = [100, 500, 1000, 5000];
const issue = (code, detail = {}) => Object.assign(new Error(code), { code, ...detail });
const issueLabels = {
  timeout: 'A consulta à Axur excedeu o tempo limite; nova tentativa agendada.',
  network: 'Falha de comunicação com a Axur; nova tentativa agendada.',
  response_size: 'A resposta da Axur excedeu o limite; o próximo lote será menor.',
  pagination: 'A paginação da Axur mudou. O ponto de retomada foi preservado.',
  repeated_page: 'A Axur repetiu uma página. O ponto de retomada foi preservado.',
  incomplete_page: 'A Axur devolveu uma página incompleta; nova tentativa agendada.',
  missing_insights: 'A Axur não devolveu todos os relatórios relacionados; os vínculos serão tentados novamente.',
  storage: 'A carga aguarda espaço livre no servidor.',
  conversion: 'Um registro da Axur precisa de revisão de formato. O lote foi preservado para nova tentativa.',
  ingest: 'Não foi possível gravar o lote. O ponto de retomada foi preservado.',
};
function smallerPage(state) {
  const size=[...PAGE_SIZES].reverse().find(size=>size<state.pageSize);
  return size?resizePage(state,size):state;
}
const nextOffset = state => state.resumeOffset ?? (state.page-1)*state.pageSize;
function resizePage(state, size) {
  const offset=nextOffset(state);
  // Read an overlapping page when the committed position is not aligned with
  // the larger size. Only its uncommitted suffix is ingested and counted.
  return {...state,page:Math.floor(offset/size)+1,pageSize:size,resumeOffset:offset,successStreak:0};
}
const id = value => crypto.createHash('sha256').update(value.toLowerCase()).digest('hex').slice(0, 24);
const iso = value => { const date = new Date(value); return value && Number.isFinite(date.getTime()) ? date.toISOString() : undefined; };
const names = values => [...new Set((Array.isArray(values)?values:[]).map(value => typeof value === 'string' ? value.trim() : typeof value?.name==='string'?value.name.trim():'').filter(value => value && value.length <= 200 && !/^(unknown|n\/a|none|unattributed|desconhecido)$/i.test(value)))];
function entities(values, kind, match) {
  return names(values).map(name => {
    // Resolve only an exact catalog name/alias. The report's narrative must not
    // turn a different actor into an attribution for this indicator.
    const known = (match?.(name, { structured: true }) || []).find(entity => [entity.name, entity.matched, ...(entity.aliases || [])].some(alias => kind==='actor'?actorNameKey(alias)===actorNameKey(name):String(alias || '').toLowerCase() === name.toLowerCase()));
    return known || { id: `axur:${kind}:${id(name)}`, name };
  });
}

export function axurObservations(iocs, insights, { scope, matchActors, matchMalware } = {}) {
  if (!scope || scope === 'global') throw new Error('Axur requires an account scope');
  const reports = new Map(insights.map(report => [report.id, report]));
  const reportEntities=new Map(),families=new Map();
  return iocs.flatMap(ioc => {
    const indicator = normalizeIndicator(ioc.value, ioc.type);
    if (!indicator || !ioc.id) return [];
    const base = { ...indicator, provider: 'Axur', scope, source: `Axur / ${ioc.source || 'CTI'}`, confidence: ioc.confidenceScore,
      published: iso(ioc.createdAt), tags: ioc.tags || [], relation: 'mentioned-with' };
    const payload = { id: ioc.id, upstreamSource: ioc.source, description: ioc.description, threatName: ioc.threatName,
      threatLevel: ioc.threatLevel, trustFactor: ioc.trustFactor, relatedTTPs: ioc.relatedTTPs || [], relatedInsights: ioc.relatedInsights || [], enrichedAt: iso(ioc.enrichedAt) };
    // AV detection labels (e.g. Generic.Trojan) are retained as evidence rather
    // than automatically creating a malware family or threat actor.
    const familyName=typeof ioc.threatName==='string'?ioc.threatName:'';
    if(familyName&&!families.has(familyName))families.set(familyName,(matchMalware?.(familyName,{structured:true}) || []).filter(entity=>[entity.name,entity.matched].some(name=>String(name || '').toLowerCase()===familyName.toLowerCase())));
    const family=families.get(familyName)||[];
    const rows = [{ ...base, externalId: `ioc:${ioc.id}`, title: ioc.description || ioc.threatName || `IOC ${ioc.source || 'Axur'}`, payload, ...(family.length === 1 ? { malwares:family, relation:'mentioned-by-source' } : {}) }];
    for (const reportId of new Set(ioc.relatedInsights || [])) {
      const report = reports.get(reportId);
      if (!report) continue;
      if(!reportEntities.has(reportId))reportEntities.set(reportId,{
        actors:entities(report.threatActors,'actor',matchActors),malwares:entities(report.malwares,'malware',matchMalware),
        cves:[...new Set((report.vulnerabilities || []).map(value=>typeof value==='string'?value:value?.vulnerability).filter(value=>/^CVE-\d{4}-\d{4,}$/i.test(value)))].map(value=>({id:value.toUpperCase(),name:value.toUpperCase()})),
      });
      rows.push({ ...base, externalId: `insight:${reportId}`, title: report.title, link: `https://cti.axur.com/insight/${encodeURIComponent(reportId)}`,
        published: iso(report.publicationDate) || base.published,
        tags: [...new Set([...(ioc.tags || []), ...(report.tags || [])])],
        ...reportEntities.get(reportId),
        payload: { insightId: reportId, association: 'reported-in-same-insight', threatLevel: report.threatLevel, attacks: report.attacks || [], lastUpdate: iso(report.lastUpdate) } });
    }
    return rows;
  });
}

// The two Axur endpoints are deliberately GET-only. No export/search creation,
// changes to the tenant, or other Axur operations are available through this client.
export function createAxurImport({ store, scope, getKey, http, matchActors, matchMalware, canWrite = () => true, now = Date.now, sleep = delay, pageSize = 5000 } = {}) {
  if (!scope || scope === 'global') throw new Error('Axur requires an account scope');
  const stateKey = `axur-import-v1:${scope}`;
  let flight;
  const status = () => ({ id: 'axur', configured: !!getKey(), ...(store.state(stateKey) || { page: 1, processed: 0, observations: 0, status: 'pending' }) });
  async function read(endpoint, params) {
    const key = getKey();
    if (!key) throw Object.assign(new Error('Axur key unavailable'), { status: 401 });
    try {
      const timeout=endpoint==='/cyber-iocs/v2/iocs'?IOC_TIMEOUT_MS:INSIGHT_TIMEOUT_MS;
      return (await http.get(`${BASE}${endpoint}`, { params: { lang: 'pt-BR', ...params }, headers: { Authorization: `Bearer ${key}` }, timeout, maxRedirects: 0, maxContentLength: 32 * 1024 * 1024 })).data;
    } catch (error) {
      const status = Number(error.response?.status) || 0;
      const retry = error.response?.headers?.['retry-after'];
      const retryMs = Number.isFinite(Number(retry)) ? Number(retry) * 1000 : Date.parse(retry) - now();
      // Never expose Axios errors: their config contains Authorization.
      const oversized=error.code==='ERR_BAD_RESPONSE'&&!status&&/maxContentLength.*exceeded/i.test(String(error.message||''));
      const code=['ECONNABORTED','ETIMEDOUT','ERR_CANCELED'].includes(error.code)?'timeout':oversized?'response_size':'network';
      throw issue(code,{ status, retryMs });
    }
  }
  async function runPages(maxPages) {
    let state = store.state(stateKey) || { page: 1, pageSize, processed: 0, observations: 0, startedAt: new Date(now()).toISOString() };
    if (!getKey() || state.status === 'complete' || state.nextAttemptAt > now()) return status();
    if(state.requestPolicy!==REQUEST_POLICY){
      // Earlier timeouts reduced even 100-record pages with ~48s fixed latency.
      // Recover throughput without changing the committed cursor or cooldown.
      if([100,500].includes(state.pageSize)&&(!state.failureCode||['timeout','network'].includes(state.failureCode)))state=resizePage(state,1000);
      else if(state.status==='retrying'&&!state.failureCode&&!/^Axur HTTP/.test(state.error || ''))state=smallerPage(state);
      state={...state,requestPolicy:REQUEST_POLICY,successStreak:0};
    }
    let stage='storage';
    const started=now();
    try {
      for (let index = 0; index < maxPages; index++) {
        stage='storage';
        if (!canWrite()) throw issue('storage');
        if((state.successStreak||0)>=3){
          const larger=PAGE_SIZES.find(size=>size>state.pageSize&&size<=(state.pageSizeCeiling||5000));
          if(larger)state=resizePage(state,larger);
        }
        const size = state.pageSize;
        const pageStarted=now(),timings={};
        stage='iocs';
        state={...state,status:'running',error:null,nextAttemptAt:0,lastAttemptAt:new Date(now()).toISOString(),activeStage:stage,requestTimeoutMs:IOC_TIMEOUT_MS};
        store.setState(stateKey,state);
        const data = await read('/cyber-iocs/v2/iocs', { page: state.page, perPage: size });
        timings.iocsMs=now()-pageStarted;
        const meta = data?.metadata;
        if (!Array.isArray(data?.iocs) || !meta || meta.page !== state.page || meta.perPage !== size || meta.offset !== (state.page - 1) * size || !Number.isSafeInteger(meta.total) || meta.total < 0 || data.iocs.length > size) throw issue('pagination');
        const fingerprint = id(data.iocs.map(ioc => ioc.id).join(','));
        if (data.iocs.length && state.lastPageFingerprint === fingerprint) throw issue('repeated_page');
        if (!data.iocs.length && meta.offset < meta.total) throw issue('incomplete_page');
        if (data.iocs.length < size && meta.offset + data.iocs.length < meta.total) throw issue('incomplete_page');
        const replayed=Math.max(0,nextOffset(state)-meta.offset);
        if(replayed>=size)throw issue('pagination');
        const iocs=data.iocs.slice(replayed);
        const reportIds = [...new Set(iocs.flatMap(ioc => ioc.relatedInsights || []))];
        const insights = [];
        const missing=[];let reportCacheHits=0;
        const credentialRevision=crypto.createHash('sha256').update(getKey()).digest('hex');
        const insightStarted=now();
        for(const reportId of reportIds){
          const cache=store.state(`axur-report-v1:${scope}:${reportId}`);
          if(cache?.expires>now()&&cache.credentialRevision===credentialRevision){insights.push(cache.report);reportCacheHits++;}else missing.push(reportId);
        }
        stage='insights';
        store.setState(stateKey,{...state,activeStage:stage});
        for (let start = 0; start < missing.length; start += 25) {
          const batch = missing.slice(start, start + 25);
          const reports = await read('/cyber-insights/v1/insights/bulk/search', { ids: batch.join(',') });
          if (!Array.isArray(reports) || batch.some(reportId => !reports.some(report => report.id === reportId))) throw issue('missing_insights');
          for(const report of reports.filter(report=>batch.includes(report.id))){
            if(['threatActors','malwares','vulnerabilities','attacks','tags'].some(key=>report[key]!==undefined&&!Array.isArray(report[key])))throw issue('conversion');
            const projected=Object.fromEntries(['id','publicationDate','lastUpdate','title','threatLevel','threatActors','malwares','vulnerabilities','attacks','tags'].filter(key=>report[key]!==undefined).map(key=>[key,report[key]]));
            store.setState(`axur-report-v1:${scope}:${report.id}`,{expires:now()+86400000,credentialRevision,report:projected});
            insights.push(projected);
          }
          await sleep(200);
        }
        timings.insightsMs=now()-insightStarted;
        stage='conversion';
        store.setState(stateKey,{...state,activeStage:stage});
        const conversionStarted=now();
        const rows = axurObservations(iocs, insights, { scope, matchActors, matchMalware });
        timings.conversionMs=now()-conversionStarted;
        stage='ingest';
        store.setState(stateKey,{...state,activeStage:stage});
        const ingestStarted=now();
        await store.ingest(rows);
        timings.ingestMs=now()-ingestStarted;
        const complete = meta.offset + data.iocs.length >= meta.total;
        state = { ...state, page: state.page + 1, resumeOffset:undefined, total: meta.total, processed: state.processed + iocs.length,
          observations: state.observations + rows.length, skipped: (state.skipped || 0) + iocs.filter(ioc => !normalizeIndicator(ioc.value, ioc.type) || !ioc.id).length,
          status: complete ? 'complete' : 'running', lastSuccessfulAt: new Date(now()).toISOString(), lastPageFingerprint: fingerprint,
          failures: 0, error: null, failureCode:null, failureStage:null, nextAttemptAt: 0, reportCacheHits:(state.reportCacheHits || 0)+reportCacheHits,
          lastPageMs:now()-pageStarted,lastPageTimings:timings,activeStage:null,successStreak:(state.successStreak||0)+1,
          lastPageRead:data.iocs.length,lastPageNewRecords:iocs.length,replayedRecords:(state.replayedRecords||0)+Math.min(replayed,data.iocs.length),pagination: 'live-offset-not-snapshot' };
        // Advance only after the page AND every referenced report are committed.
        // Replaying a page after interruption is safe because observations upsert.
        store.setState(stateKey, state);
        if (complete) break;
        await sleep(1000);
      }
    } catch (error) {
      const code=issueLabels[error.code]?error.code:stage==='ingest'?'ingest':'conversion';
      // Latency at the source did not improve when pages shrank to 100. Only
      // a proven oversized response lowers the page size and its growth ceiling.
      if(stage==='iocs'&&code==='response_size'&&!error.status){state=smallerPage(state);state.pageSizeCeiling=state.pageSize;}
      const failures = (state.failures || 0) + 1;
      const wait = Math.min(24 * 3600000, Math.max(60000 * 2 ** Math.min(failures - 1, 6), error.retryMs || 0));
      state = { ...state, status: 'retrying', activeStage:null,successStreak:0,failures, failureCode:code, failureStage:stage, lastFailureAt:new Date(now()).toISOString(), lastRunMs:now()-started,
        error: error.status ? `Axur HTTP ${error.status}` : issueLabels[code], nextAttemptAt: now() + wait };
      store.setState(stateKey, state);
    }
    return status();
  }
  return { status, run: ({ maxPages = 5 } = {}) => flight || (flight = runPages(Math.min(10, Math.max(1, maxPages))).finally(() => { flight = null; })) };
}
