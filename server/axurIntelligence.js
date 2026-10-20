import crypto from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { normalizeIndicator } from './iocIntelligence.js';

const BASE = 'https://api.axur.com/gateway/1.0/api';
const id = value => crypto.createHash('sha256').update(value.toLowerCase()).digest('hex').slice(0, 24);
const iso = value => { const date = new Date(value); return value && Number.isFinite(date.getTime()) ? date.toISOString() : undefined; };
const names = values => [...new Set((values || []).map(value => typeof value === 'string' ? value.trim() : value?.name?.trim()).filter(value => value && value.length <= 200 && !/^(unknown|n\/a|none|unattributed|desconhecido)$/i.test(value)))];
function entities(values, kind, match) {
  return names(values).map(name => {
    // Resolve only an exact catalog name/alias. The report's narrative must not
    // turn a different actor into an attribution for this indicator.
    const known = (match?.(kind === 'actor' ? `Threat actor group: ${name}` : name, { structured: kind === 'malware' }) || []).find(entity => [entity.name, entity.matched, ...(entity.aliases || [])].some(alias => String(alias || '').toLowerCase() === name.toLowerCase()));
    return known || { id: `axur:${kind}:${id(name)}`, name };
  });
}

export function axurObservations(iocs, insights, { scope, matchActors, matchMalware } = {}) {
  if (!scope || scope === 'global') throw new Error('Axur requires an account scope');
  const reports = new Map(insights.map(report => [report.id, report]));
  return iocs.flatMap(ioc => {
    const indicator = normalizeIndicator(ioc.value, ioc.type);
    if (!indicator || !ioc.id) return [];
    const base = { ...indicator, provider: 'Axur', scope, source: `Axur / ${ioc.source || 'CTI'}`, confidence: ioc.confidenceScore,
      published: iso(ioc.createdAt), tags: ioc.tags || [], relation: 'mentioned-with' };
    const payload = { id: ioc.id, upstreamSource: ioc.source, description: ioc.description, threatName: ioc.threatName,
      threatLevel: ioc.threatLevel, trustFactor: ioc.trustFactor, relatedTTPs: ioc.relatedTTPs || [], relatedInsights: ioc.relatedInsights || [], enrichedAt: iso(ioc.enrichedAt) };
    // AV detection labels (e.g. Generic.Trojan) are retained as evidence rather
    // than automatically creating a malware family or threat actor.
    const family = ioc.threatName ? (matchMalware?.(ioc.threatName, { structured:true }) || []).filter(entity => [entity.name,entity.matched].some(name => String(name || '').toLowerCase() === ioc.threatName.toLowerCase())) : [];
    const rows = [{ ...base, externalId: `ioc:${ioc.id}`, title: ioc.description || ioc.threatName || `IOC ${ioc.source || 'Axur'}`, payload, ...(family.length === 1 ? { malwares:family, relation:'mentioned-by-source' } : {}) }];
    for (const reportId of new Set(ioc.relatedInsights || [])) {
      const report = reports.get(reportId);
      if (!report) continue;
      rows.push({ ...base, externalId: `insight:${reportId}`, title: report.title, link: `https://cti.axur.com/insight/${encodeURIComponent(reportId)}`,
        published: iso(report.publicationDate) || base.published,
        tags: [...new Set([...(ioc.tags || []), ...(report.tags || [])])],
        actors: entities(report.threatActors, 'actor', matchActors), malwares: entities(report.malwares, 'malware', matchMalware),
        cves: [...new Set((report.vulnerabilities || []).map(value => typeof value === 'string' ? value : value.vulnerability).filter(value => /^CVE-\d{4}-\d{4,}$/i.test(value)))].map(value => ({ id: value.toUpperCase(), name: value.toUpperCase() })),
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
      return (await http.get(`${BASE}${endpoint}`, { params: { lang: 'pt-BR', ...params }, headers: { Authorization: `Bearer ${key}` }, timeout: 55000, maxRedirects: 0, maxContentLength: 32 * 1024 * 1024 })).data;
    } catch (error) {
      const status = Number(error.response?.status) || 0;
      const retry = error.response?.headers?.['retry-after'];
      const retryMs = Number.isFinite(Number(retry)) ? Number(retry) * 1000 : Date.parse(retry) - now();
      // Never expose Axios errors: their config contains Authorization.
      throw Object.assign(new Error(status ? `Axur HTTP ${status}` : 'Axur request failed'), { status, retryMs });
    }
  }
  async function runPages(maxPages) {
    let state = store.state(stateKey) || { page: 1, pageSize, processed: 0, observations: 0, startedAt: new Date(now()).toISOString() };
    if (!getKey() || state.status === 'complete' || state.nextAttemptAt > now()) return status();
    try {
      for (let index = 0; index < maxPages; index++) {
        if (!canWrite()) throw new Error('Insufficient storage reserve');
        const size = state.pageSize;
        const data = await read('/cyber-iocs/v2/iocs', { page: state.page, perPage: size });
        const meta = data?.metadata;
        if (!Array.isArray(data?.iocs) || !meta || meta.page !== state.page || meta.perPage !== size || meta.offset !== (state.page - 1) * size || !Number.isSafeInteger(meta.total) || meta.total < 0 || data.iocs.length > size) throw new Error('Axur pagination contract changed');
        const fingerprint = id(data.iocs.map(ioc => ioc.id).join(','));
        if (data.iocs.length && state.lastPageFingerprint === fingerprint) throw new Error('Axur repeated a page');
        if (!data.iocs.length && meta.offset < meta.total) throw new Error('Axur returned an incomplete page');
        if (data.iocs.length < size && meta.offset + data.iocs.length < meta.total) throw new Error('Axur returned a short intermediate page');
        const reportIds = [...new Set(data.iocs.flatMap(ioc => ioc.relatedInsights || []))];
        const insights = [];
        for (let start = 0; start < reportIds.length; start += 25) {
          const batch = reportIds.slice(start, start + 25);
          const reports = await read('/cyber-insights/v1/insights/bulk/search', { ids: batch.join(',') });
          if (!Array.isArray(reports) || batch.some(reportId => !reports.some(report => report.id === reportId))) throw new Error('Axur insights response incomplete');
          insights.push(...reports.filter(report => batch.includes(report.id)));
          await sleep(200);
        }
        const rows = axurObservations(data.iocs, insights, { scope, matchActors, matchMalware });
        await store.ingest(rows);
        const complete = meta.offset + data.iocs.length >= meta.total;
        state = { ...state, page: state.page + 1, total: meta.total, processed: state.processed + data.iocs.length,
          observations: state.observations + rows.length, skipped: (state.skipped || 0) + data.iocs.filter(ioc => !normalizeIndicator(ioc.value, ioc.type) || !ioc.id).length,
          status: complete ? 'complete' : 'running', lastSuccessfulAt: new Date(now()).toISOString(), lastPageFingerprint: fingerprint,
          failures: 0, error: null, nextAttemptAt: 0, pagination: 'live-offset-not-snapshot' };
        // Advance only after the page AND every referenced report are committed.
        // Replaying a page after interruption is safe because observations upsert.
        store.setState(stateKey, state);
        if (complete) break;
        await sleep(1000);
      }
    } catch (error) {
      const failures = (state.failures || 0) + 1;
      const wait = Math.min(24 * 3600000, Math.max(60000 * 2 ** Math.min(failures - 1, 6), error.retryMs || 0));
      state = { ...state, status: 'retrying', failures, error: error.status ? `Axur HTTP ${error.status}` : 'Importação interrompida; a página será tentada novamente.', nextAttemptAt: now() + wait };
      store.setState(stateKey, state);
    }
    return status();
  }
  return { status, run: ({ maxPages = 5 } = {}) => flight || (flight = runPages(Math.min(10, Math.max(1, maxPages))).finally(() => { flight = null; })) };
}
