import crypto from 'node:crypto';
import { normalizeIndicator } from './indicatorIdentity.js';
import { axurObservations } from './axurIntelligence.js';
import { readAxur } from './axurAccess.js';

const BASE = 'https://api.axur.com/gateway/1.0/api';
const problem = (message, status = 502, extra = {}) => Object.assign(Error(message), { status, ...extra });
const unique = values => [...new Set(values.filter(Boolean))];

/** Private exact-IOC lookup. Imported matches avoid API calls; successful API
 * responses use the same permanent, account-scoped cache as other providers. */
export function createAxurLookup({ scope, getKey, http, cache, store, readDetail, matchActors, matchMalware, now = Date.now }) {
  if (!scope || scope === 'global') throw Error('Axur requires an account scope');
  async function read(endpoint, params, signal) {
    const key = getKey();
    if (!key) throw problem('Configure a chave da Axur para consultar os IOCs ainda não importados.', 403, { code: 'PROVIDER_AUTH_FAILED' });
    try {
      const response = await readAxur(scope, http, BASE + endpoint, { params: { lang: 'pt-BR', ...params }, headers: { Authorization: `Bearer ${key}` }, timeout: 240000, maxRedirects: 0, maxContentLength: 32 * 1024 * 1024, signal });
      return response.data;
    } catch (error) {
      // Axios error objects contain the credential. Return only a safe status.
      const status = Number(error.response?.status) || (signal?.aborted ? 504 : 503);
      const retry = error.response?.headers?.['retry-after'];
      const retryAt = retry ? (/^\d+$/.test(String(retry)) ? now() + Number(retry) * 1000 : Date.parse(retry)) : undefined;
      throw problem([401,403].includes(status) ? 'A Axur recusou a credencial. Revise a conexão.' : status === 429 ? 'A Axur atingiu a cota; nova tentativa agendada.' : 'A consulta à Axur ficou indisponível; nova tentativa agendada.', status, { ...([401,403].includes(status) ? { code: 'PROVIDER_AUTH_FAILED' } : {}), ...(Number.isFinite(retryAt) ? { retryAt } : {}) });
    }
  }
  async function imported(value) {
    const evidence = []; let offset = 0;
    while (true) {
      const page = await readDetail({ value, owner: scope, offset, size: 100 }, { revision: 'axur-local-v1' });
      if (!page) break;
      evidence.push(...page.evidence.filter(row => row.provider === 'Axur'));
      offset += page.evidence.length;
      if (offset >= page.total) break;
      if (!page.evidence.length) throw problem('A leitura dos registros importados da Axur ficou incompleta.', 503);
    }
    return evidence;
  }
  async function search(query, signal) {
    const target = normalizeIndicator(query), iocs = [], seen = new Set();
    for (let page = 1; ; page++) {
      const result = await read('/cyber-iocs/v2/iocs', { content: query, page, perPage: 100 }, signal);
      if (!Array.isArray(result?.iocs)) throw problem('A Axur devolveu uma resposta inválida; a ausência não foi registrada.');
      const meta = result.metadata;
      if (meta && (!Number.isSafeInteger(meta.total) || meta.total < 0 || meta.page !== page || meta.perPage !== 100 || meta.offset !== (page - 1) * 100)) throw problem('Não foi possível confirmar a paginação da consulta Axur.');
      if (meta && result.iocs.length !== Math.min(100, Math.max(0, meta.total - meta.offset))) throw problem('A Axur devolveu uma página incompleta; nova tentativa agendada.');
      for (const ioc of result.iocs) {
        const normalized = normalizeIndicator(ioc.value, ioc.type);
        if (normalized?.type === target.type && normalized.value === target.value) {
          if (!ioc.id) throw problem('Um IOC da Axur veio sem identificador; a consulta será repetida.');
          if (ioc.relatedInsights !== undefined && (!Array.isArray(ioc.relatedInsights) || ioc.relatedInsights.some(id => typeof id !== 'string' || !id))) throw problem('As referências da Axur vieram em formato inválido.');
          if (!seen.has(ioc.id)) { seen.add(ioc.id); iocs.push(ioc); }
        }
      }
      if (meta ? meta.offset + result.iocs.length >= meta.total : result.iocs.length < 100) break;
      if (!result.iocs.length || page >= 100 || !meta) throw problem('A busca da Axur ficou incompleta; a ausência não foi registrada.');
    }
    const ids = unique(iocs.flatMap(ioc => ioc.relatedInsights || [])), insights = [];
    for (let start = 0; start < ids.length; start += 25) {
      const batch = ids.slice(start, start + 25), reports = await read('/cyber-insights/v1/insights/bulk/search', { ids: batch.join(',') }, signal);
      if (!Array.isArray(reports) || batch.some(id => !reports.some(report => report.id === id))) throw problem('A Axur não devolveu todos os relatórios; nova tentativa agendada.');
      if (reports.some(report => ['threatActors','malwares','vulnerabilities','attacks','tags'].some(field => report[field] !== undefined && !Array.isArray(report[field])))) throw problem('Um relatório da Axur veio em formato inválido; nova tentativa agendada.');
      insights.push(...reports.filter(report => batch.includes(report.id)));
    }
    return { data: { iocs, insights, lookupComplete: true }, headers: {} };
  }
  function vendor(query, evidence, { rawPayload, mode, collectedAt, cacheState, inventory }) {
    const reports = unique(evidence.map(row => row.link).filter(link => /^https:\/\/cti\.axur\.com\/insight\//.test(link || '')));
    const entities = evidence.flatMap(row => row.entities || []);
    const names = kind => unique(entities.filter(entity => entity.kind === kind).map(entity => entity.name));
    return { name: 'Axur', data: { Status: evidence.length ? 'Contexto encontrado' : inventory ? 'Sem correspondência na base Axur importada' : 'Sem registro exato na Axur', 'Registros Axur': evidence.length, 'Relatórios': reports.length, 'Origem': mode,
      ...(inventory ? { 'Última varredura': inventory.importAt, 'Cruzamento realizado em': inventory.checkedAt, 'Registros percorridos na varredura': inventory.recordsTraversed, 'Escopo da consulta': 'Base integral importada. A data da varredura identifica a cobertura; não representa uma nova consulta à API.' } : {}),
      'Atores mencionados': names('actor'), Malware: names('malware'), CVEs: names('cve'), 'Referências': reports,
      'Limite da relação': 'Entidades citadas no mesmo relatório não confirmam autoria ou uso atual do IOC.' }, collectedAt, cacheState, rawPayload, ...(reports[0] ? { link: reports[0] } : {}) };
  }
  return async function lookup(query, { fresh = false, completedInventory = false } = {}) {
    const indicator = normalizeIndicator(query);
    if (!indicator) throw problem('Indicador inválido para consulta Axur.', 400);
    // A completed local match already carries its original source/date/links.
    // A local miss is never treated as an API miss while the import is partial.
    if (!fresh) {
      const local = await imported(query);
      const state = completedInventory ? store.state(`axur-import-v1:${scope}`) : null;
      const importTime = Date.parse(state?.lastSuccessfulAt || '');
      if (state?.status === 'complete' && Number.isSafeInteger(state.total) && state.total > 0 && Number.isSafeInteger(state.processed) && state.processed >= state.total && Number.isFinite(importTime) && importTime <= now()) {
        const inventory = { importAt: new Date(importTime).toISOString(), checkedAt: new Date(now()).toISOString(), recordsTraversed: state.processed, pagination: state.pagination || 'live-offset-not-snapshot' };
        return vendor(query, local, { rawPayload: { evidence: local, inventory, lookupComplete: true }, mode: 'Base Axur importada · varredura concluída', collectedAt: inventory.importAt, cacheState: local.length ? 'inventory-hit' : 'inventory-miss', inventory });
      }
      if (local.length) return vendor(query, local, { rawPayload: { evidence: local }, mode: 'Base Axur importada', collectedAt: local.map(row => row.collectedAt).filter(Boolean).sort().at(-1), cacheState: 'inventory-hit' });
    }
    const signal = AbortSignal.timeout(540000);
    const response = await cache.get({ provider: 'axur', query, owner: scope, fresh }, () => search(query, signal));
    const { iocs, insights } = response.value.data;
    const persistenceKey = 'axur-lookup-v1:' + crypto.createHash('sha256').update(JSON.stringify([scope, indicator.value, response.collectedAt])).digest('hex');
    if (!store.state(persistenceKey)) {
      await store.ingest(axurObservations(iocs, insights, { scope, matchActors, matchMalware }));
      store.setState(persistenceKey, { persisted: true });
    }
    const evidence = axurObservations(iocs, insights, { scope, matchActors, matchMalware }).map(row => ({ ...row, entities: [...(row.actors || []).map(entity => ({ ...entity, kind: 'actor' })), ...(row.malwares || []).map(entity => ({ ...entity, kind: 'malware' })), ...(row.cves || []).map(entity => ({ ...entity, kind: 'cve' }))] }));
    return vendor(query, evidence, { rawPayload: response.value.data, mode: response.state === 'miss' ? 'API Axur · consulta exata' : 'Resposta Axur salva', cacheState: response.state, collectedAt: response.collectedAt });
  };
}
