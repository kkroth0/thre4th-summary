import fs from 'node:fs/promises';
import path from 'node:path';
import axios from 'axios';
import { AI_TOOL_CATALOG, AI_CATEGORIES, classifyAiTool } from './aiToolCatalog.js';
import { defaultOtMonth, validOtMonth } from './otPatchDay.js';

const DAY = 86400000, SOURCE = 'https://api.github.com/advisories';
const advisoryPage = (from, to, known = false) => SOURCE + '?' + new URLSearchParams({ type: 'reviewed', ...(from ? { modified: `${from.slice(0, 10)}..${to.slice(0, 10)}` } : {}), ...(known ? { affects: [...new Set(AI_TOOL_CATALOG.filter(t => t.repo).flatMap(t => t.packages))].join(',') } : {}), sort: 'updated', direction: 'desc', per_page: '100' });
const refs = values => [...new Set(values.filter(url => typeof url === 'string' && /^https:\/\//.test(url)))];
const nvdTime = value => /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?$/.test(value || '') ? value + 'Z' : value || '';
const score = values => { const scores = values.filter(v => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 10); return scores.length ? Math.max(...scores) : null; };
export function normalizeAiAdvisory(advisory) {
    if (advisory.withdrawn_at || advisory.type && advisory.type !== 'reviewed' || !/^GHSA-[a-z0-9-]+$/i.test(advisory.ghsa_id || '')) return null;
    const vulnerabilities = advisory.vulnerabilities || [];
    const tools = classifyAiTool({ packages: vulnerabilities.map(v => v.package).filter(Boolean), repository: advisory.source_code_location || '', summary: advisory.summary || '', text: advisory.description || '', references: advisory.references || [] });
    if (!tools.length) return null;
    const cves = [...new Set((advisory.identifiers || []).filter(i => i.type === 'CVE').map(i => i.value).concat(advisory.cve_id || []).filter(id => /^CVE-\d{4}-\d{4,}$/.test(id)))];
    const cvss = score([advisory.cvss?.score, advisory.cvss_severities?.cvss_v3?.score, advisory.cvss_severities?.cvss_v4?.score]);
    const products = vulnerabilities.flatMap((v, i) => [
        { id: `affected-${i}`, name: `${v.package?.ecosystem || ''} · ${v.package?.name || ''} ${v.vulnerable_version_range || '(faixa afetada não informada)'}`.trim(), vendor: tools.map(t => t.name).join(', '), status: 'affected', modelNumbers: [v.package?.name].filter(Boolean) },
        ...(v.first_patched_version ? [{ id: `fixed-${i}`, name: `${v.package?.name}: ${v.first_patched_version}`, vendor: tools.map(t => t.name).join(', '), status: 'fixed', modelNumbers: [v.package?.name] }] : []),
    ]);
    const remediations = vulnerabilities.filter(v => v.first_patched_version).map(v => ({ category: 'vendor_fix', details: `Primeira versão corrigida informada: ${v.first_patched_version}. Faixa afetada: ${v.vulnerable_version_range || 'consultar aviso'}. Verificar todas as linhas de versão no aviso oficial.`, url: advisory.html_url, products: [v.package?.name].filter(Boolean), cve: cves.join(', ') }));
    return { id: advisory.ghsa_id, title: advisory.summary || advisory.ghsa_id, summary: String(advisory.description || '').slice(0, 30000), source: 'GitHub Security Advisories', url: advisory.html_url || `https://github.com/advisories/${advisory.ghsa_id}`, references: refs([advisory.html_url, ...(advisory.references || [])]),
        vendors: [...new Set(tools.map(t => t.name))], tools, categories: [...new Set(tools.map(t => t.category))], published: advisory.published_at || '', updated: advisory.updated_at || advisory.published_at || '', revision: advisory.updated_at || '',
        products, remediations, cves, cvss, patch: remediations.length ? 'available' : 'unconfirmed', kev: false, revised: advisory.updated_at !== advisory.published_at, stale: false,
        matches: tools.map(t => ({ vendor: t.name, level: 'model', models: vulnerabilities.map(v => v.package?.name).filter(Boolean) })), cveSignals: cves.map(id => ({ id, kev: null, epss: null, cvss })),
    };
}
export function normalizeAiNvd(row) {
    const tools = row.tools || [], names = [...new Set(tools.map(t => t.name))];
    return { id: row.id, title: `${names.join(', ')} · ${row.id}`, summary: row.description, source: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${row.id}`, references: refs((row.references || []).map(r => r.url || r)),
        vendors: names, tools, categories: [...new Set(tools.map(t => t.category))], published: nvdTime(row.published), updated: nvdTime(row.modified), revision: nvdTime(row.modified), cves: [row.id], cvss: row.cvss, patch: 'unconfirmed', kev: row.kev, revised: row.modified !== row.published, stale: false,
        products: [{ id: row.product, name: row.product || names.join(', '), vendor: row.vendor, status: 'mentioned' }], remediations: [],
        matches: names.map(name => ({ vendor: name, level: 'vendor', models: [] })), cveSignals: [{ id: row.id, kev: row.kev, epss: row.epss, cvss: row.cvss }],
    };
}
export function mergeAiPatches(github, nvd) {
    const byCve = new Map(nvd.flatMap(row => row.cves.map(id => [id, row]))), used = new Set();
    const rows = github.map(row => {
        const matches = row.cves.map(id => byCve.get(id)).filter(Boolean);
        matches.forEach(r => used.add(r.id));
        const updated = [row.updated, ...matches.map(r => r.updated)].filter(Boolean).sort().at(-1) || row.updated;
        return { ...row, updated, revision: updated, revisionOrigins: { github: row.updated, nvd: matches.map(r => ({ cve: r.id, updated: r.updated })) }, cvss: score([row.cvss, ...matches.map(r => r.cvss)]), kev: row.kev || matches.some(r => r.kev),
            references: refs([...row.references, ...matches.flatMap(r => [r.url, ...r.references])]), alsoReportedBy: matches.length ? ['NVD'] : [],
            cveSignals: row.cveSignals.map(signal => matches.find(r => r.id === signal.id)?.cveSignals[0] || signal),
        };
    });
    return [...rows, ...nvd.filter(row => !used.has(row.id))].sort((a, b) => Number(b.kev) - Number(a.kev) || (b.cvss ?? -1) - (a.cvss ?? -1) || b.updated.localeCompare(a.updated) || a.id.localeCompare(b.id));
}
const allowedPage = address => { try { const u = new URL(address); return u.origin === 'https://api.github.com' && u.pathname === '/advisories'; } catch { return false; } };
export function createAiPatchDay({ filePath, http = axios, queryCatalog, now = () => Date.now(), token = '', pageBudget = 5 } = {}) {
    let state = { version: 3, rows: [], since: '', until: '', next: '', lastSuccess: '', checkedAt: '', error: '', persistenceError: false, truncated: false, pages: 0, recent: { next: '', until: '', lastSuccess: '' }, known: { next: '', until: '', lastSuccess: '' } };
    let flight = null, write = Promise.resolve();
    const monthly = new Map(), monthsInFlight = new Map();
    const loaded = filePath ? fs.readFile(filePath, 'utf8').then(raw => { const saved = JSON.parse(raw); if (saved.version === 3 && Array.isArray(saved.rows)) state = { ...state, ...saved }; }).catch(() => {}) : Promise.resolve();
    const persist = () => {
        if (!filePath) return Promise.resolve();
        const raw = JSON.stringify(state);
        write = write.catch(() => {}).then(async () => { await fs.mkdir(path.dirname(filePath), { recursive: true }); await fs.writeFile(filePath + '.tmp', raw); await fs.rename(filePath + '.tmp', filePath); state.persistenceError = false; }).catch(() => { state.persistenceError = true; });
        return write;
    };
    function sync() {
        if (flight) return flight;
        flight = (async () => {
            await loaded;
            const interval = state.next || state.error ? 3600000 : DAY;
            if (state.checkedAt && now() - Date.parse(state.checkedAt) < interval) return;
            state.checkedAt = new Date(now()).toISOString(); state.error = '';
            if (!state.next) {
                state.since = state.lastSuccess ? new Date(Date.parse(state.lastSuccess) - DAY).toISOString() : new Date(now() - 366 * DAY).toISOString();
                state.until = new Date(now()).toISOString();
                state.next = advisoryPage(state.since, state.until);
            }
            // A long historical import must never prevent new advisories from
            // arriving. Its cursor and the daily incremental cursor are separate.
            if (!state.recent.next && (!state.recent.lastSuccess || now() - Date.parse(state.recent.lastSuccess) >= DAY)) {
                const since = new Date(state.recent.lastSuccess ? Date.parse(state.recent.lastSuccess) - DAY : now() - 2 * DAY).toISOString();
                state.recent.until = new Date(now()).toISOString();
                state.recent.next = advisoryPage(since, state.recent.until);
            }
            if (!state.known.next && (!state.known.lastSuccess || now() - Date.parse(state.known.lastSuccess) >= DAY)) {
                state.known.until = new Date(now()).toISOString();
                // One batched package query, rather than 150 per-tool calls.
                // The first pass can recover older patched-version evidence for
                // CVEs whose NVD entry was revised in the selected month.
                state.known.next = advisoryPage(state.known.lastSuccess ? new Date(Date.parse(state.known.lastSuccess) - DAY).toISOString() : '', state.known.until, true);
            }
            try {
                for (let page = 0; (state.next || state.recent.next || state.known.next) && page < Math.min(20, Math.max(1, pageBudget)); page++) {
                    const current = state.recent.next ? state.recent : state.known.next ? state.known : state;
                    if (!allowedPage(current.next)) throw Error('Invalid advisory pagination');
                    const response = await http.get(current.next, { timeout: 25000, maxContentLength: 12 * 1024 * 1024, maxRedirects: 0, headers: { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'ThreatSumm4ry-AI-Patch-Day', ...(token ? { Authorization: `Bearer ${token}` } : {}) } });
                    if (!Array.isArray(response.data)) throw Error('Invalid advisory response');
                    const stored = new Map(state.rows.map(r => [r.id, r]));
                    for (const advisory of response.data) {
                        const normalized = normalizeAiAdvisory(advisory), previous = stored.get(advisory.ghsa_id);
                        if (previous && previous.updated > (advisory.updated_at || '')) continue;
                        if (normalized) stored.set(normalized.id, normalized); else if (advisory.ghsa_id) stored.delete(advisory.ghsa_id);
                    }
                    state.rows = [...stored.values()].sort((a, b) => b.updated.localeCompare(a.updated)).slice(0, 10000);
                    if (stored.size > 10000) state.truncated = true;
                    let size = Buffer.byteLength(JSON.stringify(state.rows));
                    while (size > 24 * 1024 * 1024 && state.rows.length) {
                        state.rows.splice(-Math.max(1, Math.ceil(state.rows.length * .05)));
                        state.truncated = true; size = Buffer.byteLength(JSON.stringify(state.rows));
                    }
                    const next = /<([^>]+)>;\s*rel="next"/.exec(response.headers?.link || '')?.[1] || '';
                    if (next && !allowedPage(next)) throw Error('Invalid advisory pagination');
                    current.next = next;
                    if (current === state.recent && !next) state.recent.lastSuccess = state.recent.until;
                    if (current === state.known && !next) state.known.lastSuccess = state.known.until;
                    state.pages++; await persist();
                    if (Number(response.headers?.['x-ratelimit-remaining']) === 0 && next) break;
                }
                if (!state.next) state.lastSuccess = state.until;
            } catch (error) { state.error = error.response?.status ? `HTTP ${error.response.status}` : 'A fonte não respondeu nesta atualização.'; }
            await persist(); monthly.clear();
        })().finally(() => { flight = null; });
        return flight;
    }
    async function query({ month = defaultOtMonth(new Date(now())) } = {}) {
        if (!validOtMonth(month)) throw Error('Invalid AI Patch Day month');
        await loaded;
        if (monthly.has(month) && now() - monthly.get(month).at < 300000) return monthly.get(month).data;
        if (monthsInFlight.has(month)) return monthsInFlight.get(month);
        const pending = (async () => {
            let local = { rows: [], status: { sources: {} } }, catalogError = false;
            const monthGithub = state.rows.filter(r => r.published.startsWith(month) || r.updated.startsWith(month));
            try { local = await queryCatalog({ month, ids: monthGithub.flatMap(r => r.cves) }); } catch { catalogError = true; }
            const nvd = local.rows.map(normalizeAiNvd);
            // Include the GHSA even when only its linked NVD entry was revised
            // this month, retaining known patched versions and avoiding duplicates.
            const nvdIds = new Set(nvd.map(r => r.id));
            const github = state.rows.filter(r => r.published.startsWith(month) || r.updated.startsWith(month) || r.cves.some(c => nvdIds.has(c)));
            const rows = mergeAiPatches(github, nvd), sourceStatus = local.status?.sources || {};
            const sources = [
                { id: 'github', name: 'GitHub Security Advisories', url: 'https://github.com/advisories', coverage: `Avisos revisados, versões afetadas e corrigidas. Consulta em lote aos pacotes do catálogo e descoberta global de novos componentes MCP/IA nos últimos 12 meses; ${state.pages} páginas processadas.${state.next || state.known.next ? ' Importação histórica em andamento; a coleta diária continua em paralelo.' : ''}${state.truncated ? ' O cache atingiu o limite; registros mais antigos podem não estar disponíveis.' : ''}`, status: state.error ? state.rows.length ? 'stale' : 'error' : state.truncated ? 'stale' : !state.lastSuccess || state.next || state.recent.next || state.known.next ? 'pending' : 'ok', lastSuccess: state.recent.lastSuccess || state.lastSuccess, checkedAt: state.checkedAt, error: state.error },
                ...['nvd', 'kev', 'epss'].map(id => ({ id, name: { nvd: 'NVD', kev: 'CISA KEV', epss: 'FIRST EPSS' }[id], url: { nvd: 'https://nvd.nist.gov/', kev: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', epss: 'https://www.first.org/epss/' }[id], coverage: id === 'nvd' ? 'Catálogo unificado local: CVEs publicadas ou revisadas no mês, filtradas pelo componente de IA.' : 'Sinais do catálogo unificado, vinculados pelo identificador CVE.', status: !catalogError && sourceStatus[id]?.status === 'ready' ? 'ok' : catalogError || sourceStatus[id]?.status === 'error' ? 'error' : 'stale', lastSuccess: sourceStatus[id]?.at, error: catalogError ? 'Catálogo temporariamente indisponível.' : sourceStatus[id]?.error || '' })),
            ];
            const discovered = rows.flatMap(r => r.tools).filter(t => t.evidence === 'discovery');
            const catalog = [...AI_TOOL_CATALOG.map(t => ({ vendor: t.name, aliases: t.packages, models: t.packages, review: [], category: t.category, repo: t.repo })), ...discovered.filter((t, i, all) => all.findIndex(x => x.name === t.name) === i).map(t => ({ vendor: t.name, aliases: [], models: [t.name], review: ['Componente identificado no texto do aviso; conferir o pacote e a aplicabilidade.'], category: t.category, repo: '' }))];
            const data = { month, rows, catalog, categories: [...new Set([...AI_CATEGORIES, ...rows.flatMap(r => r.categories)])], sources,
                status: { running: Boolean(flight), pending: state.next || state.known.next || state.recent.next || !state.recent.lastSuccess ? 1 : 0, failed: state.error || catalogError ? 1 : 0, initialized: Boolean(state.recent.lastSuccess) && !local.truncated, cadenceHours: 24, persistenceError: state.persistenceError },
                summary: { advisories: rows.length, patches: rows.filter(r => r.patch === 'available').length, mitigations: 0, kev: rows.filter(r => r.kev).length, matched: rows.filter(r => r.matches.some(m => m.level === 'model')).length },
                coverage: { initialFrom: state.since, categories: AI_CATEGORIES.length, catalogTools: AI_TOOL_CATALOG.length, githubAdvisories: state.rows.length, truncated: Boolean(local.truncated || state.truncated), historicalImportPending: Boolean(state.next || state.known.next), policy: 'Catálogo ampliável e descoberta por evidência. Produtos proprietários entram quando há aviso público nas fontes; presença no catálogo não garante cobertura integral.' },
            };
            monthly.set(month, { at: now() - (catalogError ? 285000 : 0), data }); if (monthly.size > 24) monthly.delete(monthly.keys().next().value);
            return data;
        })().finally(() => monthsInFlight.delete(month));
        monthsInFlight.set(month, pending); return pending;
    }
    return { query, sync };
}
