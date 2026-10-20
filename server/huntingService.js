import Database from 'better-sqlite3';
import { readFileSync } from 'node:fs';
import { fingerprint } from './huntingLibrary.js';

const DAY = 86400000;
const clean = (value, length = 600) => String(value || '').replace(/[\u0000-\u001f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, length);
const fold = value => clean(value, 20000).normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
const tokens = value => [...new Set((fold(value).match(/[a-z0-9][a-z0-9_.-]{3,}/g) || []).filter(word => !STOP.has(word)))];
const STOP = new Set('with from this that these those query queries detection hunting threat threats security malicious malware windows endpoint attack attacks activity suspicious events event microsoft sentinel defender using used uses user users report research system data process processes command commands information details article news about into have been more than possible techniques technique'.split(' '));
const STRONG = new Set('powershell rundll32 regsvr32 mimikatz lsass winrar anydesk cobaltstrike mshta schtasks wmic psexec certutil clickfix msbuild netsh'.split(' '));
const CVE = /^CVE-\d{4}-\d{4,}$/;
const calendarStamp = value => /^\d{4}-\d{2}-\d{2}$/.test(value || '') ? value + 'T03:00:00.000Z' : value;
const safeUrl = value => { try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password ? url.href : ''; } catch { return ''; } };
const attack = JSON.parse(readFileSync(new URL('./data/attack.json', import.meta.url), 'utf8'));
const attackById = new Map(attack.techniques.map(row => [row.id, row]));
export function huntingWindow(period, now = Date.now()) {
  if (!['day', 'week', 'month'].includes(period)) throw Object.assign(Error('Período inválido.'), { status: 400 });
  // Calendar day in Fortaleza (UTC-3); 7/30-day windows retain their full history.
  const from = period === 'day' ? Math.floor((now - 3 * 3600000) / DAY) * DAY + 3 * 3600000 : now - (period === 'week' ? 7 : 30) * DAY;
  return { period, from: new Date(from).toISOString(), to: new Date(now).toISOString() };
}
function exposureQuery(id) {
  return { id: 'exposure-' + id, title: 'Exposição a ' + id, description: 'Verificar a CVE no inventário do Defender Vulnerability Management. Presença não comprova exploração.', platform: 'defender', tables: ['DeviceTvmSoftwareVulnerabilities'], techniques: [], cves: [id],
    query: `DeviceTvmSoftwareVulnerabilities\n| where CveId == "${id}"\n| project DeviceId, DeviceName, SoftwareVendor, SoftwareName,\n    SoftwareVersion, CveId, VulnerabilitySeverityLevel`,
    provenance: [{ repo: 'ThreatSumm4ry', license: 'Autoral', url: 'https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsoftwarevulnerabilities-table' }] };
}
export function createHuntingIndex(library) {
  const postings = new Map(), queries = new Map();
  const titleTerms = new Map();
  for (const query of library) {
    queries.set(query.id, query);
    titleTerms.set(query.id, new Set(tokens(query.title)));
    const terms = [...tokens(query.title + ' ' + query.description), ...query.techniques, ...query.cves];
    for (const term of new Set(terms)) { if (!postings.has(term)) postings.set(term, new Set()); postings.get(term).add(query.id); }
  }
  function match(row) {
    const terms = tokens([row.title, row.description, ...(row.actors || []).map(x => x.name), ...(row.malware || []).map(x => x.name)].join(' '));
    const ttps = [...new Set([...(row.ttpIds || []), ...(row.ttps || []).flatMap(value => String(value).match(/\bT\d{4}(?:\.\d{3})?\b/g) || [])])];
    const scores = new Map();
    const add = (term, weight, kind) => { for (const id of postings.get(term) || []) { const hit = scores.get(id) || { score: 0, words: [], techniques: [], cves: [] }; hit.score += weight + (kind === 'words' && titleTerms.get(id).has(term) ? 8 : 0); hit[kind].push(term); scores.set(id, hit); } };
    ttps.forEach(term => add(term, 16, 'techniques')); (row.cves || []).forEach(term => add(term, 35, 'cves')); terms.forEach(term => add(term, STRONG.has(term) ? 10 : 2, 'words'));
    const text = fold([row.title, row.description, ...(row.actors || []).map(x => x.name), ...(row.malware || []).map(x => x.name)].join(' '));
    for (const [id, hit] of scores) {
      const query = queries.get(id), namedActors = query.title.match(/\b(?:APT\s?\d+|FIN\d+|UNC\d+|TA\d{3,}|Lazarus)\b/gi) || [];
      if (namedActors.some(name => !text.includes(name.toLowerCase()))) hit.score -= 35;
      const sharedTitle = hit.words.filter(word => titleTerms.get(id).has(word)).length;
      hit.score += sharedTitle * 8 / Math.sqrt(Math.max(1, titleTerms.get(id).size));
      hit.score += 20 * sharedTitle / Math.max(1, titleTerms.get(id).size);
    }
    return [...scores].filter(([, hit]) => hit.techniques.length || hit.cves.length || hit.words.some(word => STRONG.has(word)) || hit.words.length >= 3)
      .filter(([, hit]) => hit.score > 0).sort((a, b) => b[1].score - a[1].score || a[0].localeCompare(b[0])).slice(0, 1).map(([id, match]) => ({ query: queries.get(id), match }));
  }
  return { match };
}
const relevantDate = row => !row.dateInferred && row.publicationDateBasis !== 'collected' && row.securityRelevant !== false;
export function buildHuntingCandidates({ news, cves = [], library, period = 'day', now = Date.now(), index = createHuntingIndex(library), votes = {} }) {
  const window = huntingWindow(period, now), start = Date.parse(window.from), groups = new Map(), cvesById = new Map(cves.map(row => [row.id, row]));
  const sourceFor = row => ({ id: fingerprint(row.link || row.id).slice(0, 20), title: clean(row.title || row.id, 240), url: safeUrl(row.link), publishedAt: row.pubDate, source: clean(row.source, 100), storyId: row.storyId || null, kind: 'news' });
  function put(query, row, match, source) {
    const key = query.id, date = Date.parse(source.publishedAt), weight = Math.min(35, Math.max(0, Number(row.score) || Number(row.cvss) * 3 || 0)) + (row.kev ? 30 : 0) + Math.min(15, (Number(row.epss) || 0) * 15) + Math.max(0, 15 - (now - date) / DAY * 2) + Math.min(25, match.score || 0);
    const old = groups.get(key);
    if (old) {
      if (!old.sources.some(s => s.url === source.url) && old.sources.length < 6) old.sources.push(source);
      old.score = Math.max(old.score, weight);
      old.signals.kev ||= Boolean(row.kev);
      for (const signal of ['epss', 'cvss']) if (typeof row[signal] === 'number') old.signals[signal] = Math.max(old.signals[signal] ?? 0, row[signal]);
      for (const field of ['actors', 'malware']) old[field] = [...new Map([...old[field], ...(row[field] || []).map(x => ({ id: x.id, name: x.name }))].map(x => [x.id, x])).values()].slice(0, 6);
      old.cves = [...new Set([...old.cves, ...(row.cves || [])])].slice(0, 12);
      for (const id of match.techniques.filter(id => attackById.has(id))) if (!old.techniques.some(t => t.id === id)) old.techniques.push({ ...attackById.get(id), url: 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/' });
      return;
    }
    const techniques = match.techniques.filter(id => attackById.has(id));
    groups.set(key, { id: 'hunt-' + fingerprint(key).slice(0, 24), queryId: query.id, title: query.cves?.length && query.id.startsWith('exposure-') ? 'Verificar exposição a ' + query.cves[0] : 'Investigar ' + query.title,
      hypothesis: query.id.startsWith('exposure-') ? 'Pode haver ativos com esta vulnerabilidade no inventário.' : 'O comportamento descrito nas fontes pode estar presente no ambiente e merece investigação.',
      reason: row.kev ? 'Há exploração conhecida registrada no CISA KEV. Verifique a exposição e investigue o contexto.' : match.techniques.length ? 'A publicação e a consulta compartilham técnicas ATT&CK. Revise o comportamento e os dados necessários.' : match.cves.length ? 'A consulta referencia a CVE citada na publicação.' : query.id.startsWith('exposure-') ? 'Vulnerabilidade recente no catálogo. A consulta verifica exposição; não comprova exploração.' : 'O conteúdo e a consulta compartilham termos específicos do comportamento. A correspondência precisa de revisão.',
      score: weight, matchKind: techniques.length ? 'technique' : match.cves.length ? 'cve' : 'terms', matchTerms: match.words.slice(0, 8), techniques: techniques.map(id => ({ ...attackById.get(id), url: 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/' })),
      sources: [source], actors: (row.actors || []).map(x => ({ id: x.id, name: x.name })).slice(0, 6), malware: (row.malware || []).map(x => ({ id: x.id, name: x.name })).slice(0, 6), cves: (row.cves || (CVE.test(row.id || '') ? [row.id] : [])).slice(0, 12),
      signals: { kev: Boolean(row.kev), epss: typeof row.epss === 'number' ? row.epss : null, cvss: typeof row.cvss === 'number' ? row.cvss : null }, query, aiUsed: false });
  }
  const publications = news.filter(row => relevantDate(row) && safeUrl(row.link) && Date.parse(row.pubDate) >= start && Date.parse(row.pubDate) <= now)
    .sort((a, b) => (Number(b.score) || 0) - (Number(a.score) || 0) || Date.parse(b.pubDate) - Date.parse(a.pubDate)).slice(0, 350);
  for (const row of publications) {
    for (const hit of index.match(row)) put(hit.query, row, hit.match, sourceFor(row));
    for (const id of (row.topicCves?.length ? row.topicCves : row.cves || []).filter(id => CVE.test(id)).slice(0, 2)) {
      const context = cvesById.get(id);
      const evidence = { ...row, cves: [id], kev: context?.kev === true || row.kevDetails?.cve === id, epss: context?.epss ?? (row.cves?.length === 1 ? row.epss : null), cvss: context?.cvss ?? null };
      put(exposureQuery(id), evidence, { score: 6, words: [], techniques: [], cves: [id] }, sourceFor(row));
    }
  }
  for (const row of cves) {
    const added = calendarStamp(row.dateAdded), published = calendarStamp(row.published);
    const at = row.kev && Date.parse(added) >= start ? added : published;
    if (!CVE.test(row.id) || !Number.isFinite(Date.parse(at)) || Date.parse(at) < start || Date.parse(at) > now) continue;
    put(exposureQuery(row.id), row, { score: 6, words: [], techniques: [], cves: [row.id] }, { id: row.id, title: row.id + (row.product ? ' · ' + clean(row.product, 120) : ''), url: 'https://nvd.nist.gov/vuln/detail/' + row.id, publishedAt: at, kind: 'cve', source: 'NVD · CISA KEV · EPSS' });
  }
  const ranked = [...groups.values()].map(row => ({ ...row, score: row.score + Math.min(8, row.sources.length - 1) + (votes[row.queryId] === 'yes' ? 6 : votes[row.queryId] === 'no' ? -12 : 0), feedback: votes[row.queryId] || null }))
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
  // Keep a daily CVE dump from displacing every behavioural hunt.
  let exposures = 0; const seenQueries = new Set();
  const candidates = ranked.filter(row => { const key = fingerprint(row.query.query); if (seenQueries.has(key)) return false; seenQueries.add(key); return !row.queryId.startsWith('exposure-') || ++exposures <= 4; }).slice(0, 16);
  return { window, publications: publications.length, candidates };
}

export function createHuntingService({ library, getNews, getCves = async () => [], filePath = ':memory:', generate, now = () => Date.now() }) {
  const db = new Database(filePath); db.pragma('journal_mode = WAL');
  db.exec('CREATE TABLE IF NOT EXISTS hunting_feedback(owner TEXT,key TEXT,vote TEXT,at TEXT,PRIMARY KEY(owner,key)); CREATE TABLE IF NOT EXISTS hunting_ai(key TEXT PRIMARY KEY,body TEXT,at INTEGER); CREATE TABLE IF NOT EXISTS hunting_budget(owner TEXT,day TEXT,used INTEGER,PRIMARY KEY(owner,day));');
  const feedbackRows = db.prepare('SELECT key,vote FROM hunting_feedback WHERE owner=?'), cacheRead = db.prepare('SELECT body,at FROM hunting_ai WHERE key=?');
  const flights = new Map(), computed = new Map(); let indexedRevision, index, activeAi = 0;
  const votesFor = owner => Object.fromEntries(feedbackRows.all(owner).map(row => [row.key, row.vote]));
  function claim(owner) {
    const day = new Date(now()).toISOString().slice(0, 10);
    return db.transaction(() => { const count = db.prepare('SELECT used FROM hunting_budget WHERE owner=? AND day=?').get(owner, day)?.used || 0; if (count >= 9) return false; db.prepare('INSERT INTO hunting_budget VALUES(?,?,1) ON CONFLICT(owner,day) DO UPDATE SET used=used+1').run(owner, day); return true; })();
  }
  function saveAi(key, value) { db.prepare('INSERT OR REPLACE INTO hunting_ai VALUES(?,?,?)').run(key, JSON.stringify(value), now()); db.prepare('DELETE FROM hunting_ai WHERE at<?').run(now() - 7 * DAY); }
  function annotate(base, result) {
    const rows = new Map(base.map(row => [row.id, row]));
    const seen = new Set(), output = [];
    for (const choice of result?.hypotheses || []) {
      const original = rows.get(choice.id); if (!original || seen.has(choice.id) || typeof choice.title !== 'string' || typeof choice.hypothesis !== 'string' || typeof choice.reason !== 'string') continue;
      // Model cannot create entity/IOC/technique claims absent from this candidate.
      const content = [choice.title, choice.hypothesis, choice.reason].join(' '), allowed = JSON.stringify(original).toLowerCase();
      const identifiers = content.match(/\b(?:CVE-\d{4}-\d{4,}|T\d{4}(?:\.\d{3})?|(?:\d{1,3}\.){3}\d{1,3}|[a-f0-9]{32,64})\b/gi) || [];
      if (identifiers.some(id => !allowed.includes(id.toLowerCase())) || /https?:\/\//i.test(content)) continue;
      seen.add(choice.id); output.push({ ...original, title: clean(choice.title, 180), hypothesis: clean(choice.hypothesis, 600), reason: clean(choice.reason, 700), aiUsed: true });
    }
    if (!output.length) throw Error('Invalid hunting response');
    return [...output, ...base.filter(row => !seen.has(row.id))].slice(0, 12);
  }
  async function overview(owner, period) {
    const window = huntingWindow(period, now()), news = getNews(owner), revision = library.revision();
    if (indexedRevision !== revision) { index = createHuntingIndex(library.all()); indexedRevision = revision; }
    // Inventory queries are cached by the worker; news is read from local stores.
    const cves = await getCves(); const votes = votesFor(owner);
    const signature = fingerprint(JSON.stringify([owner, period, window.from.slice(0, 13), revision, news.map(r => [r.link, r.contentHash, r.pubDate, r.score]), cves.map(r => [r.id, r.dateAdded, r.modified]), votes]));
    let base = computed.get(signature);
    if (!base || now() - base.at > 5 * 60000) { base = { ...buildHuntingCandidates({ news, cves, library: library.all(), index, period, now: now(), votes }), at: now() }; computed.set(signature, base); if (computed.size > 32) computed.delete(computed.keys().next().value); }
    const candidates = base.candidates, key = signature + ':' + Math.floor(now() / (6 * 3600000));
    const cached = cacheRead.get(key); let ai = cached ? JSON.parse(cached.body) : null;
    const retryable = !cached || (ai?.status === 'unavailable' && now() - cached.at > 15 * 60000);
    if (generate && candidates.length && retryable && !flights.has(key) && activeAi < 2 && claim(owner)) {
      activeAi++;
      const task = (async () => { try { const result = await generate({ period, candidates: candidates.slice(0, 12), feedback: votes }); const rows = annotate(candidates, result); saveAi(key, { status: 'ready', choices: rows.filter(r => r.aiUsed).map(r => ({ id: r.id, title: r.title, hypothesis: r.hypothesis, reason: r.reason })) }); } catch { saveAi(key, { status: 'unavailable' }); } finally { flights.delete(key); activeAi--; } })();
      flights.set(key, task);
    }
    let rows = candidates.slice(0, 12);
    if (ai?.status === 'ready') { try { rows = annotate(candidates, { hypotheses: ai.choices }); } catch { ai = { status: 'unavailable' }; } }
    return { period, window, generatedAt: new Date(base.at).toISOString(), aiStatus: flights.has(key) ? 'processing' : ai?.status || (generate ? 'limited' : 'disabled'), library: library.status(), publications: base.publications, hypotheses: rows,
      evaluated: Object.keys(votes).length, techniques: [...new Map(rows.flatMap(row => row.techniques).map(t => [t.id, t])).values()] };
  }
  function feedback(owner, queryId, vote) {
    if (typeof queryId !== 'string' || !/^(?:[a-f0-9]{64}|exposure-CVE-\d{4}-\d{4,})$/.test(queryId) || !['yes', 'no'].includes(vote)) throw Object.assign(Error('Retorno inválido.'), { status: 400 });
    if (!queryId.startsWith('exposure-') && !library.all().some(query => query.id === queryId)) throw Object.assign(Error('Consulta não encontrada.'), { status: 404 });
    db.prepare('INSERT INTO hunting_feedback VALUES(?,?,?,?) ON CONFLICT(owner,key) DO UPDATE SET vote=excluded.vote,at=excluded.at').run(owner, queryId, vote, new Date(now()).toISOString()); computed.clear();
    return { queryId, vote };
  }
  return { overview, feedback, close: () => db.close(), idle: () => Promise.all([...flights.values()]) };
}
