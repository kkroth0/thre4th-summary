import { extractIOCs } from './ctiIntel.js';
import { mapConcurrent } from './feedCollector.js';

export const REPOSITORY_SOURCES = [
  { url: 'https://github.com/paloaltonetworks/unit42-timely-threat-intel', source: 'Unit 42 · Timely Threat Intel', repo: 'PaloAltoNetworks/Unit42-timely-threat-intel', prefix: '', kind: 'github', layer: 3, weight_boost: 15 },
  { url: 'https://github.com/rtkwlf/wolf-tools/tree/main/threat-intelligence', source: 'Arctic Wolf · Threat Intelligence', repo: 'rtkwlf/wolf-tools', prefix: 'threat-intelligence/', kind: 'github', layer: 3, weight_boost: 12, retentionDays: 3650 },
];
const json = response => typeof response.data === 'string' ? JSON.parse(response.data) : response.data;
const apiHeaders = { Accept: 'application/vnd.github+json' };
const safePath = value => typeof value === 'string' && !value.split('/').some(part => !part || part === '.' || part === '..') && !/[\\\u0000-\u001f]/.test(value);
const encodedPath = value => value.split('/').map(encodeURIComponent).join('/');

export function declaredRepositoryMalware(item) {
  if(!item.repositoryReport||item.repository?.repo!=='PaloAltoNetworks/Unit42-timely-threat-intel')return [];
  const match=String(item.text||'').match(/malware family[\s\S]{0,120}?(?:we(?:'ve| have)? named|called|named)\s+["']?([a-z][a-z0-9_-]{2,60})/i);
  return match?[{id:'reported:'+match[1].toLowerCase(),name:match[1]}]:[];
}

// Read only published indicator text. Never fetch payloads, YARA executables,
// policy binaries or links found inside a report.
function unitsFor(feed, tree) {
  const files = tree.filter(row => row.type === 'blob' && row.mode !== '120000' && /^[a-f0-9]{40}$/.test(row.sha) && row.size > 0 && row.size <= 512000 && safePath(row.path) && row.path.startsWith(feed.prefix));
  if (!feed.prefix) return files.filter(row => /^\d{4}-\d{2}-\d{2}-.+\.(txt|md)$/i.test(row.path) && !row.path.includes('/'))
    .sort((a,b) => b.path.localeCompare(a.path)).map(row => ({ path: row.path, files: [row], date: row.path.slice(0,10) + 'T00:00:00.000Z' }));
  const groups = new Map();
  for (const row of files.filter(row => /\.(csv|md)$/i.test(row.path) && !/\/(?:LICENSE|SUPPORT)\./i.test(row.path))) {
    const group = row.path.split('/').slice(0,2).join('/');
    if (group === row.path) continue;
    if (!groups.has(group)) groups.set(group, []);
    groups.get(group).push(row);
  }
  return [...groups].map(([path, files]) => ({ path, files })).sort((a,b) => a.path.localeCompare(b.path));
}

// Unit42 explicitly distinguishes malicious indicators from legitimate services
// abused by the implant. Keep those services in report text, outside risk IOCs.
export function repositoryIocs(text, path) {
  let evidence = String(text || '');
  if (!/\.csv$/i.test(path)) {
    const marker = /^\s*(?:#+\s*)?(?:INDICATORS(?: OF COMPROMISE)?|IOCS?)\s*:?\s*$/im.exec(evidence);
    evidence = marker ? evidence.slice(marker.index) : '';
    evidence = evidence.split(/\r?\n/).filter(line => !/legitimate|legítimo|legitimo|benign/i.test(line)).join('\n');
  } else {
    // Metadata, certificates, TTPs and behavioural rows are useful context but
    // are not themselves actionable IP/domain/hash indicators.
    if (!/(?:ioc|indicator|domain|network|ip-address|[-_]ips|[-_]files)/i.test(path)) evidence = '';
    else {
      const rows = csvRows(evidence);
      const headings = (rows.shift() || []).map(cell => cell.trim().toLowerCase());
      const columns = headings.map((cell,index) => /^(?:indicator|domain|ip(?: address| addresses)?|ipv[46]|url|uri|sha[-_ ]?(?:256|1)|md5|hash(?:es)?|value)$/.test(cell) ? index : -1).filter(index => index >= 0);
      evidence = rows.filter(row => !/legitimate|legítimo|legitimo|benign/i.test(row.join(' '))).flatMap(row => columns.map(index => row[index] || '')).join('\n');
    }
  }
  return extractIOCs(evidence, { plaintext: /\.csv$/i.test(path) });
}

// Quoted/multiline CSV cells are parsed before selecting indicator columns.
function csvRows(text) {
  const rows = []; let row = [], cell = '', quoted = false;
  for (let i=0;i<text.length;i++) {
    const char = text[i];
    if (char === '"') { if (quoted && text[i+1] === '"') { cell += '"'; i++; } else quoted = !quoted; }
    else if (char === ',' && !quoted) { row.push(cell); cell=''; }
    else if ((char === '\n' || char === '\r') && !quoted) { if (char === '\r' && text[i+1] === '\n') i++; row.push(cell); if (row.some(value => value.trim())) rows.push(row); row=[]; cell=''; }
    else cell += char;
  }
  row.push(cell); if (row.some(value => value.trim())) rows.push(row);
  if (rows[0]?.[0]) rows[0][0] = rows[0][0].replace(/^\uFEFF/,'');
  return rows;
}

export function createRepositoryResolver({ request, now = () => new Date(), maxReports = 2, treeTtlMs = 3600000 } = {}) {
  return async (feed, previous) => {
    // Only the two built-in, trusted repositories can use this adapter.
    if (!REPOSITORY_SOURCES.some(source => source.url === feed.url && source.repo === feed.repo)) throw new Error('Unknown indicator repository');
    const at = now();
    let tree = previous?.repositoryTree;
    let etag = previous?.treeEtag;
    let checkedAt = previous?.treeCheckedAt;
    let revision = previous?.repositoryRevision;
    if (!Array.isArray(tree) || at.getTime() - new Date(checkedAt).getTime() >= treeTtlMs) {
      const response = await request(`https://api.github.com/repos/${feed.repo}/commits/main`, { headers: { ...apiHeaders, ...(etag ? { 'If-None-Match': etag } : {}) } });
      if (response.status === 304 && Array.isArray(tree)) { /* reuse tree, including deferred reports */ }
      else {
        if (response.status !== 200) throw new Error(`Repository HTTP ${response.status}`);
        const head = json(response);
        if (!/^[a-f0-9]{40}$/.test(head.sha)) throw new Error('Invalid repository revision');
        if (head.sha !== revision || !Array.isArray(tree)) {
          const treeResponse = await request(`https://api.github.com/repos/${feed.repo}/git/trees/${head.sha}?recursive=1`, { headers: apiHeaders });
          if (treeResponse.status !== 200) throw new Error(`Repository tree HTTP ${treeResponse.status}`);
          const data = json(treeResponse);
          if (data.truncated || !Array.isArray(data.tree)) throw new Error('Incomplete repository tree');
          tree = data.tree;
        }
        revision = head.sha; etag = response.headers?.etag || null;
      }
      checkedAt = at.toISOString();
    }
    const dates = { ...previous?.repositoryDates };
    const completed = { ...previous?.repositoryCompleted };
    const candidates = unitsFor(feed, tree);
    const cutoff = at.getTime() - (feed.retentionDays || 30) * 86400000;
    const pending = candidates.filter(unit => {
      unit.signature = unit.files.map(row => row.sha).sort().join(':');
      return completed[unit.path] !== unit.signature && (!unit.date || new Date(unit.date).getTime() >= cutoff);
    });
    const items = [];
    let failed = 0;
    // A cold start is intentionally incremental; subsequent cycles resume units
    // instead of repeatedly reading every file or exhausting GitHub's quota.
    for (const unit of pending.slice(0, maxReports)) {
      try {
        let date = unit.date;
        if (!date) {
          const key = `${unit.path}:${unit.signature}`;
          date = dates[key];
          if (!date) {
            const response = await request(`https://api.github.com/repos/${feed.repo}/commits?path=${encodeURIComponent(unit.path)}&per_page=1&sha=${revision}`, { headers: apiHeaders });
            if (response.status !== 200) throw new Error(`Repository date HTTP ${response.status}`);
            date = json(response)?.[0]?.commit?.committer?.date;
            if (!date || !Number.isFinite(new Date(date).getTime())) throw new Error('Missing repository publication date');
            dates[key] = date;
          }
        }
        if (new Date(date).getTime() < cutoff) { completed[unit.path] = unit.signature; continue; }
        if (unit.files.length > 32 || unit.files.reduce((total,row) => total + row.size,0) > 2000000) throw new Error('Indicator report exceeds collection budget');
        const chunks = await mapConcurrent(unit.files, 2, async row => {
          const address = `https://raw.githubusercontent.com/${feed.repo}/${revision}/${encodedPath(row.path)}`;
          const response = await request(address, { headers: { Accept: 'text/plain' } });
          if (response.status !== 200 || typeof response.data !== 'string' || Buffer.byteLength(response.data) > 512000) throw new Error('Invalid indicator text');
          return { path: row.path, text: response.data, iocs: repositoryIocs(response.data, row.path) };
        });
        const iocs = Object.fromEntries(['ips','domains','hashes','urls'].map(type => [type, [...new Set(chunks.flatMap(chunk => chunk.iocs[type]))]]));
        const title = unit.path.split('/').at(-1).replace(/^\d{4}-\d{2}-\d{2}-/, '').replace(/\.(txt|md)$/i,'').replace(/[-_]/g,' ');
        items.push({ title, description: `Published threat intelligence and indicators · ${feed.source}`, text: chunks.map(chunk => chunk.text).join('\n\n'),
          link: `https://github.com/${feed.repo}/${feed.prefix ? 'tree' : 'blob'}/main/${encodedPath(unit.path)}`, pubDate: new Date(date).toISOString(),
          source: feed.source, layer: feed.layer, repositoryReport: true, publicationTimeKnown: !unit.date, iocs,
          repository: { repo: feed.repo, revision, path: unit.path, files: unit.files.map(row => row.path), dateBasis: unit.date ? 'report-date' : 'last-commit' } });
        completed[unit.path] = unit.signature;
      } catch { failed++; }
    }
    if (failed) throw new Error(`Failed to collect ${failed} indicator report(s); cached results retained`);
    return { response: { status: 200, headers: {} }, items, metadata: { method: 'github', discoveryUrl: feed.url,
      repositoryTree: tree, repositoryRevision: revision, treeEtag: etag, treeCheckedAt: checkedAt,
      repositoryDates: dates, repositoryCompleted: completed, deferredReports: Math.max(0, pending.length - maxReports) } };
  };
}
