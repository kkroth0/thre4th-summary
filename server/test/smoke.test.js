// API smoke tests: spawn the real server on a random port and hit routes that
// don't depend on upstream providers (or that have static fallbacks), so the
// suite is hermetic and CI-safe. Run with: npm run test:server
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import { readFileSync, writeFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 3900 + Math.floor(Math.random() * 100);
const BASE = `http://127.0.0.1:${PORT}`;
const PREMIUM_OPEN_PATH = path.join(tmpdir(), `threatsumm4ry-smoke-premium-${PORT}.json`);
const NEWS_MONITORING_PATH = path.join(tmpdir(), `threatsumm4ry-smoke-monitoring-${PORT}.json`);
const USERS_STORE_PATH = path.join(tmpdir(), `threatsumm4ry-smoke-users-${PORT}.json`);
const NEWS_ARCHIVE_PATH = path.join(tmpdir(), `threatsumm4ry-smoke-archive-${PORT}.json`);
const NEWS_STORIES_PATH = path.join(tmpdir(), `threatsumm4ry-smoke-stories-${PORT}.json`);
const FEED_JOBS_PATH = path.join(tmpdir(), `threatsumm4ry-smoke-jobs-${PORT}.json`);
const ORG_PROFILES_PATH = path.join(tmpdir(), `threatsumm4ry-smoke-profiles-${PORT}.json`);
const PHISH_WATCH_PATH = path.join(tmpdir(), `threatsumm4ry-smoke-watch-${PORT}.json`);
const SECRETS_ENCRYPTION_KEY = 'smoke-only-encryption-secret';
const SESSION_SECRET = 'test-secret';
const sessionBody = Buffer.from(JSON.stringify({ sub: 'smoke-user', login: 'tester', exp: Math.floor(Date.now() / 1000) + 3600 })).toString('base64url');
const sessionSig = crypto.createHmac('sha256', SESSION_SECRET).update(sessionBody).digest('base64url');
const AUTH_HEADERS = { Cookie: `ts_session=${sessionBody}.${sessionSig}` };
const outsiderBody = Buffer.from(JSON.stringify({ sub: 'outsider', login: 'outsider', exp: Math.floor(Date.now() / 1000) + 3600 })).toString('base64url');
const outsiderSig = crypto.createHmac('sha256', SESSION_SECRET).update(outsiderBody).digest('base64url');
const OUTSIDER_HEADERS = { Cookie: `ts_session=${outsiderBody}.${outsiderSig}` };
let proc;

async function waitForBoot(timeoutMs = 15000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        try {
            const r = await fetch(`${BASE}/api/vendors/status`, { signal: AbortSignal.timeout(1500) });
            if (r.ok) return;
        } catch { /* not up yet */ }
        await new Promise((r) => setTimeout(r, 300));
    }
    throw new Error('server did not boot within 15s');
}

test('domain investigation and actor archive endpoints enforce premium access and validate targets before upstream calls', async () => {
    for (const endpoint of ['/api/actors/activity', '/api/actors/G0032/evidence']) {
        assert.equal((await fetch(`${BASE}${endpoint}`)).status, 401);
    }
    const body = { method: 'POST', headers: { ...AUTH_HEADERS, 'Content-Type': 'application/json' }, body: JSON.stringify({ query: '127.0.0.1' }) };
    assert.equal((await fetch(`${BASE}/api/domain/subdomains`, body)).status, 400);
    assert.equal((await fetch(`${BASE}/api/domain/constructor`, body)).status, 404);
    assert.equal((await fetch(`${BASE}/api/domain/subdomains`, { ...body, headers: { 'Content-Type': 'application/json' } })).status, 401);
    assert.equal((await fetch(`${BASE}/api/actors/G0032/evidence?days=-1`, { headers: AUTH_HEADERS })).status, 400);
    const activity = await fetch(`${BASE}/api/actors/activity`, { headers: AUTH_HEADERS });
    assert.equal(activity.status, 200); assert.equal(activity.headers.get('Cache-Control'), 'private, no-store');
});

before(async () => {
    writeFileSync(NEWS_STORIES_PATH, '[]');
    writeFileSync(PHISH_WATCH_PATH, JSON.stringify({ hits: [{ id: 'owned:example.net', profileId: 'owned', ownerId: 'smoke-user', apexDomain: 'example.net', domain: 'example.net', status: 'new', score: 20, reasons: ['brand-glued'], firstSeen: '2026-10-08T12:00:00Z', lastSeen: new Date().toISOString() }], runs: {} }));
    writeFileSync(FEED_JOBS_PATH, JSON.stringify({ 'smoke-multi-source': { id: 'smoke-multi-source', url: 'https://example.com/a', urls: ['https://example.com/a', 'https://example.com/b'], status: 'pending', createdAt: new Date().toISOString() } }));
    writeFileSync(NEWS_ARCHIVE_PATH, JSON.stringify([
        { link: 'https://example.com/a', title: 'ClickFix phishing targets banks in Brazil with fake Adobe login pages', source: 'Research', pubDate: '2026-10-08T23:59:59.999Z', storyId: 'same', iocs: { ips: ['9.9.9.10'], domains: ['example.net'] } },
        { link: 'https://example.com/b', title: 'ClickFix phishing campaign', source: 'News', pubDate: '2026-10-09T00:00:00Z', storyId: 'same' },
    ]));
    writeFileSync(ORG_PROFILES_PATH, JSON.stringify([
        { id: 'owned', ownerId: 'smoke-user', name: 'Own profile', sectors: ['Financial'] },
        { id: 'private', ownerId: 'outsider', name: 'Private profile', sectors: ['Financial'] },
    ]));
    proc = spawn(process.execPath, ['index.js'], {
        cwd: path.join(__dirname, '..'),
        env: {
            ...process.env,
            PORT: String(PORT), NODE_ENV: 'test', SESSION_SECRET,
            GITHUB_ALLOWED_LOGINS: 'tester', PREMIUM_OPEN_PATH, NEWS_MONITORING_PATH,
            USERS_STORE_PATH, NEWS_ARCHIVE_PATH, NEWS_STORIES_PATH, ORG_PROFILES_PATH, PHISH_WATCH_PATH, SECRETS_ENCRYPTION_KEY, URLSCAN_API_KEY: '',
            FEED_JOBS_PATH, FEED_AGENT_SECRET: 'smoke-worker-secret',
        },
        stdio: 'ignore',
    });
    await waitForBoot();
});

after(() => {
    proc?.kill('SIGKILL');
    rmSync(PREMIUM_OPEN_PATH, { force: true });
    rmSync(`${PREMIUM_OPEN_PATH}.tmp`, { force: true });
    rmSync(NEWS_MONITORING_PATH, { force: true });
    rmSync(`${NEWS_MONITORING_PATH}.tmp`, { force: true });
    rmSync(USERS_STORE_PATH, { force: true });
    rmSync(`${USERS_STORE_PATH}.tmp`, { force: true });
    for (const target of [NEWS_ARCHIVE_PATH, NEWS_STORIES_PATH, ORG_PROFILES_PATH, FEED_JOBS_PATH, PHISH_WATCH_PATH]) { rmSync(target, { force: true }); rmSync(`${target}.tmp`, { force: true }); }
});

test('weekly evidence and private watch context enforce access, preserve candidate roles and separate inconclusive verdicts', async () => {
    for (const endpoint of ['/api/phishing/evolution', '/api/phishing-watch/intelligence', '/api/phishing-watch/hits/owned%3Aexample.net/context']) assert.equal((await fetch(BASE + endpoint)).status, 401);
    const weekly = await fetch(BASE + '/api/phishing/evolution', { headers: AUTH_HEADERS });
    assert.equal(weekly.status, 200); assert.equal(weekly.headers.get('cache-control'), 'private, no-store');
    const overview = await weekly.json(); assert.equal(overview.weeks.length, 10);
    const weekUrl = BASE + '/api/phishing/evolution/weeks/' + overview.target;
    assert.equal((await fetch(weekUrl)).status, 401);
    const weekResponse = await fetch(weekUrl, { headers: AUTH_HEADERS }); assert.equal(weekResponse.status, 200);
    assert.equal(weekResponse.headers.get('cache-control'), 'private, no-store');
    const weekEvidence = await weekResponse.json(); assert.equal(weekEvidence.week, overview.target); assert.equal(weekEvidence.members.length, weekEvidence.publications);
    assert.equal((await fetch(BASE + '/api/phishing-watch/intelligence?profileId=private', { headers: AUTH_HEADERS })).status, 404);
    const context = await fetch(BASE + '/api/phishing-watch/hits/owned%3Aexample.net/context', { headers: AUTH_HEADERS }).then(res => res.json());
    assert.equal(context.candidate.role, 'candidate'); assert.ok(context.publications.some(row => row.link === 'https://example.com/a'));
    const response = await fetch(BASE + '/api/phishing-watch/hits/owned%3Aexample.net/verdict', { method: 'POST', headers: { ...AUTH_HEADERS, 'Content-Type': 'application/json' }, body: JSON.stringify({ verdict: 'inconclusive', reason: 'duplicate' }) });
    assert.equal(response.status, 200);
    const summary = await fetch(BASE + '/api/phishing-watch/intelligence?profileId=owned', { headers: AUTH_HEADERS }).then(res => res.json());
    assert.equal(summary.precision, null); assert.equal(summary.unresolved, 1);
});

test('SQLite storage and news-based monitoring suggestions enforce access and explicit account-owned acceptance', async () => {
    for (const route of ['/api/intelligence/storage','/api/intelligence/entities?kind=actor','/api/phishing-watch/suggestions?profileId=owned']) assert.equal((await fetch(BASE+route)).status,401);
    assert.equal((await fetch(BASE+'/api/phishing-watch/suggestions?profileId=private',{headers:AUTH_HEADERS})).status,404);
    const storage=await fetch(BASE+'/api/intelligence/storage',{headers:AUTH_HEADERS}).then(res=>res.json());
    assert.equal(storage.mode,'sqlite'); assert.equal(storage.latest.equal,true); assert.equal(storage.latest.archive.source,2); assert.equal(storage.backup.ok,true);
    const response=await fetch(BASE+'/api/phishing-watch/suggestions?profileId=owned',{headers:AUTH_HEADERS});
    assert.equal(response.headers.get('cache-control'),'private, no-store');
    const data=await response.json(); const suggestion=data.suggestions.find(row=>row.term==='adobe'); assert.ok(suggestion);
    const review=(headers,decision)=>fetch(BASE+`/api/phishing-watch/suggestions/${suggestion.id}/review`,{method:'POST',headers:{...headers,'Content-Type':'application/json'},body:JSON.stringify({profileId:'owned',decision})});
    assert.equal((await review(OUTSIDER_HEADERS,'accepted')).status,403);
    assert.equal((await review(AUTH_HEADERS,'accepted')).status,200);
    const profiles=await fetch(BASE+'/api/org/profiles',{headers:AUTH_HEADERS}).then(res=>res.json());
    assert.ok(profiles.profiles.find(row=>row.id==='owned').brands.includes('adobe'));
    assert.equal((await fetch(BASE+'/api/phishing-watch/suggestions?profileId=owned',{headers:AUTH_HEADERS}).then(res=>res.json())).suggestions.length,0);
    assert.equal((await fetch(BASE+'/api/org/profiles/owned',{method:'PATCH',headers:{...AUTH_HEADERS,'Content-Type':'application/json'},body:JSON.stringify({brands:[]})})).status,200);
});

test('the worker receives all selected sources and requires its dedicated secret', async () => {
    assert.equal((await fetch(`${BASE}/api/feed/jobs/pending`)).status, 401);
    const result = await fetch(`${BASE}/api/feed/jobs/pending`, { headers: { 'X-Feed-Secret': 'smoke-worker-secret' } }).then(res => res.json());
    assert.deepEqual(result.pending[0].urls, ['https://example.com/a', 'https://example.com/b']);
    assert.ok(!JSON.stringify(result).includes('smoke-worker-secret'));
});

test('unified IOC inventory and export require premium and validate dates',async()=>{
    for(const route of ['/api/intelligence/status','/api/intelligence/iocs','/api/intelligence/ioc?value=46.101.130.1','/api/intelligence/export?from=2026-10-01&to=2026-10-13'])assert.equal((await fetch(BASE+route)).status,401);
    const response=await fetch(BASE+'/api/intelligence/iocs',{headers:AUTH_HEADERS});
    assert.equal(response.status,200);assert.equal((await response.json()).total,0);
    assert.equal((await fetch(BASE+'/api/intelligence/export?from=bad&to=2026-10-13',{headers:AUTH_HEADERS})).status,400);
    const exported=await fetch(BASE+'/api/intelligence/export?from=2026-10-01&to=2026-10-13&format=json',{headers:AUTH_HEADERS});
    assert.equal(exported.status,200);assert.equal((await exported.json()).total,0);
});

test('archive export enforces authentication, applies monitoring and includes final-day IOC evidence', async () => {
    const route = '/api/news/export?from=2026-10-08&to=2026-10-08&dataset=iocs&format=json';
    assert.equal((await fetch(BASE + route)).status, 401);
    const response = await fetch(BASE + route, { headers: AUTH_HEADERS });
    assert.equal(response.status, 200); assert.equal(response.headers.get('cache-control'), 'private, no-store');
    assert.match(response.headers.get('content-disposition'), /attachment/);
    const result = await response.json(); assert.equal(result.publications, 1); assert.equal(result.count, 2);
    assert.equal(result.rows[0].url, 'https://example.com/a');
    assert.equal((await fetch(`${BASE}/api/news/export?from=2026-02-30&to=2026-10-08`, { headers: AUTH_HEADERS })).status, 400);
    const csv = await fetch(`${BASE}/api/news/export?from=2026-10-08&to=2026-10-09`, { headers: AUTH_HEADERS }).then(res => res.text());
    assert.ok(csv.includes('ClickFix phishing campaign'));
    assert.equal((await fetch(BASE + route, { headers: OUTSIDER_HEADERS })).status, 403);
    await fetch(`${BASE}/api/news/monitoring`, { method: 'PUT', headers: { ...AUTH_HEADERS, 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'selected', vendorIds: [] }) });
    const empty = await fetch(BASE + route, { headers: AUTH_HEADERS }).then(res => res.json());
    assert.equal(empty.count, 0);
    await fetch(`${BASE}/api/news/monitoring`, { method: 'PUT', headers: { ...AUTH_HEADERS, 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'all', vendorIds: [] }) });
});

test('phishing report API enforces owner isolation, strict dates and includes the last day', async () => {
    assert.equal((await fetch(`${BASE}/api/phishing/reports`)).status, 401);
    const response = await fetch(`${BASE}/api/phishing/reports?from=2026-08-01&to=2026-10-08`, { headers: AUTH_HEADERS });
    assert.equal(response.status, 200);
    assert.match(response.headers.get('cache-control'), /private.*no-store/);
    const data = await response.json();
    assert.equal(data.reports.length, 1);
    assert.equal(data.summary.publications, 1);
    assert.deepEqual(data.facets.profiles, [{ id: 'owned', name: 'Own profile' }]);
    assert.ok(!JSON.stringify(data).includes('Private profile'));
    assert.equal((await fetch(`${BASE}/api/phishing/reports?profileId=private`, { headers: AUTH_HEADERS })).status, 404);
    assert.equal((await fetch(`${BASE}/api/phishing/reports?from=2026-02-30`, { headers: AUTH_HEADERS })).status, 400);
    const own = await fetch(`${BASE}/api/phishing/reports?profileId=owned&region=Brazil`, { headers: AUTH_HEADERS }).then(res => res.json());
    assert.equal(own.reports.length, 1);
    assert.deepEqual(own.reports[0].profileMatches[0].reasons, ['Setor: Financial']);
});

test('GET /api/vendors/status returns vendor map', async () => {
    const r = await fetch(`${BASE}/api/vendors/status`);
    assert.equal(r.status, 200);
    const body = await r.json();
    assert.equal(typeof body, 'object');
    assert.ok(Object.keys(body).length > 0, 'expected at least one vendor entry');
});

test('actor list exposes slim technique ids for local correlation', async () => {
    const response = await fetch(`${BASE}/api/actors`);
    assert.equal(response.status, 200);
    const body = await response.json();
    const mapped = body.actors.find((actor) => actor.technique_count > 0);
    assert.ok(mapped);
    assert.equal(mapped.techniques.length, mapped.technique_count);
    assert.match(mapped.techniques[0], /^T\d{4}(?:\.\d{3})?$/);
});

test('GET /api/auth/me unauthenticated', async () => {
    const r = await fetch(`${BASE}/api/auth/me`);
    assert.equal(r.status, 200);
    const body = await r.json();
    assert.equal(body.authenticated, false);
});

test('lookup performance counters are restricted to administrators and reveal no queries or keys', async () => {
    const endpoint = `${BASE}/api/admin/performance`;
    assert.equal((await fetch(endpoint)).status, 401);
    assert.equal((await fetch(endpoint, { headers: OUTSIDER_HEADERS })).status, 403);
    const response = await fetch(endpoint, { headers: AUTH_HEADERS });
    assert.equal(response.status, 200); assert.equal(response.headers.get('cache-control'), 'private, no-store');
    const body = await response.json(); assert.equal(typeof body.lookups.hits, 'number');
    assert.ok(!('queries' in body.lookups)); assert.ok(!('credentials' in body.lookups));
});

test('GET /api/cves/recent never fabricates CVEs before source import', async () => {
    const r = await fetch(`${BASE}/api/cves/recent`);
    assert.equal(r.status, 200);
    const body = await r.json();
    assert.deepEqual(body, []);
    assert.match(r.headers.get('cache-control'), /no-store/);
});

test('public vulnerability APIs expose an empty pending catalog until real records arrive', async () => {
    for (const view of ['listing', 'top', 'weaponized']) {
        const response = await fetch(`${BASE}/api/vulnerabilities?view=${view}&page=1&size=25`);
        assert.equal(response.status, 200);
        assert.match(response.headers.get('cache-control'), /no-store/);
        const body = await response.json();
        assert.deepEqual(body.rows, []); assert.equal(body.total, 0);
        assert.equal(body.status.yearsImported, 0);
        assert.equal(body.status.sources.nvd.status, 'pending');
    }
    const overview = await fetch(`${BASE}/api/vulnerabilities/overview`);
    assert.equal(overview.status, 200); assert.equal((await overview.json()).stats.total, 0);
});

test('vulnerability refresh requires authentication and unknown CVEs return 404', async () => {
    const refresh = await fetch(`${BASE}/api/vulnerabilities/refresh`, { method: 'POST' });
    assert.equal(refresh.status, 401);
    const missing = await fetch(`${BASE}/api/vulnerabilities/CVE-2026-99999`);
    assert.equal(missing.status, 404);
});

test('unknown API route yields 404, not a crash', async () => {
    const r = await fetch(`${BASE}/api/definitely-not-a-route`);
    assert.equal(r.status, 404);
});

test('monitoramento exige sessão, aceita usuário comum e isola preferências por conta', async () => {
    const anon = await fetch(`${BASE}/api/news/monitoring`);
    assert.equal(anon.status, 401);
    const denied = await fetch(`${BASE}/api/news/monitoring`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'selected', vendorIds: ['cisco'] }) });
    assert.equal(denied.status, 401);
    const catalog = await fetch(`${BASE}/api/news/monitoring`, { headers: OUTSIDER_HEADERS });
    assert.equal(catalog.status, 200);
    assert.match(catalog.headers.get('cache-control'), /private.*no-store/);
    const data = await catalog.json();
    assert.ok(data.vendors.some((vendor) => vendor.id === 'fortinet' && vendor.aliases.includes('FortiGate')));
    const saved = await fetch(`${BASE}/api/news/monitoring`, { method: 'PUT', headers: { ...OUTSIDER_HEADERS, 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'selected', vendorIds: ['fortinet'], ownerId: 'smoke-user' }) });
    assert.equal(saved.status, 200);
    assert.deepEqual((await saved.json()).preferences.vendorIds, ['fortinet']);
    const own = await fetch(`${BASE}/api/news/monitoring`, { headers: OUTSIDER_HEADERS });
    assert.deepEqual((await own.json()).preferences.vendorIds, ['fortinet']);
    const other = await fetch(`${BASE}/api/news/monitoring`, { headers: AUTH_HEADERS });
    assert.equal((await other.json()).preferences.mode, 'all');
    const invalid = await fetch(`${BASE}/api/news/monitoring`, { method: 'PUT', headers: { ...OUTSIDER_HEADERS, 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'selected', vendorIds: ['not-a-vendor'] }) });
    assert.equal(invalid.status, 400);
});

test('urlscan BYOK é cifrado, isolado por conta e ativa a busca sem chave da plataforma', async () => {
    const key = 'urlscan-smoke-personal-key';
    const route = `${BASE}/api/user/keys/urlscan`;
    const write = (headers, value) => fetch(route, {
        method: 'PUT', headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: value, ownerId: 'outsider' }),
    });
    assert.equal((await write({}, key)).status, 401);
    assert.equal((await write(AUTH_HEADERS, 'short')).status, 400);
    const watchStatus = () => fetch(`${BASE}/api/phishing-watch/hits`, { headers: AUTH_HEADERS }).then(r => r.json());
    assert.equal((await watchStatus()).configured, false);

    const saved = await write(AUTH_HEADERS, key);
    assert.equal(saved.status, 200);
    assert.deepEqual(await saved.json(), { provider: 'urlscan', hasKey: true });
    const own = await fetch(`${BASE}/api/user/keys`, { headers: AUTH_HEADERS }).then(r => r.json());
    assert.deepEqual(own.keys, { shodan: false, urlscan: true, abuse_ch: false, otx:false, abuseipdb:false });
    assert.ok(!JSON.stringify(own).includes(key));
    const other = await fetch(`${BASE}/api/user/keys`, { headers: OUTSIDER_HEADERS }).then(r => r.json());
    assert.equal(other.keys.urlscan, false);

    const disk = readFileSync(USERS_STORE_PATH, 'utf8');
    assert.ok(!disk.includes(key), 'segredo não pode ficar em texto aberto');
    const blob = Buffer.from(JSON.parse(disk)['smoke-user'].apiKeysEnc.urlscan, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', crypto.createHash('sha256').update(SECRETS_ENCRYPTION_KEY).digest(), blob.subarray(0, 12));
    decipher.setAuthTag(blob.subarray(12, 28));
    assert.equal(Buffer.concat([decipher.update(blob.subarray(28)), decipher.final()]).toString(), key);
    assert.equal((await watchStatus()).configured, true);
    // Perfil inexistente chega à autorização do perfil, sem chamar o fornecedor.
    const run = await fetch(`${BASE}/api/phishing-watch/run`, {
        method: 'POST', headers: { ...AUTH_HEADERS, 'Content-Type': 'application/json' },
        body: JSON.stringify({ profileId: 'missing-byok-profile' }),
    });
    assert.equal(run.status, 404);
    assert.equal((await fetch(route, { method: 'DELETE', headers: OUTSIDER_HEADERS })).status, 200);
    assert.equal((await watchStatus()).configured, true, 'outra conta não remove nossa chave');
    assert.equal((await fetch(route, { method: 'DELETE', headers: AUTH_HEADERS })).status, 200);
    assert.equal((await watchStatus()).configured, false);
    assert.equal(JSON.parse(readFileSync(USERS_STORE_PATH, 'utf8'))['smoke-user'].apiKeysEnc.urlscan, undefined);
});

test('Abuse.ch BYOK is encrypted and isolated from other accounts', async () => {
    const key = 'abuse-ch-smoke-personal-key';
    const route = `${BASE}/api/user/keys/abuse_ch`;
    assert.equal((await fetch(route, { method: 'PUT', headers: { ...AUTH_HEADERS, 'Content-Type': 'application/json' }, body: JSON.stringify({ key }) })).status, 200);
    const own = await fetch(`${BASE}/api/user/keys`, { headers: AUTH_HEADERS }).then(r => r.json());
    const other = await fetch(`${BASE}/api/user/keys`, { headers: OUTSIDER_HEADERS }).then(r => r.json());
    assert.equal(own.keys.abuse_ch, true);
    assert.equal(other.keys.abuse_ch, false);
    assert.ok(!JSON.stringify(own).includes(key));
    const disk = readFileSync(USERS_STORE_PATH, 'utf8');
    assert.ok(!disk.includes(key));
    const blob = Buffer.from(JSON.parse(disk)['smoke-user'].apiKeysEnc.abuse_ch, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', crypto.createHash('sha256').update(SECRETS_ENCRYPTION_KEY).digest(), blob.subarray(0, 12));
    decipher.setAuthTag(blob.subarray(12, 28));
    assert.equal(Buffer.concat([decipher.update(blob.subarray(28)), decipher.final()]).toString(), key);
    assert.equal((await fetch(route, { method: 'DELETE', headers: OUTSIDER_HEADERS })).status, 200);
    assert.equal((await fetch(`${BASE}/api/user/keys`, { headers: AUTH_HEADERS }).then(r => r.json())).keys.abuse_ch, true);
    assert.equal((await fetch(route, { method: 'DELETE', headers: AUTH_HEADERS })).status, 200);
    assert.equal((await fetch(`${BASE}/api/user/keys`, { headers: AUTH_HEADERS }).then(r => r.json())).keys.abuse_ch, false);
});

test('malware routes enforce authentication and validate queries before contacting providers', async () => {
    for (const route of ['/api/malware/families', '/api/malware/family?id=win.vidar', '/api/malware/sample/' + 'a'.repeat(64)]) {
        assert.equal((await fetch(`${BASE}${route}`)).status, 401);
    }
    assert.equal((await fetch(`${BASE}/api/malware/family`, { headers: AUTH_HEADERS })).status, 400);
    assert.equal((await fetch(`${BASE}/api/malware/sample/invalid`, { headers: AUTH_HEADERS })).status, 400);
});

test('removed provider endpoints return 404', async () => {
    for (const route of ['/api/dnsbl', '/api/dnsbl/batch', '/api/censys', '/api/teamcymru', '/api/hybridanalysis', '/api/metadefender', '/api/circl', '/api/pulsedive']) {
        const response = await fetch(`${BASE}${route}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query: '8.8.8.8', provider: 'zen.spamhaus.org', providers: ['zen.spamhaus.org'] }),
        });
        assert.equal(response.status, 404, route);
    }
});

test('removed hunt-pack endpoint yields 404', async () => {
    const r = await fetch(`${BASE}/api/newsletter/hunt-pack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: 'https://example.com/report', lang: 'en' }),
    });
    assert.equal(r.status, 404);
});

test('premium route rejects anonymous users', async () => {
    const r = await fetch(`${BASE}/api/feed/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: 'https://example.com' }),
    });
    assert.ok([401, 403].includes(r.status), `expected 401/403, got ${r.status}`);
});

test('legacy groq-key endpoint is gone', async () => {
    const r = await fetch(`${BASE}/api/user/groq-key`, { method: 'PUT' });
    assert.equal(r.status, 404);
});

test('exposure watchlist requires authentication', async () => {
    const r = await fetch(`${BASE}/api/exposure-watchlist/assets`);
    assert.equal(r.status, 401);
    const body = await r.json();
    assert.equal(body.needAuth, true);
});

test('knowledge routes exist and require authentication', async () => {
    // 401 e não 404: prova que as três rotas estão montadas e que o gate roda
    // antes de qualquer escrita no store.
    const get = await fetch(`${BASE}/api/knowledge`);
    const post = await fetch(`${BASE}/api/knowledge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: 'https://example.com/a', title: 'x' }),
    });
    const del = await fetch(`${BASE}/api/knowledge/abc`, { method: 'DELETE' });
    assert.deepEqual([get.status, post.status, del.status], [401, 401, 401]);
});

test('daily edition route rejects malformed and unavailable historical dates', async () => {
    const malformed = await fetch(`${BASE}/api/intel/daily-brief?date=not-a-date`);
    assert.equal(malformed.status, 400);

    const unavailable = await fetch(`${BASE}/api/intel/daily-brief?date=2000-01-01`);
    assert.equal(unavailable.status, 404);
    const body = await unavailable.json();
    assert.match(body.error, /not found/i);
});

test('gate premium aberto libera quem está fora da allow-list, e fechar volta a barrar', async () => {
    const gate = (premiumOpen) => fetch(`${BASE}/api/admin/premium-open`, {
        method: 'PUT',
        headers: { ...AUTH_HEADERS, 'Content-Type': 'application/json' },
        body: JSON.stringify({ premiumOpen }),
    });

    const initial = await fetch(`${BASE}/api/admin/premium-open`, { headers: AUTH_HEADERS });
    assert.equal(initial.status, 200);
    assert.equal((await initial.json()).premiumOpen, false, 'o padrão precisa ser fechado');

    const blocked = await fetch(`${BASE}/api/knowledge`, { headers: OUTSIDER_HEADERS });
    assert.equal(blocked.status, 403);

    assert.equal((await (await gate(true)).json()).premiumOpen, true);
    const allowed = await fetch(`${BASE}/api/knowledge`, { headers: OUTSIDER_HEADERS });
    assert.equal(allowed.status, 200);

    assert.equal((await (await gate(false)).json()).premiumOpen, false);
    const blockedAgain = await fetch(`${BASE}/api/knowledge`, { headers: OUTSIDER_HEADERS });
    assert.equal(blockedAgain.status, 403);
});

test('gate premium so aceita admin: sessao comum leva 403 e nao muda nada', async () => {
    const r = await fetch(`${BASE}/api/admin/premium-open`, {
        method: 'PUT',
        headers: { ...OUTSIDER_HEADERS, 'Content-Type': 'application/json' },
        body: JSON.stringify({ premiumOpen: true }),
    });
    assert.equal(r.status, 403);

    const leitura = await fetch(`${BASE}/api/admin/premium-open`, { headers: OUTSIDER_HEADERS });
    assert.equal(leitura.status, 403);

    const aindaBarrado = await fetch(`${BASE}/api/knowledge`, { headers: OUTSIDER_HEADERS });
    assert.equal(aindaBarrado.status, 403);
});

test('gate premium não aceita sessão anônima', async () => {
    const r = await fetch(`${BASE}/api/admin/premium-open`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ premiumOpen: true }),
    });
    assert.equal(r.status, 401);
});


test('weekly reports enforce account access, Sunday boundaries and profile ownership', async () => {
    assert.equal((await fetch(`${BASE}/api/reports/weekly`)).status,401);
    assert.equal((await fetch(`${BASE}/api/reports/weekly?week=2026-10-12`,{headers:AUTH_HEADERS})).status,400);
    const historical=await fetch(`${BASE}/api/reports/weekly?week=2026-10-04`,{headers:AUTH_HEADERS});
    assert.equal(historical.status,200);assert.equal(historical.headers.get('Cache-Control'),'private, no-store');
    assert.equal((await historical.json()).report,null);
    const response=await fetch(`${BASE}/api/reports/weekly`,{method:'PUT',headers:{...AUTH_HEADERS,'Content-Type':'application/json'},body:JSON.stringify({enabled:false,profileId:'private'})});
    assert.equal(response.status,400);
    const allowed=await fetch(`${BASE}/api/reports/weekly`,{method:'PUT',headers:{...AUTH_HEADERS,'Content-Type':'application/json'},body:JSON.stringify({enabled:false,profileId:'owned'})});
    assert.equal(allowed.status,200);assert.equal((await allowed.json()).plan.profileId,'owned');
});
