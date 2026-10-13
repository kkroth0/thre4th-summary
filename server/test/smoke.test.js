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
const ORG_PROFILES_PATH = path.join(tmpdir(), `threatsumm4ry-smoke-profiles-${PORT}.json`);
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
    writeFileSync(NEWS_ARCHIVE_PATH, JSON.stringify([
        { link: 'https://example.com/a', title: 'ClickFix phishing targets banks in Brazil', source: 'Research', pubDate: '2026-10-08T23:59:59.999Z', storyId: 'same' },
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
            USERS_STORE_PATH, NEWS_ARCHIVE_PATH, ORG_PROFILES_PATH, SECRETS_ENCRYPTION_KEY, URLSCAN_API_KEY: '',
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
    for (const target of [NEWS_ARCHIVE_PATH, ORG_PROFILES_PATH]) { rmSync(target, { force: true }); rmSync(`${target}.tmp`, { force: true }); }
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
    assert.deepEqual(own.keys, { shodan: false, urlscan: true, abuse_ch: false });
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
