// API smoke tests: spawn the real server on a random port and hit routes that
// don't depend on upstream providers (or that have static fallbacks), so the
// suite is hermetic and CI-safe. Run with: npm run test:server
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import { mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 3900 + Math.floor(Math.random() * 100);
const BASE = `http://127.0.0.1:${PORT}`;
const HUNTS_STORE_PATH = `/tmp/threatsumm4ry-smoke-hunts-${PORT}.json`;
const PREMIUM_OPEN_PATH = `/tmp/threatsumm4ry-smoke-premium-${PORT}.json`;
const SESSION_SECRET = 'test-secret';
const sessionBody = Buffer.from(JSON.stringify({ sub: 'smoke-user', login: 'tester', exp: Math.floor(Date.now() / 1000) + 3600 })).toString('base64url');
const sessionSig = crypto.createHmac('sha256', SESSION_SECRET).update(sessionBody).digest('base64url');
const AUTH_HEADERS = { Cookie: `ts_session=${sessionBody}.${sessionSig}` };
const otherSessionBody = Buffer.from(JSON.stringify({ sub: 'other-user', login: 'tester', exp: Math.floor(Date.now() / 1000) + 3600 })).toString('base64url');
const otherSessionSig = crypto.createHmac('sha256', SESSION_SECRET).update(otherSessionBody).digest('base64url');
const OTHER_AUTH_HEADERS = { Cookie: `ts_session=${otherSessionBody}.${otherSessionSig}` };
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

before(async () => {
    proc = spawn(process.execPath, ['index.js'], {
        cwd: path.join(__dirname, '..'),
        env: {
            ...process.env,
            PORT: String(PORT), NODE_ENV: 'test', SESSION_SECRET,
            GITHUB_ALLOWED_LOGINS: 'tester', HUNTS_STORE_PATH, PREMIUM_OPEN_PATH,
        },
        stdio: 'ignore',
    });
    await waitForBoot();
});

after(() => {
    proc?.kill('SIGKILL');
    rmSync(HUNTS_STORE_PATH, { force: true, recursive: true });
    rmSync(`${HUNTS_STORE_PATH}.tmp`, { force: true });
    rmSync(PREMIUM_OPEN_PATH, { force: true });
    rmSync(`${PREMIUM_OPEN_PATH}.tmp`, { force: true });
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

test('GET /api/cves/recent returns CVE list (static fallback offline)', async () => {
    const r = await fetch(`${BASE}/api/cves/recent`);
    assert.equal(r.status, 200);
    const body = await r.json();
    assert.ok(Array.isArray(body) && body.length > 0, 'expected non-empty array');
    assert.ok(body[0].id?.startsWith('CVE-'), 'entries look like CVEs');
});

test('unknown API route yields 404, not a crash', async () => {
    const r = await fetch(`${BASE}/api/definitely-not-a-route`);
    assert.equal(r.status, 404);
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

test('hunting routes exist and require authentication', async () => {
    const requests = await Promise.all([
        fetch(`${BASE}/api/hearth`),
        fetch(`${BASE}/api/hunts`),
        fetch(`${BASE}/api/hunts/coverage?axis=technique`),
        fetch(`${BASE}/api/hunts`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ title: 'x', hypothesis: 'y' }),
        }),
        fetch(`${BASE}/api/hunts/abc`, { method: 'PATCH' }),
        fetch(`${BASE}/api/hunts/abc`, { method: 'DELETE' }),
        fetch(`${BASE}/api/feed/job/abc/related`),
    ]);
    assert.deepEqual(requests.map((response) => response.status), [401, 401, 401, 401, 401, 401, 401]);
});

test('private hunt changes its own ATT&CK and field coverage', async () => {
    const createdResponse = await fetch(`${BASE}/api/hunts`, {
        method: 'POST',
        headers: { ...AUTH_HEADERS, 'Content-Type': 'application/json' },
        body: JSON.stringify({
            title: 'Logon de alto risco', hypothesis: 'Conta comprometida', status: 'ready',
            techniques: ['T1078'], technologies: ['Microsoft Sentinel'], dataSources: ['SigninLogs'],
            query: 'SigninLogs\n| where RiskLevelDuringSignIn == "high"',
        }),
    });
    assert.equal(createdResponse.status, 201);
    const created = await createdResponse.json();

    const [technique, technology, dataSource] = await Promise.all([
        fetch(`${BASE}/api/hunts/coverage?axis=technique`, { headers: AUTH_HEADERS }).then((r) => r.json()),
        fetch(`${BASE}/api/hunts/coverage?axis=technology`, { headers: AUTH_HEADERS }).then((r) => r.json()),
        fetch(`${BASE}/api/hunts/coverage?axis=dataSource`, { headers: AUTH_HEADERS }).then((r) => r.json()),
    ]);
    assert.equal(technique.covered, 1);
    assert.equal(technique.total, 697);
    assert.deepEqual(technology.values, [{ value: 'Microsoft Sentinel', count: 1 }]);
    assert.deepEqual(dataSource.values, [{ value: 'SigninLogs', count: 1 }]);

    const otherList = await fetch(`${BASE}/api/hunts`, { headers: OTHER_AUTH_HEADERS }).then((r) => r.json());
    assert.deepEqual(otherList.items, []);
    const [otherPatch, otherDelete] = await Promise.all([
        fetch(`${BASE}/api/hunts/${created.hunt.id}`, { method: 'PATCH', headers: OTHER_AUTH_HEADERS }),
        fetch(`${BASE}/api/hunts/${created.hunt.id}`, { method: 'DELETE', headers: OTHER_AUTH_HEADERS }),
    ]);
    assert.deepEqual([otherPatch.status, otherDelete.status], [404, 404]);

    const patched = await fetch(`${BASE}/api/hunts/${created.hunt.id}`, {
        method: 'PATCH', headers: { ...AUTH_HEADERS, 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: 'Logon de alto risco atualizado' }),
    });
    assert.equal(patched.status, 200);
    assert.equal((await patched.json()).hunt.title, 'Logon de alto risco atualizado');

    const deleted = await fetch(`${BASE}/api/hunts/${created.hunt.id}`, { method: 'DELETE', headers: AUTH_HEADERS });
    assert.equal(deleted.status, 200);
    assert.deepEqual((await deleted.json()).items, []);
});

test('persistence failure does not report a hunt as saved', async () => {
    rmSync(HUNTS_STORE_PATH, { force: true });
    mkdirSync(HUNTS_STORE_PATH);
    try {
        const response = await fetch(`${BASE}/api/hunts`, {
            method: 'POST',
            headers: { ...AUTH_HEADERS, 'Content-Type': 'application/json' },
            body: JSON.stringify({ title: 'Não pode sumir', hypothesis: 'Falha de disco' }),
        });
        assert.equal(response.status, 500);
        const own = await fetch(`${BASE}/api/hunts`, { headers: AUTH_HEADERS }).then((r) => r.json());
        assert.deepEqual(own.items, []);
    } finally {
        rmSync(HUNTS_STORE_PATH, { force: true, recursive: true });
        rmSync(`${HUNTS_STORE_PATH}.tmp`, { force: true });
    }
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

test('execucao de hunt: abre, fecha com achado e entra no resumo do mes', async () => {
    const criada = await fetch(`${BASE}/api/hunts`, {
        method: 'POST',
        headers: { ...AUTH_HEADERS, 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: 'Egress incomum', hypothesis: 'saida para dominio novo', techniques: ['T1071'] }),
    });
    assert.equal(criada.status, 201);
    const { hunt } = await criada.json();

    const aberta = await fetch(`${BASE}/api/hunts/${hunt.id}/runs`, {
        method: 'POST',
        headers: { ...AUTH_HEADERS, 'Content-Type': 'application/json' },
        body: JSON.stringify({ state: 'running' }),
    });
    assert.equal(aberta.status, 201);
    const { run } = await aberta.json();
    assert.equal(run.finishedAt, null);

    const fechada = await fetch(`${BASE}/api/hunts/${hunt.id}/runs/${run.id}`, {
        method: 'PATCH',
        headers: { ...AUTH_HEADERS, 'Content-Type': 'application/json' },
        body: JSON.stringify({ state: 'done', outcome: 'suspicious', events: 7, findings: 'sete conexoes para dominio de 2 dias' }),
    });
    assert.equal(fechada.status, 200);
    const fechadaBody = await fechada.json();
    assert.equal(fechadaBody.run.outcome, 'suspicious');
    assert.ok(fechadaBody.run.finishedAt, 'execucao fechada carimba o fim');

    const mes = new Date().toISOString().slice(0, 7);
    const resumo = await fetch(`${BASE}/api/hunts/runs/summary?month=${mes}`, { headers: AUTH_HEADERS });
    assert.equal(resumo.status, 200);
    const corpo = await resumo.json();
    assert.equal(corpo.byState.done >= 1, true);
    assert.equal(corpo.byOutcome.suspicious >= 1, true);

    const porTecnica = await fetch(`${BASE}/api/hunts/by-technique/T1071`, { headers: AUTH_HEADERS });
    assert.equal(porTecnica.status, 200);
    const indice = await porTecnica.json();
    assert.equal(indice.hunts.some((item) => item.id === hunt.id), true);
    assert.equal(indice.hunts.find((item) => item.id === hunt.id).lastRun.outcome, 'suspicious');

    const invalida = await fetch(`${BASE}/api/hunts/by-technique/T99`, { headers: AUTH_HEADERS });
    assert.equal(invalida.status, 400);
});

test('execucao de outro dono nao existe pra quem consulta', async () => {
    const criada = await fetch(`${BASE}/api/hunts`, {
        method: 'POST',
        headers: { ...AUTH_HEADERS, 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: 'Privada', hypothesis: 'so do dono' }),
    });
    const { hunt } = await criada.json();

    const invasao = await fetch(`${BASE}/api/hunts/${hunt.id}/runs`, {
        method: 'POST',
        headers: { ...OTHER_AUTH_HEADERS, 'Content-Type': 'application/json' },
        body: JSON.stringify({ state: 'running' }),
    });
    assert.equal(invasao.status, 404);
});
