// API smoke tests: spawn the real server on a random port and hit routes that
// don't depend on upstream providers (or that have static fallbacks), so the
// suite is hermetic and CI-safe. Run with: npm run test:server
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 3900 + Math.floor(Math.random() * 100);
const BASE = `http://127.0.0.1:${PORT}`;
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
        env: { ...process.env, PORT: String(PORT), NODE_ENV: 'test', SESSION_SECRET: 'test-secret' },
        stdio: 'ignore',
    });
    await waitForBoot();
});

after(() => { proc?.kill('SIGKILL'); });

test('GET /api/vendors/status returns vendor map', async () => {
    const r = await fetch(`${BASE}/api/vendors/status`);
    assert.equal(r.status, 200);
    const body = await r.json();
    assert.equal(typeof body, 'object');
    assert.ok(Object.keys(body).length > 0, 'expected at least one vendor entry');
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
