import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHmac, randomBytes } from 'node:crypto';
import { createServer } from 'node:net';
import { once } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

test('assistant HTTP routes start safely, enforce account gates and origin, and read archived news without a bot', { timeout: 30000 }, async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'assistant-http-'));
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  const write = (name, value) => { const file = path.join(directory, name); fs.writeFileSync(file, JSON.stringify(value)); return file; };
  const portServer = createServer(); portServer.listen(0, '127.0.0.1'); await once(portServer, 'listening');
  const port = portServer.address().port; await new Promise(resolve => portServer.close(resolve));
  const secret = randomBytes(32).toString('hex');
  const cookie = (login, sub) => {
    const payload = Buffer.from(JSON.stringify({ sub, login, exp: Math.floor(Date.now() / 1000) + 600 })).toString('base64url');
    return 'ts_session=' + payload + '.' + createHmac('sha256', secret).update(payload).digest('base64url');
  };
  const child = spawn(process.execPath, ['server/index.js'], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, env: { ...process.env,
    NODE_ENV: 'test', PORT: String(port), SESSION_SECRET: secret, SECRETS_ENCRYPTION_KEY: randomBytes(32).toString('hex'),
    APP_BASE_URL: 'https://app.example', OPENROUTER_API_KEY: '', GITHUB_ALLOWED_LOGINS: 'assistant-tests', GITHUB_ALLOWED_ORG: '',
    PREMIUM_OPEN_PATH: write('premium.json', false), USERS_STORE_PATH: write('users.json', { one: { login: 'assistant-tests' }, two: { login: 'outsider' } }),
    NEWS_ARCHIVE_PATH: write('archive.json', [{ title: 'Mirai research from saved ETL', source: 'Research', link: 'https://research.example/mirai', description: 'Mirai malware investigation.', pubDate: new Date(Date.now() - 3600000).toISOString(), score: 80, cves: [], actors: [], malware: [{ id: 'mirai', name: 'Mirai' }], iocs: {} }]),
    NEWS_STORIES_PATH: write('stories.json', []), IOC_INTELLIGENCE_PATH: ':memory:',
  } });
  child.stdout.resume(); child.stderr.resume();
  t.after(async () => {
    if (child.exitCode === null) { const stopped = once(child, 'exit'); child.kill(); await stopped; }
    assert.equal(path.dirname(directory), path.resolve(os.tmpdir()));
    fs.rmSync(directory, { recursive: true, force: true });
  });
  const base = 'http://127.0.0.1:' + port;
  let ready = false;
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw Error('Test backend exited before startup');
    try { if ((await fetch(base + '/api/integrations/telegram')).status === 401) { ready = true; break; } } catch { /* wait for the isolated local process */ }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.equal(ready, true);
  const headers = { Cookie: cookie('assistant-tests', 'one'), 'Content-Type': 'application/json' };
  assert.equal((await fetch(base + '/api/integrations/telegram', { headers: { Cookie: cookie('outsider', 'two') } })).status, 403);
  const status = await fetch(base + '/api/integrations/telegram', { headers }); assert.equal(status.status, 200);
  const metadata = await status.json(); assert.equal(metadata.configured, false); assert.equal(metadata.aiAvailable, false);
  assert.equal(status.headers.get('cache-control'), 'private, no-store'); assert.equal(metadata.token, undefined);
  assert.equal((await fetch(base + '/api/assistant/query', { method: 'POST', headers: { ...headers, Origin: 'https://other.example' }, body: JSON.stringify({ question: '/status' }) })).status, 403);
  const result = await fetch(base + '/api/assistant/query', { method: 'POST', headers, body: JSON.stringify({ question: '/buscar Mirai', aiEnabled: false }) });
  assert.equal(result.status, 200); assert.match((await result.json()).text, /Mirai research from saved ETL/);
  assert.equal((await fetch(base + '/api/integrations/telegram/connect', { method: 'POST', headers, body: JSON.stringify({ token: 'invalid' }) })).status, 400);
  assert.equal((await fetch(base + '/api/integrations/telegram/webhook/123456789', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Telegram-Bot-Api-Secret-Token': 'wrong' }, body: JSON.stringify({ update_id: 1 }) })).status, 401);
  assert.equal((await fetch(base + '/api/integrations/telegram/webhook/123456789', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ update_id: 2, message: { text: 'á'.repeat(6000) } }) })).status, 401, 'Telegram UTF-8 payloads use their bounded parser, without bypassing signature verification');
});
