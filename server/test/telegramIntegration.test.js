import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import { createTelegramIntegration, TELEGRAM_LIMITS } from '../telegramIntegration.js';
const token = '123456789:' + 'x'.repeat(35);
const message = (id, text, chat = 12345, extra = {}) => ({ update_id: id, message: { chat: { id: chat, type: 'private' }, from: { id: chat, is_bot: false }, text, ...extra } });
function fixture(options = {}) {
  let at = Date.parse('2026-10-15T12:00:00Z'), secret, permitted = true, failure;
  const calls = [], answers = [];
  const deps = { publicOrigin: 'https://app.example', now: () => at, encrypt: value => Buffer.from(value).toString('base64'), decrypt: value => Buffer.from(value, 'base64').toString(),
    isAllowed: () => permitted, aiAvailable: () => true,
    answer: async (...args) => { answers.push(args); return { text: 'Evidence-backed response', aiUsed: args[2].aiEnabled && args[2].claimAi() }; },
    http: { post: async (url, body) => {
      const method = url.slice(url.lastIndexOf('/') + 1); calls.push({ method, body });
      if (method === 'sendMessage' && failure) throw failure;
      if (method === 'getMe') return { data: { ok: true, result: { id: 123456789, is_bot: true, username: 'example_test_bot' } } };
      if (method === 'getWebhookInfo') return { data: { ok: true, result: { url: '' } } };
      if (method === 'setWebhook') secret = body.secret_token;
      return { data: { ok: true, result: method === 'sendMessage' ? { message_id: calls.length } : true } };
    } }, ...options };
  const store = createTelegramIntegration(deps);
  return { store, deps, calls, answers, get secret() { return secret; }, advance: ms => { at += ms; }, permit: value => { permitted = value; }, fail: value => { failure = value; } };
}
async function connected(options = {}) {
  const f = fixture(options); await f.store.configure('alice', token);
  const code = new URL(f.store.link('alice').url).searchParams.get('start');
  assert.equal(f.store.accept('123456789', f.secret, message(1, '/start ' + code)).accepted, true);
  await f.store.tick(); return f;
}
const sends = f => f.calls.filter(call => call.method === 'sendMessage');
test('webhook setup is authenticated and configuration never returns credentials or destination IDs', async () => {
  const f = fixture();
  await assert.rejects(f.store.configure('alice', 'bad'), /inválido/); assert.equal(f.calls.length, 0);
  await f.store.configure('alice', token);
  assert.equal(f.calls.find(row => row.method === 'setWebhook').body.url, 'https://app.example/api/integrations/telegram/webhook/123456789');
  assert.equal(f.store.validWebhook('123456789', 'wrong'), false);
  assert.equal(f.store.validWebhook('123456789', f.secret), true);
  assert.ok(!JSON.stringify(f.store.status('alice')).includes(token));
  await assert.rejects(f.store.configure('bob', token), /outra conta/);
  assert.equal(f.store.status('bob').configured, false); f.store.close();
});
test('linking requires a fresh single-use code and a private human conversation', async () => {
  const f = fixture(); await f.store.configure('alice', token);
  assert.equal(f.store.accept('123456789', 'wrong', message(1, 'hello')).authorized, false);
  assert.equal(f.store.accept('123456789', f.secret, message(1, 'hello')).accepted, false);
  const code = new URL(f.store.link('alice').url).searchParams.get('start');
  assert.equal(f.store.accept('123456789', f.secret, message(1, '/start ' + code, 12345, { chat: { id: 12345, type: 'group' } })).accepted, false);
  assert.equal(f.store.accept('123456789', f.secret, message(1, '/start ' + code)).accepted, true);
  assert.equal(f.store.accept('123456789', f.secret, message(2, '/start ' + code)).accepted, false);
  assert.equal(f.store.accept('123456789', f.secret, message(3, '/status', 99999)).accepted, false);
  assert.equal(f.store.accept('123456789', f.secret, message(4, '/status', 12345, { from: { id: 99999 } })).accepted, false);
  assert.equal(f.store.status('alice').connected, true); f.store.close();
});
test('expired link codes cannot connect a conversation', async () => {
  const f = fixture(); await f.store.configure('alice', token);
  const code = new URL(f.store.link('alice').url).searchParams.get('start'); f.advance(11 * 60000);
  assert.equal(f.store.accept('123456789', f.secret, message(1, '/start ' + code)).accepted, false); f.store.close();
});
test('local development stays available without HTTPS and refuses to expose an insecure webhook', async () => {
  const f = fixture({ publicOrigin: 'http://localhost:8080' });
  assert.equal(f.store.status('alice').webhookAvailable, false);
  await assert.rejects(f.store.configure('alice', token), /HTTPS/);
  assert.equal(f.calls.length, 0);
  assert.match((await f.store.preview('alice', '/status', false)).text, /response/); f.store.close();
});
test('an unrelated existing webhook is never overwritten', async () => {
  let writes = 0;
  const f = fixture({ http: { post: async (url) => {
    if (url.endsWith('/getMe')) return { data: { ok: true, result: { id: 123456789, is_bot: true, username: 'example_test_bot' } } };
    if (url.endsWith('/getWebhookInfo')) return { data: { ok: true, result: { url: 'https://other.example/hook' } } };
    writes++; return { data: { ok: true, result: true } };
  } } });
  await assert.rejects(f.store.configure('alice', token), /outra integração/);
  assert.equal(writes, 0); assert.equal(f.store.status('alice').configured, false); f.store.close();
});
test('webhook duplicate updates and simultaneous ticks send exactly one reply', async () => {
  const f = await connected();
  f.store.accept('123456789', f.secret, message(2, '/briefing'));
  assert.equal(f.store.accept('123456789', f.secret, message(2, '/briefing')).duplicate, true);
  await Promise.all([f.store.tick(), f.store.tick(), f.store.tick()]);
  assert.equal(sends(f).length, 2); assert.equal(f.answers.length, 2);
  assert.equal(f.store.status('alice').deliveries.filter(row => row.state === 'sent').length, 2); f.store.close();
});
test('revoked access cancels queued work before reading private knowledge or sending', async () => {
  const f = await connected(); f.store.accept('123456789', f.secret, message(2, '/ioc 8.8.8.8')); f.permit(false);
  await f.store.tick(); assert.equal(sends(f).length, 1); assert.equal(f.answers.length, 1);
  assert.equal(f.store.status('alice').deliveries[0].state, 'cancelled'); f.store.close();
});
test('daily briefing is opt-in, waits until the next selected hour and persists daily deduplication', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'telegram-daily-')), filePath = path.join(directory, 'data.sqlite');
  const f = await connected({ filePath });
  await f.store.tick(); assert.equal(sends(f).length, 1);
  f.store.preferences('alice', { dailyEnabled: true, dailyHour: 8, aiEnabled: false });
  f.advance(61000); await f.store.tick(); assert.equal(sends(f).length, 1, 'do not send past the selected time on activation day');
  f.advance(86400000); await f.store.tick(); assert.equal(sends(f).length, 2);
  f.advance(61000); await f.store.tick(); assert.equal(sends(f).length, 2);
  f.store.close();
  const restarted = createTelegramIntegration(f.deps); await restarted.tick(); assert.equal(sends(f).length, 2);
  restarted.close(); fs.rmSync(directory, { recursive: true, force: true });
});
test('known Telegram 429 retries only the saved reply and respects retry_after', async () => {
  const f = await connected();
  f.store.accept('123456789', f.secret, message(2, '/briefing'));
  f.fail({ response: { status: 429, data: { error_code: 429, parameters: { retry_after: 120 } } } });
  await f.store.tick(); assert.equal(f.store.status('alice').deliveries[0].state, 'queued');
  f.fail(null); f.advance(119000); await f.store.tick(); assert.equal(sends(f).length, 2);
  f.advance(1001); await f.store.tick(); assert.equal(sends(f).length, 3); assert.equal(f.answers.length, 2);
  assert.equal(f.store.status('alice').deliveries[0].state, 'sent'); f.store.close();
});
test('ambiguous delivery outcomes are never silently resent, including after restart', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'telegram-uncertain-')), filePath = path.join(directory, 'data.sqlite');
  const f = await connected({ filePath }); f.store.accept('123456789', f.secret, message(2, '/briefing'));
  f.fail(Error('timeout')); await f.store.tick();
  assert.equal(f.store.status('alice').deliveries[0].state, 'uncertain'); f.store.close();
  const restarted = createTelegramIntegration(f.deps); f.fail(null); await restarted.tick(); assert.equal(sends(f).length, 2);
  restarted.close(); fs.rmSync(directory, { recursive: true, force: true });
});
test('restart marks an interrupted sending job uncertain and safely resumes unsent processing', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'telegram-restart-')), filePath = path.join(directory, 'data.sqlite');
  const f = await connected({ filePath }); f.store.accept('123456789', f.secret, message(2, '/status')); f.store.accept('123456789', f.secret, message(3, '/briefing')); f.store.close();
  const db = new Database(filePath); db.prepare("UPDATE telegram_jobs SET state='sending' WHERE id=?").run('update:123456789:2'); db.prepare("UPDATE telegram_jobs SET state='processing' WHERE id=?").run('update:123456789:3'); db.close();
  const restarted = createTelegramIntegration(f.deps); await restarted.tick();
  assert.equal(sends(f).length, 2); assert.equal(restarted.status('alice').deliveries.filter(row => row.state === 'uncertain').length, 1);
  restarted.close(); fs.rmSync(directory, { recursive: true, force: true });
});
test('persisted AI budget and per-owner query limits bound external calls', async () => {
  const f = await connected();
  for (let i = 0; i < TELEGRAM_LIMITS.dailyAi + 3; i++) await f.store.preview('alice', 'question ' + i, true);
  assert.equal(f.store.status('alice').aiUsedToday, TELEGRAM_LIMITS.dailyAi);
  assert.equal(f.store.status('bob').aiUsedToday, 0);
  for (let i = 2; i <= TELEGRAM_LIMITS.hourlyQueries; i++) assert.equal(f.store.accept('123456789', f.secret, message(i, '/status')).accepted, true);
  assert.equal(f.store.accept('123456789', f.secret, message(99, '/status')).limited, true); f.store.close();
});
test('disconnect while an answer is being prepared prevents any later delivery', async () => {
  let release, started;
  const waiting = new Promise(resolve => { started = resolve; });
  const f = await connected({ answer: async (owner, question) => {
    if (question === '/briefing') { started(); await new Promise(resolve => { release = resolve; }); }
    return { text: 'prepared' };
  } });
  f.store.accept('123456789', f.secret, message(2, '/briefing'));
  const tick = f.store.tick(); await waiting; await f.store.disconnect('alice'); release(); await tick;
  assert.equal(sends(f).length, 1); assert.equal(f.store.status('alice').configured, false); f.store.close();
});
