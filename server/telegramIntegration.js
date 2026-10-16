import Database from 'better-sqlite3';
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';

const digest = value => createHash('sha256').update(String(value || '')).digest('hex');
const equal = (value, hash) => hash && timingSafeEqual(Buffer.from(digest(value)), Buffer.from(hash));
const stamp = time => new Date(time).toISOString();
const dateKey = time => new Intl.DateTimeFormat('sv-SE', { timeZone: 'America/Fortaleza' }).format(new Date(time));
export const TELEGRAM_LIMITS = { hourlyQueries: 20, dailyAi: 30, linkMinutes: 10 };

// No polling or provider collection per question. A verified webhook durably
// queues a job; the worker only reads the existing local intelligence.
export function createTelegramIntegration({ filePath = ':memory:', http, encrypt, decrypt, publicOrigin, answer, isAllowed = () => true, aiAvailable = () => false, now = () => Date.now() }) {
    let origin;
    try { origin = new URL(publicOrigin); } catch { /* a local-only install can still query saved evidence */ }
    const webhookAvailable = !!origin && origin.protocol === 'https:' && !origin.username && !origin.password && !origin.search && !origin.hash && origin.pathname === '/';
    const db = new Database(filePath); db.pragma('journal_mode = WAL'); db.pragma('busy_timeout = 5000');
    db.exec('CREATE TABLE IF NOT EXISTS telegram_connections(owner TEXT PRIMARY KEY,bot_id TEXT NOT NULL UNIQUE,username TEXT NOT NULL,token_enc TEXT NOT NULL,secret_hash TEXT NOT NULL,chat_id TEXT,link_hash TEXT,link_expires INTEGER,ai_enabled INTEGER NOT NULL DEFAULT 0,daily_enabled INTEGER NOT NULL DEFAULT 0,daily_hour INTEGER NOT NULL DEFAULT 8,access_until INTEGER NOT NULL DEFAULT 0,updated INTEGER NOT NULL);'
        + 'CREATE TABLE IF NOT EXISTS telegram_jobs(id TEXT PRIMARY KEY,owner TEXT NOT NULL,bot_id TEXT NOT NULL,chat_id TEXT NOT NULL,question TEXT NOT NULL,state TEXT NOT NULL,created INTEGER NOT NULL,next_at INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,reply TEXT,ai_used INTEGER NOT NULL DEFAULT 0,message_id TEXT,error TEXT);'
        + 'CREATE INDEX IF NOT EXISTS telegram_due ON telegram_jobs(state,next_at);'
        + 'CREATE INDEX IF NOT EXISTS telegram_owner_history ON telegram_jobs(owner,created);'
        + 'CREATE TABLE IF NOT EXISTS telegram_ai_usage(owner TEXT NOT NULL,day TEXT NOT NULL,n INTEGER NOT NULL,PRIMARY KEY(owner,day));');
    // A crash before sending is safe to recompute. After sending starts the
    // outcome can be ambiguous; never silently resend and duplicate a briefing.
    db.prepare("UPDATE telegram_jobs SET state='queued' WHERE state='processing'").run();
    db.prepare("UPDATE telegram_jobs SET state='uncertain',error='delivery_unconfirmed' WHERE state='sending'").run();
    const connection = owner => db.prepare('SELECT * FROM telegram_connections WHERE owner=?').get(String(owner));
    const allowed = row => row && isAllowed(row.owner, row.access_until);
    let active = null, scheduleAt = -Infinity;
    const setupLocks = new Set();
    async function call(token, method, body = {}) {
        try {
            const response = await http.post('https://api.telegram.org/bot' + token + '/' + method, body, { timeout: 10000, maxContentLength: 128000, maxRedirects: 0 });
            if (!response.data?.ok) {
                const failure = Error('Telegram rejected request'); failure.status = response.data?.error_code || 502; failure.retryAfter = response.data?.parameters?.retry_after; throw failure;
            }
            return response.data.result;
        } catch (error) {
            const failure = Error('Não foi possível concluir a operação no Telegram.');
            failure.status = error.status || error.response?.data?.error_code || error.response?.status || 502;
            failure.retryAfter = error.retryAfter || error.response?.data?.parameters?.retry_after;
            failure.ambiguous = !error.response && !error.status || failure.status >= 500;
            throw failure;
        }
    }
    function status(owner) {
        const row = connection(owner), day = dateKey(now());
        return { configured: !!row, connected: !!row?.chat_id, username: row?.username || null, aiEnabled: !!row?.ai_enabled, aiAvailable: !!aiAvailable(), webhookAvailable,
            dailyEnabled: !!row?.daily_enabled, dailyHour: row?.daily_hour ?? 8, timeZone: 'America/Fortaleza', accessAllowed: row ? !!allowed(row) : true,
            limits: TELEGRAM_LIMITS, aiUsedToday: db.prepare('SELECT n FROM telegram_ai_usage WHERE owner=? AND day=?').get(String(owner), day)?.n || 0,
            deliveries: db.prepare('SELECT state,created,ai_used aiUsed,message_id messageId,error FROM telegram_jobs WHERE owner=? ORDER BY created DESC,rowid DESC LIMIT 8').all(String(owner)) };
    }
    async function configure(owner, token, accessUntil = 0) {
        owner = String(owner); token = String(token || '').trim();
        if (!webhookAvailable) throw Error('Configure APP_BASE_URL com a origem HTTPS pública da plataforma.');
        if (!/^\d{5,16}:[A-Za-z0-9_-]{20,100}$/.test(token)) throw Error('Token do BotFather inválido.');
        if (setupLocks.has(owner)) throw Error('Configuração já está em andamento.');
        setupLocks.add(owner);
        let botLock;
        try {
            const me = await call(token, 'getMe');
            if (!me?.is_bot || !Number.isSafeInteger(me.id) || !/^[A-Za-z0-9_]{5,64}$/.test(me.username || '')) throw Error('Bot inválido.');
            const botId = String(me.id), existing = db.prepare('SELECT owner FROM telegram_connections WHERE bot_id=?').get(botId);
            if (existing && existing.owner !== owner) throw Error('Este bot já está vinculado a outra conta.');
            botLock = 'bot:' + botId;
            if (setupLocks.has(botLock)) { botLock = null; throw Error('Este bot já está sendo configurado.'); }
            setupLocks.add(botLock);
            const webhookUrl = origin.origin + '/api/integrations/telegram/webhook/' + botId;
            const info = await call(token, 'getWebhookInfo');
            if (info?.url && info.url !== webhookUrl) throw Error('Este bot já atende outra integração. Crie um bot dedicado no BotFather.');
            const secret = randomBytes(32).toString('hex'), tokenEnc = encrypt(token), old = connection(owner);
            await call(token, 'setWebhook', { url: webhookUrl, secret_token: secret, allowed_updates: ['message'], max_connections: 2 });
            db.transaction(() => {
                db.prepare("UPDATE telegram_jobs SET state='cancelled',error='connection_changed' WHERE owner=? AND state IN ('queued','processing')").run(owner);
                db.prepare('DELETE FROM telegram_connections WHERE owner=?').run(owner);
                db.prepare('INSERT INTO telegram_connections(owner,bot_id,username,token_enc,secret_hash,chat_id,ai_enabled,daily_enabled,daily_hour,access_until,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
                    .run(owner, botId, me.username, tokenEnc, digest(secret), old?.bot_id === botId ? old.chat_id : null, old?.ai_enabled || 0, 0, old?.daily_hour ?? 8, accessUntil, now());
            })();
            return status(owner);
        } finally { setupLocks.delete(owner); if (botLock) setupLocks.delete(botLock); }
    }
    function link(owner) {
        const row = connection(owner); if (!row) throw Error('Configure o bot primeiro.');
        const code = randomBytes(24).toString('base64url'), expires = now() + TELEGRAM_LIMITS.linkMinutes * 60000;
        db.prepare('UPDATE telegram_connections SET link_hash=?,link_expires=? WHERE owner=?').run(digest(code), expires, String(owner));
        return { url: 'https://t.me/' + row.username + '?start=' + code, expiresAt: stamp(expires) };
    }
    function preferences(owner, value) {
        if (!connection(owner)) throw Error('Configure o bot primeiro.');
        if (typeof value.aiEnabled !== 'boolean' || typeof value.dailyEnabled !== 'boolean' || !Number.isInteger(value.dailyHour) || value.dailyHour < 0 || value.dailyHour > 23) throw Error('Configuração inválida.');
        db.prepare('UPDATE telegram_connections SET ai_enabled=?,daily_enabled=?,daily_hour=?,updated=? WHERE owner=?')
            .run(+value.aiEnabled, +value.dailyEnabled, value.dailyHour, now(), String(owner));
        return status(owner);
    }
    function authorize(owner, until) { const expires = Number(until) || 0; db.prepare('UPDATE telegram_connections SET access_until=? WHERE owner=? AND access_until<>?').run(expires, String(owner), expires); }
    function validWebhook(botId, secret) {
        if (!/^\d{5,16}$/.test(String(botId)) || typeof secret !== 'string' || secret.length > 256) return false;
        const row = db.prepare('SELECT secret_hash FROM telegram_connections WHERE bot_id=?').get(String(botId));
        return !!row && !!equal(secret, row.secret_hash);
    }
    const accept = db.transaction((botId, secret, update) => {
        if (!validWebhook(botId, secret)) return { authorized: false, accepted: false };
        const row = db.prepare('SELECT * FROM telegram_connections WHERE bot_id=?').get(String(botId)), message = update?.message;
        if (!allowed(row) || !Number.isSafeInteger(update?.update_id) || update.update_id < 0 || message?.chat?.type !== 'private'
            || !Number.isSafeInteger(message.chat.id) || message.chat.id <= 0 || message.from?.id !== message.chat.id || message.from?.is_bot || typeof message.text !== 'string') return { authorized: true, accepted: false };
        const id = 'update:' + botId + ':' + update.update_id;
        if (db.prepare('SELECT 1 FROM telegram_jobs WHERE id=?').get(id)) return { authorized: true, accepted: true, duplicate: true };
        const start = message.text.match(/^\/start(?:@\w+)?\s+([A-Za-z0-9_-]+)$/);
        if (start) {
            if (!row.link_hash || row.link_expires <= now() || !equal(start[1], row.link_hash)) return { authorized: true, accepted: false };
            db.prepare("UPDATE telegram_jobs SET state='cancelled',error='chat_changed' WHERE owner=? AND state IN ('queued','processing')").run(row.owner);
            db.prepare('UPDATE telegram_connections SET chat_id=?,link_hash=NULL,link_expires=NULL,updated=? WHERE owner=?').run(String(message.chat.id), now(), row.owner);
            row.chat_id = String(message.chat.id);
        }
        if (row.chat_id !== String(message.chat.id)) return { authorized: true, accepted: false };
        const recent = db.prepare("SELECT COUNT(*) n FROM telegram_jobs WHERE owner=? AND created>? AND id LIKE 'update:%'").get(row.owner, now() - 3600000).n;
        if (recent >= TELEGRAM_LIMITS.hourlyQueries) return { authorized: true, accepted: false, limited: true };
        db.prepare("INSERT INTO telegram_jobs(id,owner,bot_id,chat_id,question,state,created,next_at) VALUES(?,?,?,?,?,'queued',?,?)")
            .run(id, row.owner, String(botId), row.chat_id, start ? '/ajuda' : message.text.slice(0, 500), now(), now());
        return { authorized: true, accepted: true };
    });
    function schedule() {
        if (now() - scheduleAt < 60000) return;
        scheduleAt = now();
        const day = dateKey(now()), hour = Number(new Intl.DateTimeFormat('en-GB', { timeZone: 'America/Fortaleza', hour: '2-digit', hourCycle: 'h23' }).format(new Date(now())));
        for (const row of db.prepare('SELECT * FROM telegram_connections WHERE daily_enabled=1 AND chat_id IS NOT NULL').all()) {
            if (!allowed(row) || hour < row.daily_hour) continue;
            const dueAt = Date.parse(day + 'T' + String(row.daily_hour).padStart(2, '0') + ':00:00-03:00');
            if (dueAt < row.updated) continue;
            db.prepare("INSERT OR IGNORE INTO telegram_jobs(id,owner,bot_id,chat_id,question,state,created,next_at) VALUES(?,?,?,?,?,'queued',?,?)")
                .run('daily:' + row.owner + ':' + day, row.owner, row.bot_id, row.chat_id, '/briefing', now(), now());
        }
        // Keep delivery deduplication well beyond Telegram's retry window.
        db.prepare("DELETE FROM telegram_jobs WHERE created<? AND state NOT IN ('queued','processing','sending')").run(now() - 90 * 86400000);
        db.prepare('DELETE FROM telegram_ai_usage WHERE day<?').run(dateKey(now() - 90 * 86400000));
    }
    const claimAi = db.transaction(owner => {
        const day = dateKey(now()), used = db.prepare('SELECT n FROM telegram_ai_usage WHERE owner=? AND day=?').get(owner, day)?.n || 0;
        if (used >= TELEGRAM_LIMITS.dailyAi || !aiAvailable()) return false;
        db.prepare('INSERT INTO telegram_ai_usage VALUES(?,?,1) ON CONFLICT(owner,day) DO UPDATE SET n=n+1').run(owner, day); return true;
    });
    async function processOne() {
        schedule();
        const job = db.prepare("SELECT * FROM telegram_jobs WHERE state='queued' AND next_at<=? ORDER BY created,rowid LIMIT 1").get(now());
        if (!job) return;
        let row = connection(job.owner);
        if (!allowed(row) || row.bot_id !== job.bot_id || row.chat_id !== job.chat_id || job.id.startsWith('daily:') && (!row.daily_enabled || job.id !== 'daily:' + job.owner + ':' + dateKey(now()))) {
            db.prepare("UPDATE telegram_jobs SET state='cancelled',error='access_or_connection_changed' WHERE id=?").run(job.id); return;
        }
        db.prepare("UPDATE telegram_jobs SET state='processing' WHERE id=?").run(job.id);
        try {
            if (!job.reply) {
                const result = await answer(job.owner, job.question, { aiEnabled: !!row.ai_enabled, claimAi: () => claimAi(job.owner) });
                job.reply = String(result.text || 'Resposta indisponível.').slice(0, 3900);
                db.prepare('UPDATE telegram_jobs SET reply=?,ai_used=? WHERE id=?').run(job.reply, +!!result.aiUsed, job.id);
            }
            row = connection(job.owner);
            const state = db.prepare('SELECT state FROM telegram_jobs WHERE id=?').get(job.id)?.state;
            if (!allowed(row) || row.bot_id !== job.bot_id || row.chat_id !== job.chat_id || state !== 'processing' || job.id.startsWith('daily:') && !row.daily_enabled) {
                db.prepare("UPDATE telegram_jobs SET state='cancelled',error='access_or_connection_changed' WHERE id=?").run(job.id); return;
            }
            db.prepare("UPDATE telegram_jobs SET state='sending',attempts=attempts+1 WHERE id=?").run(job.id);
            const sent = await call(decrypt(row.token_enc), 'sendMessage', { chat_id: row.chat_id, text: job.reply, link_preview_options: { is_disabled: true }, protect_content: true });
            if (!sent?.message_id) throw Object.assign(Error('Delivery unconfirmed'), { ambiguous: true });
            db.prepare("UPDATE telegram_jobs SET state='sent',message_id=?,error=NULL WHERE id=?").run(String(sent.message_id), job.id);
        } catch (error) {
            const sending = db.prepare('SELECT state FROM telegram_jobs WHERE id=?').get(job.id)?.state === 'sending';
            const retry = error.status === 429 && job.attempts < 2;
            db.prepare('UPDATE telegram_jobs SET state=?,next_at=?,error=? WHERE id=?')
                .run(retry ? 'queued' : sending && error.ambiguous ? 'uncertain' : 'failed',
                    now() + Math.max(1000, Math.min(3600000, Number(error.retryAfter || 60) * 1000)),
                    retry ? 'telegram_rate_limit' : sending && error.ambiguous ? 'delivery_unconfirmed' : 'request_failed', job.id);
        }
    }
    function tick() {
        if (active) return active;
        active = processOne().finally(() => { active = null; }); return active;
    }
    async function disconnect(owner) {
        const row = connection(owner);
        if (row) {
            // Revoke locally first; queued/in-flight computation may no longer send.
            db.transaction(() => {
                db.prepare('DELETE FROM telegram_connections WHERE owner=?').run(String(owner));
                db.prepare("UPDATE telegram_jobs SET state='cancelled',error='disconnected' WHERE owner=? AND state IN ('queued','processing')").run(String(owner));
            })();
            try {
                const token = decrypt(row.token_enc), info = await call(token, 'getWebhookInfo');
                if (info?.url === origin?.origin + '/api/integrations/telegram/webhook/' + row.bot_id) await call(token, 'deleteWebhook', { drop_pending_updates: false });
            } catch { /* local revocation is authoritative */ }
        }
        return status(owner);
    }
    return { configure, link, status, preferences, authorize, validWebhook, accept, tick, disconnect,
        preview: (owner, question, aiEnabled) => answer(String(owner), String(question || '').slice(0, 500), { aiEnabled, claimAi: () => claimAi(String(owner)) }),
        close: () => db.close() };
}
