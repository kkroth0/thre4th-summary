import { createHash } from 'node:crypto';
import { retryAt } from './credentialGate.js';

export const POOL_PROVIDERS = new Set(['virustotal', 'abuseipdb', 'otx', 'abuse_ch', 'threatfox', 'urlhaus', 'malwarebazaar']);
export const credentialId = value => createHash('sha256').update(value).digest('hex').slice(0, 24);

// The stored plaintext is itself encrypted by the existing secret store.
// Legacy single-key values remain valid and migrate only when the user edits them.
export function decodeCredentials(value) {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    if (parsed?.version === 1 && Array.isArray(parsed.keys)) return [...new Set(parsed.keys.filter(key => typeof key === 'string' && key.length >= 8 && key.length <= 400))];
  } catch { /* legacy plain key */ }
  return [value];
}

export function parseCredentialInput(value) {
  const keys = Array.isArray(value) ? value : typeof value === 'string' ? value.split(/[\r\n,]+/) : [];
  if (!keys.length || keys.length > 50 || keys.some(key => typeof key !== 'string' || key.trim().length < 8 || key.trim().length > 400 || /\s/.test(key.trim()))) throw new Error('Informe até 50 chaves válidas, uma por linha.');
  return [...new Set(keys.map(key => key.trim()))];
}

export function createCredentialPool({ now = Date.now, load = () => null, save = () => {} } = {}) {
  const flights = new Set(), cursors = new Map();
  const stateKey = (provider, key) => `credential-pool:v1:${provider}:${credentialId(key)}`;
  const state = (provider, key) => load(stateKey(provider, key)) || {};
  const put = (provider, key, value) => save(stateKey(provider, key), value);
  const availableAt = (value, limits, at) => {
    const day = new Date(at).toISOString().slice(0, 10);
    return Math.max(value.blockedUntil || 0, value.nextAt || 0, value.invalidUntil || 0,
      limits.perDay > 0 && value.day === day && value.used >= limits.perDay ? Date.parse(day + 'T00:00:00Z') + 86400000 : 0);
  };
  const waiting = at => Object.assign(new Error('Todas as credenciais estão ocupadas ou aguardando renovação de cota.'), {
    response: { status: 429, headers: { 'retry-after': String(Math.max(1, Math.ceil((at - now()) / 1000))) } }, retryAt: at,
  });
  return {
    describe(provider, keys, limits = {}) {
      const at = now();
      return keys.map((key, index) => {
        const value = state(provider, key), until = availableAt(value, limits, at);
        const day = new Date(at).toISOString().slice(0, 10);
        const waitingReason = value.invalidUntil > at ? 'authentication' : value.blockedUntil > at ? 'provider' : limits.perDay > 0 && value.day === day && value.used >= limits.perDay ? 'local_daily_limit' : value.nextAt > at ? 'pacing' : flights.has(stateKey(provider, key)) ? 'in_flight' : null;
        return { id: credentialId(key), label: `Chave ${index + 1}`, status: value.invalidUntil > at ? 'authentication_error' : until > at ? 'cooldown' : flights.has(stateKey(provider, key)) ? 'busy' : 'available', waitingReason, retryAt: until > at ? until : null, usedToday: value.day === day ? value.used || 0 : 0, lastStatus: value.lastStatus || null };
      });
    },
    async run(provider, keys, request, limits = {}) {
      keys = [...new Set(keys.filter(Boolean))];
      if (!keys.length) throw Object.assign(new Error('API Key missing'), { noKey: true });
      const shared = load(`credential-pool:shared:${provider}`) || 0;
      if (shared > now()) throw waiting(shared);
      const start = cursors.get(provider) || 0;
      let next = Infinity, lastAuth;
      for (let offset = 0; offset < keys.length; offset++) {
        const index = (start + offset) % keys.length, key = keys[index], id = stateKey(provider, key);
        const at = now(), previous = state(provider, key), until = availableAt(previous, limits, at);
        if (previous.invalidUntil > at) { lastAuth = true; continue; }
        if (until > at || flights.has(id)) { next = Math.min(next, until > at ? until : at + 1000); continue; }
        flights.add(id);
        cursors.set(provider, (index + 1) % keys.length);
        const day = new Date(at).toISOString().slice(0, 10);
        put(provider, key, { ...previous, day, used: (previous.day === day ? previous.used || 0 : 0) + 1, nextAt: limits.perMinute > 0 ? at + 60000 / limits.perMinute : 0 });
        try {
          const response = await request(key);
          const headers = response?.headers || {};
          const remaining = headers.get?.('x-ratelimit-remaining') ?? headers['x-ratelimit-remaining'];
          const daily = headers.get?.('x-daily-requests-left') ?? headers['x-daily-requests-left'];
          const depleted = (remaining != null && String(remaining) === '0') || (daily != null && String(daily) === '0');
          put(provider, key, { ...state(provider, key), lastStatus: response?.status || 200, invalidUntil: 0, ...(depleted ? { blockedUntil: retryAt(headers, now()) } : {}) });
          return response;
        } catch (error) {
          const status = error.response?.status;
          if (status === 429) {
            const headers = error.response?.headers || {}, until = retryAt(headers, now());
            put(provider, key, { ...state(provider, key), blockedUntil: until, lastStatus: 429 });
            const scope = headers.get?.('x-ratelimit-scope') ?? headers['x-ratelimit-scope'];
            if (['ip', 'global', 'service'].includes(String(scope).toLowerCase())) { save(`credential-pool:shared:${provider}`, until); throw waiting(until); }
            next = Math.min(next, until);
            continue;
          }
          if (status === 401 || status === 403) {
            put(provider, key, { ...state(provider, key), invalidUntil: now() + 10 * 60000, lastStatus: status });
            lastAuth = error;
            continue;
          }
          put(provider, key, { ...state(provider, key), lastStatus: status || null });
          throw error;
        } finally { flights.delete(id); }
      }
      if (Number.isFinite(next)) throw waiting(next);
      if (lastAuth) throw Object.assign(new Error('As credenciais foram recusadas pelo provedor.'), { code: 'PROVIDER_AUTH_FAILED', response: { status: 502 } });
      throw waiting(now() + 60000);
    },
  };
}
