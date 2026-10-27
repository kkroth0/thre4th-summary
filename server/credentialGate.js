// One allowance pool per configured provider account. Another key does not reset it.
export function retryAt(headers = {}, now = Date.now()) {
  const get = key => headers.get?.(key) ?? headers[key];
  const retry = get('retry-after');
  if (retry != null && retry !== '') {
    const numeric = Number(retry);
    const parsed = Number.isFinite(numeric) ? now + Math.max(1, numeric) * 1000 : Date.parse(retry);
    if (Number.isFinite(parsed) && parsed > now) return parsed;
  }
  const reset = Number(get('x-ratelimit-reset'));
  if (Number.isFinite(reset) && reset * 1000 > now) return reset * 1000;
  // Unknown quota window: back off conservatively rather than cycling keys.
  return now + 60_000;
}

export function createCredentialGate({ now = () => Date.now(), load = () => null, save = () => {} } = {}) {
  const state = new Map();
  const key = pool => 'credential-gate:v1:' + pool;
  const get = pool => state.get(pool) || load(key(pool)) || {};
  const set = (pool, value) => { state.set(pool, value); save(key(pool), value); };
  return {
    reserve(pool, { perMinute, perDay } = {}) {
      const at = now(), day = new Date(at).toISOString().slice(0, 10), previous = get(pool);
      const used = previous.day === day ? previous.used || 0 : 0;
      const dailyReset = Date.parse(day + 'T00:00:00Z') + 86400000;
      const reset = Math.max(previous.blockedUntil || 0, previous.nextAt || 0, perDay > 0 && used >= perDay ? dailyReset : 0);
      if (reset > at) throw Object.assign(new Error('Provider allowance is waiting for reset'), { response: { status: 429, headers: { 'retry-after': String(Math.ceil((reset - at) / 1000)) } } });
      set(pool, { ...previous, day, used: used + 1, nextAt: perMinute > 0 ? at + 60000 / perMinute : 0 });
    },
    limited(pool, headers) {
      const previous = get(pool);
      set(pool, { ...previous, blockedUntil: Math.max(previous.blockedUntil || 0, retryAt(headers, now())) });
    },
  };
}
