import fs from 'node:fs/promises';
import path from 'node:path';
import { normalizeVictim } from './ransomwareLive.js';

const DAY = 86400000;
export const ULTRAPAR_RANSOMWARE_SECTORS = ['Financial Services', 'Transportation', 'Manufacturing', 'Energy & Utilities'];
export function weeklyProfile(profile) {
  if (!profile) return null;
  const sectors = profile.ransomwareSectors || (/ultrapar|grupo\s+ultra/i.test(profile.name || '') ? ULTRAPAR_RANSOMWARE_SECTORS : []);
  return { ...profile, ransomwareSectors: [...new Set(sectors)] };
}
export function historyMonths(range, now = Date.now()) {
  const first = new Date(Date.parse(range.from) - 11 * 7 * DAY);
  const last = new Date(Math.min(Date.parse(range.to) - 1, now));
  const months = [];
  for (let d = new Date(Date.UTC(first.getUTCFullYear(), first.getUTCMonth(), 1)); d <= last; d.setUTCMonth(d.getUTCMonth() + 1)) months.push(d.toISOString().slice(0, 7));
  return months;
}
// Only public source observations are cached here. Private reports and choices
// remain in the account-scoped weekly store. A truncated month is never cached.
export function createWeeklyRansomware({ http, apiKey, filePath, now = () => Date.now() }) {
  let cache = {}, loading, saving = Promise.resolve();
  const flights = new Map();
  async function load() {
    loading ||= (async () => {
      if (filePath) try { cache = JSON.parse(await fs.readFile(filePath, 'utf8')); } catch { /* first collection */ }
    })();
    await loading;
  }
  async function month(key) {
    await load();
    const saved = cache[key];
    const ttl = key === new Date(now()).toISOString().slice(0, 7) ? 60 * 60000 : DAY;
    if (saved && now() - saved.at < ttl) return saved;
    if (flights.has(key)) return flights.get(key);
    const work = (async () => {
      const response = await http.get('https://api-pro.ransomware.live/victims/', {
        headers: { 'X-API-KEY': apiKey }, params: { year: Number(key.slice(0, 4)), month: Number(key.slice(5)), date: 'discovered' },
        timeout: 30000, maxRedirects: 0, maxContentLength: 32 * 1024 * 1024,
      });
      const data = response.data;
      if (!Array.isArray(data?.victims) || !Number.isInteger(data.count) || data.victims.length !== data.count) throw Error('Incomplete ransomware month');
      const result = { at: now(), victims: data.victims.map(row => normalizeVictim(row, 'ransomware.live Pro')) };
      cache[key] = result;
      for (const old of Object.keys(cache).sort().slice(0, -6)) delete cache[old];
      if (filePath) {
        saving = saving.catch(() => {}).then(async () => {
          const tmp = filePath + '.tmp';
          await fs.mkdir(path.dirname(filePath), { recursive: true });
          await fs.writeFile(tmp, JSON.stringify(cache), { mode: 0o600 });
          await fs.rename(tmp, filePath);
        });
        await saving;
      }
      return result;
    })().finally(() => flights.delete(key));
    flights.set(key, work);
    return work;
  }
  return { async get(range) {
    if (!apiKey) return { victims: [], coverage: { status: 'partial', message: 'Histórico mensal requer a chave Pro. O feed recente não garante a semana completa.' } };
    const months = historyMonths(range, now()), victims = [], missing = [];
    for (const key of months) {
      try { victims.push(...(await month(key)).victims); }
      catch { missing.push(key); if (cache[key]) victims.push(...cache[key].victims); }
    }
    return { victims, coverage: { status: missing.length ? 'partial' : 'ready', checkedAt: new Date(now()).toISOString(), months, missingMonths: missing, dateBasis: 'discovered', ...(missing.length ? { message: 'Histórico parcial: meses indisponíveis nesta atualização.' } : {}) } };
  } };
}
