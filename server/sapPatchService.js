import fs from 'node:fs';
import path from 'node:path';
import axios from 'axios';
import { latestPatchMonth, monthUrl, parseSapNotes, sortNotes, summarize } from './sapPatch.js';

export function createSapPatchService({ http = axios, now = () => Date.now(), filePath } = {}) {
    const cache = new Map(), flights = new Map();
    if (filePath) try { if (fs.statSync(filePath).size < 8 * 1024 * 1024) for (const [key, entry] of JSON.parse(fs.readFileSync(filePath, 'utf8')).entries || []) if (entry.data?.notes && /^20\d{2}-\d\d$|^latest$/.test(key)) cache.set(key, entry); } catch { /* first start */ }
    const persist = () => { if (filePath) try { fs.mkdirSync(path.dirname(filePath), { recursive: true }); fs.writeFileSync(filePath + '.tmp', JSON.stringify({ entries: [...cache] }), { mode: 0o600 }); fs.renameSync(filePath + '.tmp', filePath); } catch { /* usable in-memory snapshot */ } };
    async function query(month) {
        const parts = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Fortaleza', year: 'numeric', month: '2-digit' }).formatToParts(new Date(now()));
        const currentMonth = parts.find(p => p.type === 'year').value + '-' + parts.find(p => p.type === 'month').value;
        if (month !== undefined && (typeof month !== 'string' || !/^20\d{2}-(0[1-9]|1[0-2])$/.test(month) || month < '2018-01' || month > currentMonth)) { const error = Error('Mês inválido. Use AAAA-MM entre 2018 e o mês atual.'); error.status = 400; throw error; }
        const key = month || 'latest', old = cache.get(key);
        if (old && old.until > now()) return old.data;
        if (flights.has(key)) return flights.get(key);
        const flight = (async () => {
            const primary = latestPatchMonth(new Date(now())), previous = new Date(Date.UTC(primary.year, primary.month - 1, 15));
            const urls = month ? [monthUrl(Number(month.slice(0, 4)), Number(month.slice(5)) - 1)] : [primary.url, monthUrl(previous.getUTCFullYear(), previous.getUTCMonth())];
            try {
                let lastError;
                for (const url of urls) {
                    try {
                        const response = await http.get(url, { timeout: 15000, maxRedirects: 3, maxContentLength: 4 * 1024 * 1024, responseType: 'text', headers: { 'User-Agent': 'Mozilla/5.0', Accept: 'text/html,application/xhtml+xml' } });
                        const parsed = parseSapNotes(response.data);
                        if (!parsed.notes.length || month && parsed.releaseDate && !parsed.releaseDate.startsWith(month)) throw Error('A SAP ainda não disponibilizou notas válidas para este mês.');
                        const notes = sortNotes(parsed.notes), data = { url, releaseDate: parsed.releaseDate, notes, summary: summarize(notes), stale: false };
                        cache.set(key, { data, until: now() + 86400000 }); if (cache.size > 60) cache.delete(cache.keys().next().value); persist(); return data;
                    } catch (error) { lastError = error; if (month || error.response?.status && error.response.status !== 404) break; }
                }
                throw lastError || Error('Não foi possível carregar o SAP Patch Day.');
            } catch (error) {
                if (old) { const data = { ...old.data, stale: true }; cache.set(key, { data, until: now() + 60000 }); return data; }
                const failure = Error(error.response?.status === 404 ? 'A SAP ainda não disponibilizou notas para este mês.' : 'Não foi possível consultar as notas SAP deste mês.'); failure.status = error.response?.status === 404 ? 404 : 502; throw failure;
            }
        })().finally(() => flights.delete(key));
        flights.set(key, flight); return flight;
    }
    return { query };
}
