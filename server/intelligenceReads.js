import { Worker } from 'node:worker_threads';

export function optimizeIntelligenceReads(filePath) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./intelligenceOptimizeWorker.js', import.meta.url), { workerData: { filePath }, execArgv: [] });
    worker.once('message', data => data.ok ? resolve() : reject(Error('Inventory index preparation deferred')));
    worker.once('error', reject);
    worker.once('exit', () => reject(Error('Inventory index preparation interrupted')));
  });
}

// One bounded reader on small VPSs. Expensive SQLite scans cannot monopolize
// Express; identical account-scoped requests share a recent result/in-flight read.
export function createIntelligenceReads({ filePath, ttl = 15000, timeout = 60000, maxPending = 16,
  maxEntries = 48, maxBytes = 16 * 1024 * 1024 } = {}) {
  let worker, idle, sequence = 0, bytes = 0, closed = false;
  const pending = new Map(), flights = new Map(), cache = new Map();
  const unavailable = () => Object.assign(Error('A consulta está temporariamente indisponível.'), { status: 503 });
  function reset(current) {
    if (worker !== current) return;
    worker = null; clearTimeout(idle);
    for (const item of pending.values()) { clearTimeout(item.timer); item.reject(unavailable()); }
    pending.clear(); flights.clear();
    return current.terminate();
  }
  function start() {
    clearTimeout(idle);
    if (worker) return worker;
    const current = new Worker(new URL('./intelligenceReadWorker.js', import.meta.url), {
      workerData: { filePath }, execArgv: [], resourceLimits: { maxOldGenerationSizeMb: 128 },
    });
    worker = current; current.unref();
    current.on('error', () => reset(current));
    current.on('exit', () => reset(current));
    current.on('message', ({ id, data, error }) => {
      const item = pending.get(id);
      if (!item) return;
      pending.delete(id); clearTimeout(item.timer);
      if (error) item.reject(unavailable()); else item.resolve(data);
      if (!pending.size) { current.unref(); idle = setTimeout(() => { void reset(current); }, 10000); idle.unref(); }
    });
    return current;
  }
  function query(method, params = {}, { revision = '' } = {}) {
    if (closed) return Promise.reject(unavailable());
    const { archive: _archive, stories: _stories, ...identity } = params;
    const key = JSON.stringify([method, identity, revision]);
    const hit = cache.get(key);
    if (hit?.until > Date.now()) { cache.delete(key); cache.set(key, hit); return Promise.resolve(hit.data); }
    if (hit) { bytes -= hit.bytes; cache.delete(key); }
    if (flights.has(key)) return flights.get(key);
    if (pending.size >= maxPending) return Promise.reject(unavailable());
    const current = start(), id = ++sequence;
    current.ref();
    const request = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reset(current), timeout); timer.unref();
      pending.set(id, { resolve, reject, timer });
      try { current.postMessage({ id, method, params }); }
      catch { reset(current); }
    }).then(data => {
      const size = Buffer.byteLength(JSON.stringify(data));
      if (size <= maxBytes) {
        while (cache.size && (cache.size >= maxEntries || bytes + size > maxBytes)) {
          const first = cache.keys().next().value; bytes -= cache.get(first).bytes; cache.delete(first);
        }
        cache.set(key, { data, bytes: size, until: Date.now() + ttl }); bytes += size;
      }
      return data;
    }).finally(() => flights.delete(key));
    flights.set(key, request);
    return request;
  }
  return { query, async close() { closed = true; if (worker) await reset(worker); cache.clear(); bytes = 0; } };
}
