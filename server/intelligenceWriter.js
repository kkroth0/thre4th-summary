import { Worker } from 'node:worker_threads';

// The core ingestion queue serializes batches and news revisions. An isolated
// SQLite connection keeps disk waits and commits out of the HTTP event loop.
export function createIntelligenceWriter(filePath) {
  let worker = null, idle, serial = 0, active = null;
  function stop(current) {
    if (worker !== current) return;
    worker = null; clearTimeout(idle);
    if (active) { active.reject(Error('IOC batch write interrupted; checkpoint retained')); active = null; }
    return current.terminate();
  }
  function start() {
    clearTimeout(idle);
    if (worker) return worker;
    const current = new Worker(new URL('./intelligenceWriteWorker.js', import.meta.url), {
      workerData: { filePath }, execArgv: [], resourceLimits: { maxOldGenerationSizeMb: 128 },
    });
    worker = current;
    current.on('error', () => stop(current));
    current.on('exit', () => stop(current));
    current.on('message', ({ id, count, error }) => {
      if (active?.id !== id) return;
      const call = active; active = null;
      if (error) call.reject(Error('IOC batch write failed; checkpoint retained')); else call.resolve(count);
      idle = setTimeout(() => { void stop(current); }, 5000); idle.unref(); current.unref();
    });
    return current;
  }
  return {
    ingest(rows) {
      if (active) return Promise.reject(Error('IOC write queue must be serialized'));
      const current = start(), id = ++serial; current.ref();
      return new Promise((resolve, reject) => {
        active = { id, resolve, reject };
        try { current.postMessage({ id, rows }); } catch { void stop(current); }
      });
    },
    async close() { if (worker) await stop(worker); },
  };
}
