import { Worker } from 'node:worker_threads';

// XML/HTML DOMs expand far beyond the wire size. Keep them out of the API heap,
// parse one source at a time, and terminate idle heaps instead of retaining DOMs.
export function createFeedParser({ timeoutMs = 20000, idleMs = 2000,
  makeWorker = () => new Worker(new URL('./feedParserWorker.js', import.meta.url), {
    execArgv: [], resourceLimits: { maxOldGenerationSizeMb: 96 },
  }),
} = {}) {
  let worker, active, idle, serial = 0, closed = false;
  const queue = [];
  const failure = () => Error('A interpretação do feed excedeu a capacidade; cache anterior preservado.');
  function reset(current) {
    if (worker !== current) return;
    worker = null; clearTimeout(idle);
    if (active) { clearTimeout(active.timer); active.reject(failure()); active = null; }
    void current.terminate();
    pump();
  }
  function pump() {
    if (active || closed || !queue.length) return;
    clearTimeout(idle);
    if (!worker) {
      const current = makeWorker(); worker = current;
      current.on('error', () => reset(current));
      current.on('exit', () => reset(current));
      current.on('message', message => {
        if (worker !== current || active?.id !== message.id) return;
        const call = active; active = null; clearTimeout(call.timer);
        if (message.error) call.reject(failure()); else call.resolve(message.items);
        if (queue.length) pump();
        else { current.unref(); idle = setTimeout(() => reset(current), idleMs); idle.unref(); }
      });
    }
    const current = worker, call = queue.shift(); active = call;
    current.ref(); call.timer = setTimeout(() => reset(current), timeoutMs);
    try { current.postMessage({ id: call.id, args: call.args }); }
    catch { reset(current); }
  }
  const parse = (...args) => new Promise((resolve, reject) => {
    if (closed || queue.length >= 16) { reject(failure()); return; }
    queue.push({ id: ++serial, args, resolve, reject }); pump();
  });
  parse.close = async () => {
    closed = true;
    for (const call of queue.splice(0)) call.reject(failure());
    if (worker) { const current = worker; reset(current); await current.terminate(); }
  };
  return parse;
}
