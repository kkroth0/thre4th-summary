// Coordinate interactive IOC searches and the background import for one account.
// Axur's CTI endpoints are read-only and do not tolerate parallel searches well.
const queues = new Map();
export async function readAxur(scope, http, url, options) {
  const key = String(scope), previous = queues.get(key) || Promise.resolve();
  let release;
  const done = new Promise(resolve => { release = resolve; });
  const tail = previous.catch(() => {}).then(() => done);
  queues.set(key, tail);
  try {
    await previous.catch(() => {});
    options.signal?.throwIfAborted();
    return await http.get(url, options);
  } finally {
    release();
    if (queues.get(key) === tail) queues.delete(key);
  }
}
