// Shodan allows ~1 request/second per API key. A batch scan fires one request
// per target with no spacing, so a 225-IP run gets 429'd partway through.
// Every Shodan call in the server goes through this gate: one shared chain,
// >= MIN_INTERVAL_MS apart, one retry on 429 honouring Retry-After.
// ponytail: single-process chain. Two server instances sharing one key would
// each keep their own spacing — move the clock to Redis if we ever scale out.

const MIN_INTERVAL_MS = Number(process.env.SHODAN_MIN_INTERVAL_MS) || 1100;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const retryAfterMs = (error) => {
  const header = Number(error?.response?.headers?.['retry-after']);
  return Number.isFinite(header) && header > 0 ? header * 1000 : MIN_INTERVAL_MS * 2;
};

let chain = Promise.resolve();
let lastStart = 0;

export const shodanThrottled = (call) => {
  const run = chain.then(async () => {
    const wait = lastStart + MIN_INTERVAL_MS - Date.now();
    if (wait > 0) await sleep(wait);
    lastStart = Date.now();
    try {
      return await call();
    } catch (error) {
      if (error?.response?.status !== 429) throw error;
      await sleep(retryAfterMs(error));
      lastStart = Date.now();
      return call();
    }
  });
  chain = run.then(() => {}, () => {});
  return run;
};

// Drop-in for the axiosClient dep: same .get, throttled.
export const shodanAxios = (axiosClient) => ({
  get: (...args) => shodanThrottled(() => axiosClient.get(...args)),
});
