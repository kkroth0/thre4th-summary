import { Worker } from 'node:worker_threads';

// Keep source JSON decoding outside the request heap. Concurrent downloads
// share one bounded build, and only compact publication metadata crosses back.
export function createNewsExportSourceReader(directory) {
    let cached;
    return sources => {
        const urls = [...new Set(sources.map(source => source.url))].sort();
        const key = JSON.stringify(urls);
        if (cached?.key === key && (cached.pending || cached.expires > Date.now())) return cached.promise;
        const entry = { key, pending: true };
        entry.promise = new Promise((resolve, reject) => {
            const worker = new Worker(new URL('./newsExportSourceWorker.js', import.meta.url), {
                execArgv: [], resourceLimits: { maxOldGenerationSizeMb: 128 },
                workerData: { directory, sources: urls.map(url => ({ url })) },
            });
            let settled = false;
            const finish = (error, rows) => {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                void worker.terminate();
                if (error) reject(error);
                else { entry.expires = Date.now() + 300_000; resolve(rows); }
            };
            const failure = () => Object.assign(new Error('A leitura do histórico não terminou. Tente novamente em instantes.'), { status: 503 });
            const timer = setTimeout(() => finish(failure()), 90_000);
            worker.once('message', result => finish(Array.isArray(result.rows) ? null : failure(), result.rows));
            worker.once('error', () => finish(failure()));
            worker.once('exit', () => { if (!settled) finish(failure()); });
        }).finally(() => { entry.pending = false; });
        cached = entry;
        return entry.promise;
    };
}
