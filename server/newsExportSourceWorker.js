import fs from 'node:fs';
import { parentPort, workerData } from 'node:worker_threads';
import { createFeedCache } from './feedCollector.js';
import { createNewsExportSourceCache } from './newsExportSourceCache.js';
try {
    const cache = createFeedCache({ directory: workerData.directory, fs });
    const rows = await createNewsExportSourceCache(cache)(workerData.sources);
    parentPort.postMessage({ rows });
} catch (error) {
    parentPort.postMessage({ error: error.code || error.name });
}
