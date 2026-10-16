import { workerData, parentPort } from 'node:worker_threads';
import { createVulnerabilityCatalog } from './vulnerabilityCatalog.js';

const catalog = createVulnerabilityCatalog({ filePath: workerData.filePath });
try {
    const result = await catalog.backfillAiIndex();
    parentPort.postMessage({ complete: result.complete, indexed: result.indexed });
} finally { catalog.close(); }
