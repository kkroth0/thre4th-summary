import Database from 'better-sqlite3';
import { parentPort, workerData } from 'node:worker_threads';
import { setImmediate as yieldLoop } from 'node:timers/promises';
import { createObservationWriter } from './observationWriter.js';
import { createNewsPersistence } from './newsPersistence.js';

const db = new Database(workerData.filePath, { fileMustExist: true });
db.pragma('busy_timeout = 5000');
db.pragma('cache_size = -8000');
const chunk = createObservationWriter(db, createNewsPersistence(db));
parentPort.on('message', async ({ id, rows }) => {
  try {
    let size = 100;
    for (let offset = 0; offset < rows.length;) {
      const batch = rows.slice(offset, offset + size), start = performance.now();
      chunk(batch); offset += batch.length;
      size = Math.min(200, Math.max(25, Math.floor(size * 50 / Math.max(1, performance.now() - start))));
      await yieldLoop();
    }
    parentPort.postMessage({ id, count: rows.length });
  } catch { parentPort.postMessage({ id, error: true }); }
});
