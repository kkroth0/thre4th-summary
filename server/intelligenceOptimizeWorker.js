import Database from 'better-sqlite3';
import { parentPort, workerData } from 'node:worker_threads';
import { backfillActorObservationIndex } from './actorObservationIndex.js';

const db = new Database(workerData.filePath, { fileMustExist: true });
db.pragma('busy_timeout = 1000');
db.pragma('cache_size = -8000');
db.pragma('temp_store = FILE');
try {
  // Cover inventory pages and counters without loading multi-KB provider
  // payloads from every observation. This only adds an index; no rows change.
  db.exec('CREATE INDEX IF NOT EXISTS observations_inventory ON observations(scope,indicator,published DESC,provider,collected)');
  backfillActorObservationIndex(db);
  parentPort.postMessage({ ok: true });
} catch { parentPort.postMessage({ ok: false }); }
finally { db.close(); }
