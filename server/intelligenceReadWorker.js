import Database from 'better-sqlite3';
import { parentPort, workerData } from 'node:worker_threads';
import { normalizeIndicator } from './indicatorIdentity.js';
import { createIocIntelligenceReads } from './iocIntelligenceReads.js';
import { actorPublications, buildActorActivity } from './actorEvidence.js';
import { buildActorIdentityIndex, canonicalActorReferences } from './actorIdentity.js';

const db = new Database(workerData.filePath, { readonly: true, fileMustExist: true });
db.pragma('query_only = ON');
db.pragma('busy_timeout = 1000');
db.pragma('cache_size = -8000');
const reads = createIocIntelligenceReads(db, normalizeIndicator);
parentPort.on('message', ({ id, method, params }) => {
  try {
    db.exec('BEGIN');
    let data;
    if (method === 'entities') data = reads.entities(params.kind, params.owner);
    else if (method === 'status') data = reads.status(params.owner);
    else if (method === 'list') data = reads.list(params);
    else if (method === 'detail') data = reads.detail(params.value, params.owner, params);
    else if (method === 'publications') data = reads.publications(params);
    else if (method === 'actorActivity') {
      const identities=buildActorIdentityIndex(params.catalog||[]);
      const news=canonicalActorReferences(actorPublications(params.archive,params.stories),identities);
      data=buildActorActivity((function*(){yield* news;for(const row of reads.actorActivityRows(params.owner))yield* canonicalActorReferences([row],identities);})());
    } else throw Error('Unsupported read');
    db.exec('COMMIT');
    parentPort.postMessage({ id, data });
  } catch {
    if (db.inTransaction) db.exec('ROLLBACK');
    parentPort.postMessage({ id, error: 'A consulta está temporariamente indisponível.' });
  }
});
