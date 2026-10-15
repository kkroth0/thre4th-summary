import path from 'node:path';
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
const root = path.resolve(process.argv[2] || process.cwd());
const { default: Database } = await import(pathToFileURL(path.join(root, 'server/node_modules/better-sqlite3/lib/index.js')));
const { compareNewsSnapshots, readPrimaryNewsSnapshot } = await import(pathToFileURL(path.join(root, 'server/newsPersistence.js')));
const db = new Database(path.join(root, 'server/.ioc-intelligence.sqlite'), { readonly: true, fileMustExist: true });
db.pragma('query_only=ON');
db.exec('BEGIN');
const hasManifest = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='news_storage_state'").get();
const primary = hasManifest ? readPrimaryNewsSnapshot(db) : null;
let jsonSnapshot, backupComparison;
try {
  jsonSnapshot = { archive: JSON.parse(fs.readFileSync(path.join(root, 'server/.news-archive.json'), 'utf8')), stories: JSON.parse(fs.readFileSync(path.join(root, 'server/.news-stories.json'), 'utf8')) };
  backupComparison = compareNewsSnapshots(db, jsonSnapshot.archive, jsonSnapshot.stories);
} catch { backupComparison = { equal: false, error: 'JSON recovery copy is unavailable or invalid' }; }
const snapshot = primary || jsonSnapshot;
if (!snapshot) throw Error('No valid news snapshot available');
const comparison = compareNewsSnapshots(db, snapshot.archive, snapshot.stories);
const report = { readOnly: true, at: new Date().toISOString(), mode: primary ? 'sqlite' : 'shadow', generation: primary?.generation || 0, comparison, backupComparison,
  backup: hasManifest ? JSON.parse(db.prepare("SELECT payload FROM news_storage_state WHERE id='backup'").get()?.payload || 'null') : null,
  bodyVersions: db.prepare('SELECT COUNT(*) n FROM news_body_versions').get().n,
  retainedBodies: db.prepare('SELECT COUNT(DISTINCT link) n FROM news_body_versions').get().n,
  revisions: db.prepare('SELECT COUNT(*) n FROM news_document_revisions').get().n,
  entities: db.prepare("SELECT scope='global' public,kind,COUNT(DISTINCT entity) n FROM intelligence_entity_names GROUP BY scope='global',kind").all(),
  checks: db.prepare('SELECT COUNT(*) n FROM news_shadow_checks').get().n,
  recentChecks: db.prepare('SELECT payload FROM news_shadow_checks ORDER BY id DESC LIMIT 3').all().map(row => JSON.parse(row.payload)),
};
db.close(); console.log(JSON.stringify(report, null, 2));
if (!comparison.readyForReadPilot || !backupComparison.equal) process.exitCode = 1;
