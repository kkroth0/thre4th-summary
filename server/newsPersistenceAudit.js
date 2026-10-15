import path from 'node:path';
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
const root = path.resolve(process.argv[2] || process.cwd());
const { default: Database } = await import(pathToFileURL(path.join(root, 'server/node_modules/better-sqlite3/lib/index.js')));
const { compareNewsSnapshots } = await import(pathToFileURL(path.join(root, 'server/newsPersistence.js')));
const db = new Database(path.join(root, 'server/.ioc-intelligence.sqlite'), { readonly: true, fileMustExist: true });
db.pragma('query_only=ON');
const archive = JSON.parse(fs.readFileSync(path.join(root, 'server/.news-archive.json'), 'utf8'));
const stories = JSON.parse(fs.readFileSync(path.join(root, 'server/.news-stories.json'), 'utf8'));
const comparison = compareNewsSnapshots(db, archive, stories);
const report = { readOnly: true, at: new Date().toISOString(), comparison,
  bodyVersions: db.prepare('SELECT COUNT(*) n FROM news_body_versions').get().n,
  retainedBodies: db.prepare('SELECT COUNT(DISTINCT link) n FROM news_body_versions').get().n,
  revisions: db.prepare('SELECT COUNT(*) n FROM news_document_revisions').get().n,
  entities: db.prepare("SELECT scope='global' public,kind,COUNT(DISTINCT entity) n FROM intelligence_entity_names GROUP BY scope='global',kind").all(),
  checks: db.prepare('SELECT COUNT(*) n FROM news_shadow_checks').get().n,
  recentChecks: db.prepare('SELECT payload FROM news_shadow_checks ORDER BY id DESC LIMIT 3').all().map(row => JSON.parse(row.payload)),
};
db.close(); console.log(JSON.stringify(report, null, 2));
if (!comparison.equal || comparison.conflictingAliases) process.exitCode = 1;
