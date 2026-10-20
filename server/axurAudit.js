// Read-only production verification. Emit aggregate counts, never credentials,
// indicator values, private report contents or encrypted user records.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
const root = path.resolve(process.argv[2] || process.cwd());
const login = String(process.argv[3] || '').toLowerCase();
if (!/^[a-z0-9-]{1,39}$/.test(login)) throw new Error('Expected GitHub login');
const users = JSON.parse(fs.readFileSync(path.join(root, 'server/.users.json'), 'utf8'));
const owner = Object.keys(users).find(key => users[key].login?.toLowerCase() === login);
if (!owner) throw new Error('Account not found');
const { default: Database } = await import(pathToFileURL(path.join(root, 'server/node_modules/better-sqlite3/lib/index.js')));
const db = new Database(path.join(root, 'server/.ioc-intelligence.sqlite'), { readonly:true, fileMustExist:true });
db.pragma('query_only = ON');db.pragma('busy_timeout = 5000');
const checkpoint = db.prepare('SELECT value FROM intelligence_state WHERE id=?').get(`axur-import-v1:${owner}`);
const state = checkpoint ? JSON.parse(checkpoint.value) : null;
const evidence = db.prepare("SELECT COUNT(*) evidence,COUNT(DISTINCT indicator) indicators FROM observations WHERE scope=? AND provider='Axur'").get(owner);
const linked = db.prepare("SELECT e.kind,COUNT(*) links,COUNT(DISTINCT e.entity) entities FROM observations o JOIN entity_links e ON e.observation=o.id WHERE o.scope=? AND o.provider='Axur' GROUP BY e.kind").all(owner);
const publicEvidence = db.prepare("SELECT COUNT(*) count FROM observations WHERE scope='global' AND provider='Axur'").get().count;
console.log(JSON.stringify({checkedAt:new Date().toISOString(),readOnly:true,configured:!!users[owner].apiKeysEnc?.axur,checkpoint:state,...evidence,linked,publicEvidence},null,2));
db.close();
if (publicEvidence || !evidence.evidence || !state?.processed) process.exitCode=1;
