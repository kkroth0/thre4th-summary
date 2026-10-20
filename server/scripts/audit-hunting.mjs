// Manual audit: reads public-news backups, uses an in-memory service, and makes
// one bounded model request. No account data, feedback, keys or model text logged.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
const root = path.resolve(process.argv[2] || process.cwd());
const require = createRequire(path.join(root, 'server/index.js'));
const config = require('dotenv').parse(readFileSync(path.join(root, '.env')));
const http = require('axios');
const load = file => import(pathToFileURL(path.join(root, 'server', file)));
const { createHuntingLibrary } = await load('huntingLibrary.js');
const { buildHuntingCandidates } = await load('huntingService.js');
const { createHuntingGenerator } = await load('huntingAi.js');
const library = createHuntingLibrary({ snapshotPath: path.join(root, 'server/data/hunting-library.json') });
const news = JSON.parse(readFileSync(path.join(root, 'server/.news-archive.json'), 'utf8'));
const started = Date.now();
const result = buildHuntingCandidates({ news, library: library.all(), period: 'day' });
const report = { queries: library.all().length, publications: result.publications, elapsedMs: Date.now() - started,
  candidates: result.candidates.map(row => ({ query: row.query.title, match: row.matchKind, terms: row.matchTerms, sources: row.sources.map(source => source.title) })),
  ai: { configured: !!config.OPENROUTER_API_KEY, model: config.OPENROUTER_HUNTING_MODEL || 'deepseek/deepseek-v4.1-flash' } };
if (config.OPENROUTER_API_KEY && result.candidates.length) {
  const observedHttp = { post: async (...args) => { const response = await http.post(...args); const choice = response.data?.choices?.[0];
    Object.assign(report.ai, { http: response.status, finishReason: choice?.finish_reason, contentCharacters: choice?.message?.content?.length || 0, completionTokens: response.data?.usage?.completion_tokens }); return response; } };
  try {
    const generate = createHuntingGenerator({ http: observedHttp, getKey: () => config.OPENROUTER_API_KEY, model: report.ai.model });
    const output = await generate({ period: 'day', candidates: result.candidates.slice(0, 12), feedback: {} });
    report.ai.validChoices = output?.hypotheses?.filter(row => result.candidates.some(candidate => candidate.id === row.id)).length || 0;
  } catch (error) { report.ai.error = error.response?.status || error.code || error.name; }
}
console.log(JSON.stringify(report, null, 2));
if (report.ai.configured && (!report.ai.validChoices || report.ai.error)) process.exitCode = 1;
