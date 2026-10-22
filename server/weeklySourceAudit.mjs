// Operator check: reads provider APIs/catalog and warms only the shared public
// ransomware cache. Does not create or change any account's weekly report.
import path from 'node:path';
import { pathToFileURL } from 'node:url';
const root = path.resolve(process.argv[2] || process.cwd());
const local = name => pathToFileURL(path.join(root, 'server', name)).href;
const { default: dotenv } = await import(local('node_modules/dotenv/lib/main.js'));
const { default: http } = await import(local('node_modules/axios/index.js'));
dotenv.config({ path: path.join(root, '.env'), quiet: true });
const { weeklyWindow, buildWeeklyReport } = await import(local('weeklyReports.js'));
const { createWeeklyRansomware, weeklyProfile } = await import(local('weeklyRansomware.js'));
const { createVulnerabilityQueries } = await import(local('vulnerabilityQueries.js'));
const range = weeklyWindow(), result = { week: range.id, configured: { nvd: !!process.env.NVD_API_KEY, ransomware: !!process.env.RANSOMWARE_LIVE_API_KEY } };
try {
  const response = await http.get('https://services.nvd.nist.gov/rest/json/cves/2.0', { headers: { apiKey: process.env.NVD_API_KEY }, params: { resultsPerPage: 1 }, timeout: 20000, maxRedirects: 0 });
  result.nvd = { status: response.status, catalogTotal: response.data.totalResults };
} catch (error) { result.nvd = { status: error.response?.status || error.code || 'unavailable' }; }
try {
  const response = await http.get('https://api-pro.ransomware.live/listsectors', { headers: { 'X-API-KEY': process.env.RANSOMWARE_LIVE_API_KEY }, timeout: 20000, maxRedirects: 0 });
  const sectors = Array.isArray(response.data) ? response.data : response.data.sectors;
  result.sectors = { status: response.status, expected: weeklyProfile({ name: 'Grupo Ultrapar' }).ransomwareSectors, matched: weeklyProfile({ name: 'Grupo Ultrapar' }).ransomwareSectors.every(name => JSON.stringify(sectors).includes(name)) };
} catch (error) { result.sectors = { status: error.response?.status || error.code || 'unavailable' }; }
const history = await createWeeklyRansomware({ http, apiKey: process.env.RANSOMWARE_LIVE_API_KEY, filePath: path.join(root, 'server/.feed-cache/weekly-ransomware.json') }).get(range);
const reader = createVulnerabilityQueries({ filePath: path.join(root, 'server/.vulnerability-catalog.sqlite') });
try {
  const catalog = await reader.query('weekly', range);
  const report = buildWeeklyReport({ victims: history.victims, vulnerabilities: catalog.rows, coverage: { ransomware: history.coverage } }, { range, profile: { name: 'Grupo Ultrapar' } });
  result.catalog = { sources: catalog.status.sources, weeklyCves: report.vulnerabilities.total, weeklyKev: report.vulnerabilities.kevCount, aiCves: report.vulnerabilities.ai.total, editorial: { highlights: report.vulnerabilities.editorial.highlights.map(row=>({id:row.id,family:row.editorialFamily})), exploited: report.vulnerabilities.editorial.exploited.map(row=>row.id), missingFocus: report.vulnerabilities.editorial.missingFocus } };
  result.ransomware = { coverage: history.coverage, observations: history.victims.length, latam: report.ransomware.latam, brazil: report.ransomware.brazil, focus: report.ransomware.focusCount, weeksAvailable: report.ransomware.history.filter(w => w.available).length };
} catch (error) { result.catalog = { status: error.code || error.name }; }
finally { await reader.close(); }
console.log(JSON.stringify(result, null, 2));
if (!result.configured.nvd || !result.configured.ransomware || result.nvd?.status !== 200 || !result.sectors?.matched || result.ransomware?.coverage.status !== 'ready' || !result.catalog?.weeklyCves) process.exitCode = 1;
