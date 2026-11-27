// Verify the installed recovery path against the enabled feeds. Output counts
// only. No end-user account, cookies, article bodies or private exports.
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import vm from 'node:vm';
const root = path.resolve(process.argv[2], 'server');
const load = name => import(pathToFileURL(path.join(root, name)));
const { createFeedCache } = await load('feedCollector.js');
const { createNewsExportSourceCache } = await load('newsExportSourceCache.js');
const { selectNewsExportPublications } = await load('newsExportSelection.js');
const { newsExportRows } = await load('newsExport.js');
const { CTI_FEEDS } = await load('ctiIntel.js');
const { PUBLICATION_SOURCES, OT_PUBLICATION_SOURCES } = await load('publicationSources.js');
const { REPOSITORY_SOURCES } = await load('repositorySources.js');
const { SCRAPE_SOURCES } = await load('scrapeFeeds.js');
let config = {};
try { config = JSON.parse(fs.readFileSync(path.join(root, '.feed-sources.json'), 'utf8')); }
catch (error) { if (error.code !== 'ENOENT') throw error; }
const enabled = [...CTI_FEEDS,...PUBLICATION_SOURCES,...OT_PUBLICATION_SOURCES,...REPOSITORY_SOURCES,...(config.custom||[]),...SCRAPE_SOURCES]
    .filter(source => !(config.disabled || []).includes(source.url));
const cache = createFeedCache({ directory: path.join(root,'.feed-cache','rss'), fs });
const sourceCache = await createNewsExportSourceCache(cache)(enabled);
const window = { from:'2026-11-20T03:00:00.000Z', to:'2026-11-28T02:59:59.999Z' };
const rowsFor = preferences => newsExportRows(selectNewsExportPublications({ ...window, sourceCache, preferences }).publications,'news');
const all = rowsFor({mode:'all'});
const empty = rowsFor({mode:'selected',vendorIds:[]});
console.log(JSON.stringify({sources:enabled.length, exportedFromSources:all.length, distinctLinks:new Set(all.map(row=>row.url)).size, emptySelection:empty.length}));
if (!all.length || empty.length || all.some(row=>!row.title||!row.url||!row.date||!row.analysisStatus)) process.exitCode=1;
const archive = JSON.parse(fs.readFileSync(path.join(root,'.news-archive.json'),'utf8'));
const stories = JSON.parse(fs.readFileSync(path.join(root,'.news-stories.json'),'utf8'));
const code = fs.readFileSync(path.join(root,'index.js'),'utf8');
const start=code.indexOf("app.get('/api/news/export'");
const end=code.indexOf('\n});',start)+5;
const { newsExportQuery, newsExportCsv } = await load('newsExport.js');
let handler;
const snapshot=cache.get('newsletter:snapshot');
vm.runInNewContext(code.slice(start,end).replace('res.status(error.status || 500)', 'console.error(error.stack); res.status(error.status || 500)'),{
    app:{get(route,...handlers){handler=handlers.at(-1);}}, requirePremium(){}, console,
    newsExportQuery, newsExportRows, newsExportCsv, selectNewsExportPublications,
    readNewsExportSources:async()=>sourceCache,
    effectiveFeeds:()=>enabled, SCRAPE_SOURCES:[], feedOverrides:{disabled:[]},
    memoryCache:{newsletter:{data:snapshot?.items||[]}},
    newsArchiveStore:{all:()=>archive}, newsStoryStore:{all:()=>stories},
    newsMonitoringStore:{get:()=>({mode:'all',vendorIds:[]})},
});
const res={code:200,status(code){this.code=code;return this;},set(){return this;},json(data){console.log(JSON.stringify({http:this.code,error:data.error,count:data.count,publications:data.publications}));},type(){return this;},send(){console.log('csv',this.code);}};
await handler({query:{...window,dataset:'news',format:'json'},user:{sub:'diagnostic'}},res);
if(res.code!==200)process.exitCode=1;
