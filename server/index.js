import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import dotenv from 'dotenv';
import axios from 'axios';
import path from 'path';
import { fileURLToPath } from 'url';
import dns from 'dns';
import net from 'net';
import fs from 'fs';
import crypto from 'crypto';
import compression from 'compression';
import * as cheerio from 'cheerio';
import {
    scoreArticle, localizeEnrichment, severityFromScore, extractIOCs, CTI_FEEDS,
    extractReadableText, collectArtifactLinks, githubArtifact, ARTIFACT_TEXT_FILE,
    protectTerms, restoreTerms, isTransientFeedError, isPureNoise,
    ttpIdsFrom,
} from './ctiIntel.js';
import { actorTargeting } from './actorProfile.js';
import { buildSoftwareIndex, buildActorNameIndex } from './actorSoftware.js';
import { filterExactIocs } from './threatfoxMatch.js';
import { getShodanCreditStatus, runAttackSurfaceScan } from './attackSurface.js';
import { shodanAxios } from './shodanGate.js';
import { createMalwareCatalog } from './malwareCatalog.js';
import { createPhishingSources } from './phishingSources.js';
import { createWhoisLookup } from './whoisLookup.js';
import { createDomainIntelligence, domainTarget } from './domainIntelligence.js';
import { createVulnerabilityCatalog } from './vulnerabilityCatalog.js';
import { createVulnerabilityQueries, optimizeVulnerabilityCatalog } from './vulnerabilityQueries.js';
import { createLookupCache } from './lookupCache.js';
import { PUBLICATION_SOURCES, OT_PUBLICATION_SOURCES, createPublicationResolver } from './publicationSources.js';
import { REPOSITORY_SOURCES, createRepositoryResolver } from './repositorySources.js';
import { prepareFeedJobDocuments } from './feedJobDocuments.js';
import { createPublicationRequest } from './publicationHttp.js';
import { actorPublications, buildActorActivity, buildActorEvidence } from './actorEvidence.js';
import { otxThrottled, OTX_TIMEOUT_MS } from './otxGate.js';
import { findMentions, findDomainMentions } from './newsIocs.js';
import { refsOfReport, relatedTo } from './attackIndex.js';
import { isJobId, jobSummary, normalizeDeckRequestType, normalizeDeckSubtype, normalizeDeckTemplate, orphanDeckFiles, pruneJobsMap } from './feedJobs.js';
import { addKnowledgeItem, normalizeKnowledgeInput } from './knowledge.js';
import { createWatchlistStore, runDueExposureSnapshots, runExposureSnapshot } from './exposureWatchlist.js';
import { detectQueryType, sanitizeQuery } from './iocValidation.js';
import { isEarlyDoc, normalizeCvrf } from './patchTuesday.js';
import { parseSapNotes, latestPatchMonth, monthUrl, summarize as summarizeSap, sortNotes as sortSapNotes } from './sapPatch.js';
import {
    asArray,
    buildThreatMapResponse,
    countBy,
    COUNTRY_NAMES,
    DEFAULT_FOCUS_REGIONS,
    filterByRegions,
    LATAM_COUNTRIES,
    normalizeVictim,
    ransomwareLiveRequestOptions,
    REGIONS,
    sectorListRequestOptions,
    sectorVictimsRequestOptions,
} from './ransomwareLive.js';
import {
    createEditionGenerator,
    createEditionStore,
    getCompletedDate,
    selectDailyEdition,
} from './dailyEditions.js';
import { buildActorIndex, matchActors } from './actorMatch.js';
import { buildMalwareIndex, matchMalware } from './malwareMatch.js';
import { buildCampaignIndex, matchCampaigns } from './campaignMatch.js';
import { explainCorrelation, explainCorrelationDecisions } from './correlationEvidence.js';
import { extractSellerHandle, findRelatedBySeller, storySellerHandle } from './darkWebHandle.js';
import { categorize } from './newsCategories.js';
import { correlateNewsFeedAsync } from './newsCorrelation.js';
import { parseFeed } from './feedParse.js';
import { createFeedCache, createFeedCollector, canonicalArticleUrl, singleFlightRefresh } from './feedCollector.js';
import { collectArticleTexts } from './articleCollector.js';
import { enrichFeedItemsAsync, applyVulnerabilityContext, EXTRACTION_VERSION } from './feedEnrichment.js';
import { createStoryStore } from './newsStoryStore.js';
import { createNewsArchiveStore } from './newsArchiveStore.js';
import { newsExportQuery, newsExportRows, newsExportCsv } from './newsExport.js';
import { buildPhishingDataset, phishingQuery } from './phishingDataset.js';
import { VENDOR_CATALOG } from './vendorCatalog.js';
import { createNewsMonitoringStore, filterMonitoredNews, filterMonitoredStories } from './newsMonitoring.js';
import {
    PHISH_LIMITS, createPhishWatchStore, createOwnerUrlscanClient, runDuePhishWatch, runProfileWatch,
    createDnsResolver, recheckHitsDns,
} from './phishingWatch.js';
import {
    OPEN_STATUS, applyStatus, attachEvidence, buildDailyDigest, createTicketStore, markDns,
    noteRecurrence, selectAutoOpen, takedownRequest, ticketFromHit,
} from './phishTickets.js';
import { createRdap, takedownTargets } from './rdap.js';
import { createQuotaReader } from './vendorQuotas.js';
import { ORG_REGIONS, ORG_SECTORS, createProfileStore } from './orgProfiles.js';
import { buildThreatModel } from './orgThreatModel.js';
import { SCRAPE_SOURCES, collectScraped } from './scrapeFeeds.js';

// Load the root .env regardless of the process cwd (systemd runs from server/,
// local dev may not).
dotenv.config({ path: path.join(path.dirname(fileURLToPath(import.meta.url)), '../.env') });

// Fail fast in production if the session secret is missing: signing with an
// empty key would silently break every login (cookies issued but never valid).
if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
    console.error('FATAL: SESSION_SECRET is required in production. Generate one with:');
    console.error("  node -e \"console.log(require('crypto').randomBytes(64).toString('hex'))\"");
    process.exit(1);
}

// Last-resort safety net: log and keep the process alive on stray rejections,
// crash cleanly (systemd restarts us) on truly unrecoverable exceptions.
process.on('unhandledRejection', (reason) => {
    console.error('unhandledRejection:', reason instanceof Error ? reason.stack : reason);
});
process.on('uncaughtException', (err) => {
    console.error('uncaughtException:', err.stack || err);
    process.exit(1);
});

// Global safety net: cap every outbound request at 10s so a slow/hung upstream
// provider can't tie up a connection indefinitely. Handlers that need a
// different budget (feed refresh, OpenRouter, etc.) still set their own `timeout`,
// which overrides this default.
axios.defaults.timeout = 10000;

const app = express();
// Trust a single front reverse proxy (Render/nginx) so express-rate-limit keys
// off the real client IP. Use 1 (a known hop), NOT true (which would trust
// client-supplied X-Forwarded-For and make the per-IP limit spoofable).
app.set('trust proxy', 1);
app.use(compression());
const PORT = process.env.PORT || 3001;

// Security headers
app.use(helmet({
    contentSecurityPolicy: false, // CSP is handled by Nginx in production
    crossOriginEmbedderPolicy: false, // Allow loading external resources
}));

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Atomic JSON persistence: write to a sibling tmp file then rename, so a crash
// mid-write can never truncate or corrupt the live store.
function writeJsonAtomic(file, data) {
    const tmp = `${file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
    fs.renameSync(tmp, file);
}

const EXPOSURE_ASSETS_PATH = path.join(__dirname, '.exposure-watchlist.json');
const EXPOSURE_SNAPSHOTS_PATH = path.join(__dirname, '.exposure-snapshots.json');
const exposureStore = createWatchlistStore({
    assetsPath: EXPOSURE_ASSETS_PATH,
    snapshotsPath: EXPOSURE_SNAPSHOTS_PATH,
    readFileSync: fs.readFileSync,
    writeJsonAtomic,
});
const DAILY_SUMMARIES_PATH = path.join(__dirname, '.daily-summaries.json');
const dailyEditionStore = createEditionStore({ filePath: DAILY_SUMMARIES_PATH, writeJsonAtomic });

const NEWS_STORIES_PATH = path.join(__dirname, '.news-stories.json');
const newsStoryStore = createStoryStore({ filePath: NEWS_STORIES_PATH, readFileSync: fs.readFileSync, writeJsonAtomic });
const NEWS_ARCHIVE_PATH = process.env.NEWS_ARCHIVE_PATH || path.join(__dirname, '.news-archive.json');
const newsArchiveStore = createNewsArchiveStore({ filePath: NEWS_ARCHIVE_PATH, readFileSync: fs.readFileSync, writeJsonAtomic });
const newsMonitoringStore = createNewsMonitoringStore({
    filePath: process.env.NEWS_MONITORING_PATH || path.join(__dirname, '.news-monitoring.json'),
    readFileSync: fs.readFileSync, writeJsonAtomic,
});

const PHISH_WATCH_PATH = path.join(__dirname, '.phish-watch.json');
const phishWatchStore = createPhishWatchStore({ filePath: PHISH_WATCH_PATH, readFileSync: fs.readFileSync, writeJsonAtomic });
// Só busca, nunca submete: submeter publicaria a URL do cliente no urlscan.
const urlscanClientFor = createOwnerUrlscanClient({
    getUserApiKey: (ownerId) => getUserApiKey(ownerId, 'urlscan'),
    platformApiKey: process.env.URLSCAN_API_KEY,
});
// Resolução direta contra os nameservers, sem depender de o urlscan reescanear.
const phishDnsResolver = createDnsResolver({
    resolve4: dns.promises.resolve4,
    resolve6: dns.promises.resolve6,
    resolveMx: dns.promises.resolveMx,
    resolveNs: dns.promises.resolveNs,
});

const PHISH_TICKETS_PATH = path.join(__dirname, '.phish-tickets.json');
const phishTicketStore = createTicketStore({ filePath: PHISH_TICKETS_PATH, readFileSync: fs.readFileSync, writeJsonAtomic });
const rdap = createRdap({});

// A evidência é congelada na abertura porque domínio de phishing morre rápido e
// o pedido de derrubada precisa da prova de quando estava no ar. RDAP é registro
// de terceiro: se falhar, o ticket existe do mesmo jeito, sem os contatos.
async function withEvidence(ticket, hit, at) {
    try {
        const [registration, hosting] = await Promise.all([
            rdap.domain(ticket.apexDomain).catch(() => null),
            hit.ip ? rdap.ip(hit.ip).catch(() => null) : Promise.resolve(null),
        ]);
        return attachEvidence(ticket, {
            at, registration, hosting, ip: hit.ip, asn: hit.asn, country: hit.country,
            targets: takedownTargets({ domain: ticket.apexDomain, hosting, registration }),
        });
    } catch (error) {
        console.error('phish ticket evidence failed:', error.message || error);
        return ticket;
    }
}

/**
 * Achado → fila. Score alto abre sozinho; confirmado na mão abre também.
 *
 * O mesmo domínio voltando não abre tarefa nova: se o ticket já foi encerrado,
 * reabre com a data da volta, que é o que mostra golpista insistente.
 */
async function syncTicketsFromHits(ownerId, profileId, { manualHitId = null } = {}) {
    const at = new Date().toISOString();
    const opened = [];
    const hits = phishWatchStore.list(ownerId, { profileId });
    const semTicket = hits.filter((hit) => !phishTicketStore.byId(hit.id));
    const autoOpen = new Set(selectAutoOpen(semTicket).map((hit) => hit.id));

    for (const hit of hits) {
        const manual = manualHitId && hit.id === manualHitId;
        const existing = phishTicketStore.byId(hit.id);

        if (existing) {
            if (!OPEN_STATUS.includes(existing.status) && String(hit.lastSeen) > String(existing.updatedAt)) {
                phishTicketStore.upsert(noteRecurrence(existing, { at }));
            }
            continue;
        }
        if (!manual && !autoOpen.has(hit.id)) continue;

        const ticket = ticketFromHit(hit, { at, openedBy: manual ? 'manual' : 'auto', by: manual ? 'analista' : 'sistema' });
        phishTicketStore.upsert(await withEvidence(ticket, hit, at));
        opened.push(ticket.id);
    }
    return opened;
}

// Domínio que parou de resolver é candidato a derrubado — o sistema anota o
// fato e nunca fecha o ticket sozinho: pode ter sido o takedown, pode ter sido
// o golpista trocando de casa.
async function recheckTicketDns(now = new Date()) {
    const cutoff = now.getTime() - PHISH_LIMITS.runIntervalMs;
    for (const ticket of phishTicketStore.all()) {
        if (!OPEN_STATUS.includes(ticket.status)) continue;
        const checkedAt = ticket.dns?.checkedAt ? new Date(ticket.dns.checkedAt).getTime() : 0;
        if (checkedAt > cutoff) continue;
        let alive = false;
        try {
            const addresses = await dns.promises.resolve4(ticket.apexDomain);
            alive = addresses.length > 0;
        } catch { alive = false; }
        phishTicketStore.upsert(markDns(ticket, alive, { at: new Date().toISOString() }));
    }
}

const ORG_PROFILES_PATH = process.env.ORG_PROFILES_PATH || path.join(__dirname, '.org-profiles.json');
const orgProfileStore = createProfileStore({ filePath: ORG_PROFILES_PATH, readFileSync: fs.readFileSync, writeJsonAtomic });

// Data de primeira aparição das fontes raspadas. Sem isto, cada refresh de 10
// minutos recarimbaria todo post com a hora atual.
const SCRAPE_SEEN_PATH = path.join(__dirname, '.scrape-seen.json');
let scrapeSeen = {};
try { scrapeSeen = JSON.parse(fs.readFileSync(SCRAPE_SEEN_PATH, 'utf8')) || {}; } catch { scrapeSeen = {}; }

// 2232 names and aliases, indexed once at boot rather than per article.
const actorIndex = (() => {
    try {
        const raw = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'actors.json'), 'utf8'));
        return buildActorIndex(Array.isArray(raw) ? raw : raw.actors);
    } catch (error) {
        console.error('actor index unavailable:', error.message);
        return buildActorIndex([]);
    }
})();

// Same pattern, same reason: ~4000 malware-family names and aliases, indexed
// once at boot rather than per article.
const malwareIndex = (() => {
    try {
        const raw = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'malware.json'), 'utf8'));
        return buildMalwareIndex(Array.isArray(raw) ? raw : raw.malware);
    } catch (error) {
        console.error('malware index unavailable:', error.message);
        return buildMalwareIndex([]);
    }
})();

// Same pattern again: ~166 named operations (MITRE ATT&CK + Tidal Cyber),
// indexed once at boot.
const campaignIndex = (() => {
    try {
        const raw = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'campaigns.json'), 'utf8'));
        return buildCampaignIndex(Array.isArray(raw) ? raw : raw.campaigns);
    } catch (error) {
        console.error('campaign index unavailable:', error.message);
        return buildCampaignIndex([]);
    }
})();

// CORS Config
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:8080'];
const corsOptionsDelegate = (req, callback) => {
    const origin = req.header('Origin');
    // Allow same-origin / non-browser requests (no Origin header) and explicitly
    // allowlisted origins only. No credentials are used (no cookie/session auth),
    // and we no longer reflect arbitrary origins via a host-match fallback.
    const isAllowed = !origin || allowedOrigins.includes(origin);

    callback(null, {
        origin: isAllowed,
        methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization'],
    });
};
app.use(cors(corsOptionsDelegate));

// Express Settings - Payload Limits
// Padrão apertado (10kb) p/ todas as rotas; a rota interna autenticada de upload
// do boletim (POST /api/feed/job/result) usa parser próprio maior (ver abaixo),
// pois o JSON do boletim gerado pelo motor excede 10kb e dava 413 Payload Too Large.
// O teto subiu de novo quando o worker passou a mandar deck E PDF no mesmo corpo:
// ~3 MB de .pptx + ~2 MB de .pdf viram ~7 MB depois do base64, e o JSON vai junto.
const tightJson = express.json({ limit: '10kb' });
const bulkJson = express.json({ limit: '25mb' });
app.use((req, res, next) => {
    if (req.method === 'POST' && req.path === '/api/feed/job/result') return bulkJson(req, res, next);
    return tightJson(req, res, next);
});
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// Rate limiting
const skipRateLimit = (req) => {
    // Skip rate limiting only if DISABLE_RATE_LIMIT is explicitly set to 'true'
    // Rate limiting is ON by default for security
    const disableRateLimit = process.env.DISABLE_RATE_LIMIT === 'true';
    if (disableRateLimit) return true;

    // Usuário logado não é limitado: um lote de busca dispara ~20 consultas por
    // IOC e o teto real dele passa a ser a cota das bases, mostrada na faixa de
    // créditos. Anônimo continua limitado — as rotas de busca são públicas e
    // queimam a chave do servidor.
    if (verifySession(getCookie(req, 'ts_session'))) return true;

    const p = req.path || '';
    // Rotas worker<->site: o worker na VPS faz poll a cada 10s, o que sozinho
    // consome 90 das 150 requisições da janela de 15 min e derruba o próprio
    // pipeline de geração. Não são superfície pública — requireFeedSecret já
    // barra quem não tem o FEED_AGENT_SECRET, e é ele que faz o rate limiting
    // de verdade aqui.
    return p === '/feed/jobs/pending' || p === '/feed/job/result'
        || p === '/api/feed/jobs/pending' || p === '/api/feed/job/result';
};

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 150,
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: skipRateLimit
});
app.use('/api/', limiter);

const scanLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 60,
    message: { error: 'Scan rate limit exceeded. Please wait a minute.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: skipRateLimit
});

// Error Sanitization Utility
const sanitizeError = (error) => {
    let status = error.response?.status || 500;
    
    // Map upstream 401/403 to 502 (Bad Gateway) to prevent frontend from treating it as session authentication failure
    if (status === 401 || status === 403) {
        status = 502;
    }
    
    const safeMessages = {
        400: 'Bad request',
        502: 'Upstream authentication or access configuration failed',
        404: 'Resource not found',
        429: 'Rate limit exceeded on upstream provider',
    };
    const message = safeMessages[status] || 'Internal server error';
    console.error(`[Error] Status: ${status}, Message: ${error.message}`);
    return { status, message };
};


// Helper to extract quota info
const sendResponseWithQuota = (res, axiosResponse, vendor) => {
    const headers = axiosResponse.headers;
    const quota = {};

    // A cota do AbuseIPDB só existe no header de uma consulta real: aproveitar a
    // que já está passando evita gastar um crédito pra perguntar quantos sobraram.
    if (vendor) quotaReader.record(vendor, headers);

    if (headers['x-ratelimit-remaining']) quota.remaining = headers['x-ratelimit-remaining'];
    if (headers['x-ratelimit-limit']) quota.limit = headers['x-ratelimit-limit'];
    if (headers['x-ratelimit-reset']) quota.reset = headers['x-ratelimit-reset'];

    if (headers['x-daily-requests-left']) quota.daily_remaining = headers['x-daily-requests-left'];

    res.json({
        data: axiosResponse.data,
        quota: Object.keys(quota).length > 0 ? quota : undefined
    });
};

// --- API Key rotation ---
// Each provider can supply several keys, discovered from the base env var plus
// numbered fallbacks: VIRUSTOTAL_API_KEY, VIRUSTOTAL2_API_KEY, VIRUSTOTAL3_API_KEY...
// (any single var may itself hold a comma-separated list). When a key gets
// rate-limited or rejected, we transparently rotate to the next one. A
// per-provider cursor remembers where to resume so load spreads across keys.
const keyCursors = {};

const splitKeys = (raw) => (raw || '').split(',').map(k => k.trim()).filter(Boolean);

const getKeys = (envName) => {
    const keys = [...splitKeys(process.env[envName])];

    // Pull in numbered fallbacks, e.g. ABUSEIPDB_API_KEY -> ABUSEIPDB2_API_KEY, ABUSEIPDB3_API_KEY
    const match = envName.match(/^(.*?)(_API_KEY)$/);
    if (match) {
        const [, prefix, suffix] = match;
        for (let n = 2; process.env[`${prefix}${n}${suffix}`] !== undefined; n++) {
            keys.push(...splitKeys(process.env[`${prefix}${n}${suffix}`]));
        }
    }
    return [...new Set(keys)]; // de-dupe in case a key is repeated across vars
};

// Runs makeRequest(key) against each available key, rotating on rate-limit (429)
// or auth (401/403) failures until one succeeds or all keys are exhausted.
// Other errors (404, etc.) are genuine answers and surface immediately.
// Throws an error tagged `noKey` when no keys are configured.
const withKeyRotation = async (envName, makeRequest) => {
    const keys = getKeys(envName);
    if (keys.length === 0) {
        const err = new Error('API Key missing');
        err.noKey = true;
        throw err;
    }

    const start = keyCursors[envName] || 0;
    let lastError;

    for (let i = 0; i < keys.length; i++) {
        const idx = (start + i) % keys.length;
        try {
            const response = await makeRequest(keys[idx]);
            keyCursors[envName] = idx; // next request starts from the key that worked
            return response;
        } catch (error) {
            lastError = error;
            const status = error.response?.status;
            if (status === 429 || status === 401 || status === 403) {
                if (keys.length > 1) {
                    console.warn(`[KeyRotation] ${envName} key #${idx + 1}/${keys.length} failed (${status}), rotating...`);
                }
                keyCursors[envName] = (idx + 1) % keys.length; // skip the exhausted key next time
                continue;
            }
            throw error; // not a rotation-worthy error
        }
    }
    throw lastError; // all keys exhausted
};

const quotaReader = createQuotaReader({ getKeys });
const lookupCache = createLookupCache();
async function cachedProvider(req, res, provider, query, credentials, load) {
    const session = verifySession(getCookie(req, 'ts_session'));
    const result = await lookupCache.get({ provider, query, owner: session?.sub || '', credentials, fresh: req.body?.fresh === true }, async () => {
        const response = await load();
        // Keep only the JSON and quota headers, never axios sockets/config/keys.
        const quotaHeaders = {};
        for (const name of ['x-ratelimit-remaining', 'x-ratelimit-limit', 'x-ratelimit-reset', 'x-daily-requests-left']) if (response.headers?.[name] !== undefined) quotaHeaders[name] = response.headers[name];
        return { data: response.data, headers: quotaHeaders };
    });
    res.set('Cache-Control', 'private, no-store');
    res.set('X-Lookup-Cache', result.state);
    res.set('X-Lookup-Collected-At', result.collectedAt);
    return result.value;
}

app.get('/api/admin/performance', requireAdmin, (req, res) => {
    res.set('Cache-Control', 'private, no-store');
    res.json({ lookups: lookupCache.stats() });
});

// --- API Endpoints ---

// VirusTotal
app.post('/api/virustotal', scanLimiter, async (req, res) => {
    const { query } = req.body;

    try {
        const queryType = detectQueryType(query);
        const sanitized = sanitizeQuery(query, queryType);
        let endpoint = "";

        if (queryType === "ip") endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${sanitized}`;
        else if (queryType === "domain") endpoint = `https://www.virustotal.com/api/v3/domains/${sanitized}`;
        else if (queryType === "hash") endpoint = `https://www.virustotal.com/api/v3/files/${sanitized}`;
        else endpoint = `https://www.virustotal.com/api/v3/urls/${Buffer.from(sanitized).toString('base64').replace(/=/g, "")}`;

        const response = await cachedProvider(req, res, 'virustotal', sanitized, getKeys('VIRUSTOTAL_API_KEY'), () => withKeyRotation('VIRUSTOTAL_API_KEY', (key) =>
            axios.get(endpoint, { headers: { "x-apikey": key } })
        ));
        sendResponseWithQuota(res, response);
    } catch (error) {
        if (error.noKey) return res.status(500).json({ error: "API Key missing" });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// AbuseIPDB
app.post('/api/abuseipdb', scanLimiter, async (req, res) => {
    const { query } = req.body;

    try {
        const queryType = detectQueryType(query);
        if (queryType !== "ip") return res.json({ data: { "Status": "IP only" } });

        const sanitized = sanitizeQuery(query, 'ip');
        const response = await cachedProvider(req, res, 'abuseipdb', sanitized, getKeys('ABUSEIPDB_API_KEY'), () => withKeyRotation('ABUSEIPDB_API_KEY', (key) =>
            axios.get(`https://api.abuseipdb.com/api/v2/check`, {
                params: {
                    ipAddress: sanitized,
                    maxAgeInDays: 90,
                    verbose: true
                },
                headers: { "Key": key, "Accept": "application/json" }
            })
        ));
        sendResponseWithQuota(res, response, 'AbuseIPDB');
    } catch (error) {
        if (error.noKey) return res.status(500).json({ error: "API Key missing" });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// AbuseIPDB Check-Block
app.post('/api/abuseipdb/check-block', scanLimiter, async (req, res) => {
    const { query } = req.body;
    if (!query) return res.status(400).json({ error: "Network parameter 'query' is required" });

    try {
        const sanitized = sanitizeQuery(query, 'cidr');
        const response = await cachedProvider(req, res, 'abuseipdb-block', sanitized, getKeys('ABUSEIPDB_API_KEY'), () => withKeyRotation('ABUSEIPDB_API_KEY', (key) =>
            axios.get(`https://api.abuseipdb.com/api/v2/check-block`, {
                params: {
                    network: sanitized,
                    maxAgeInDays: 30
                },
                headers: { "Key": key, "Accept": "application/json" }
            })
        ));
        sendResponseWithQuota(res, response, 'AbuseIPDB');
    } catch (error) {
        if (error.noKey) return res.status(500).json({ error: "API Key missing" });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// AlienVault OTX
app.post('/api/alienvault', scanLimiter, async (req, res) => {
    const { query } = req.body;
    const headers = {};
    if (process.env.ALIENVAULT_API_KEY) headers["X-OTX-API-KEY"] = process.env.ALIENVAULT_API_KEY;

    try {
        const queryType = detectQueryType(query);
        const sanitized = sanitizeQuery(query, queryType);
        let endpoint = "";

        if (queryType === "ip") endpoint = `https://otx.alienvault.com/api/v1/indicators/IPv4/${sanitized}/general`;
        else if (queryType === "domain") endpoint = `https://otx.alienvault.com/api/v1/indicators/domain/${sanitized}/general`;
        else if (queryType === "hash") endpoint = `https://otx.alienvault.com/api/v1/indicators/file/${sanitized}/general`;
        else endpoint = `https://otx.alienvault.com/api/v1/indicators/url/${encodeURIComponent(sanitized)}/general`;

        // A OTX morre por concorrência sem devolver 429: o gate segura o lote
        // em 4 chamadas em voo e o timeout impede que uma travada ocupe a vaga.
        const response = await cachedProvider(req, res, 'otx', sanitized, process.env.ALIENVAULT_API_KEY || '', () => otxThrottled(() => axios.get(endpoint, { headers, timeout: OTX_TIMEOUT_MS })));
        sendResponseWithQuota(res, response);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// Shodan — todas as chamadas passam pelo gate (~1 req/s por chave).
const shodanClient = shodanAxios(axios);

app.post('/api/shodan', scanLimiter, async (req, res) => {
    const { query } = req.body;
    if (!process.env.SHODAN_API_KEY) return res.status(500).json({ error: "API Key missing" });

    try {
        const queryType = detectQueryType(query);
        if (queryType !== "ip" && queryType !== "domain") return res.json({ data: { "Status": "IP/Domain only" } });

        const sanitized = sanitizeQuery(query, queryType);
        // Host lookup for IPs; DNS/subdomain enumeration for domains.
        const endpoint = queryType === "ip"
            ? `https://api.shodan.io/shodan/host/${sanitized}`
            : `https://api.shodan.io/dns/domain/${sanitized}`;
        const response = await cachedProvider(req, res, 'shodan', sanitized, process.env.SHODAN_API_KEY, () => shodanClient.get(endpoint, {
            params: { key: process.env.SHODAN_API_KEY }
        }));
        sendResponseWithQuota(res, response);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// abuse.ch usa UMA Auth-Key por conta, válida em MalwareBazaar, ThreatFox e
// URLhaus (e YARAify). Aceita uma env dedicada `ABUSE_CH_API_KEY` ou cai em
// qualquer uma das específicas — assim configurar uma só chave já liga todos os
// serviços abuse.ch. Desde 2024 a auth é obrigatória: sem chave, tudo dá 401.
const abuseChKey = (req) => {
    const session = req ? verifySession(getCookie(req, 'ts_session')) : null;
    return (getUserApiKey(session?.sub, 'abuse_ch') || process.env.ABUSE_CH_API_KEY || process.env.THREATFOX_API_KEY
        || process.env.URLHAUS_API_KEY || process.env.MALWAREBAZAAR_API_KEY || '').trim();
};

// URLhaus
app.post('/api/urlhaus', scanLimiter, async (req, res) => {
    const { query } = req.body;
    try {
        const queryType = detectQueryType(query);
        if (!["url", "domain", "hash"].includes(queryType)) {
            return res.status(400).json({ error: "URL, Domain or Hash query required" });
        }

        // Safe x-www-form-urlencoded formatting (VULN-08)
        const params = new URLSearchParams();
        let endpoint;
        if (queryType === "hash") {
            // Payload lookup: URLhaus indexes malware samples by MD5/SHA256
            // (SHA1 isn't supported by this endpoint).
            const sanitized = sanitizeQuery(query, 'hash');
            if (sanitized.length === 40) return res.json({ data: { "Status": "MD5/SHA256 only" } });
            params.append(sanitized.length === 32 ? 'md5_hash' : 'sha256_hash', sanitized);
            endpoint = `https://urlhaus-api.abuse.ch/v1/payload/`;
        } else {
            const sanitized = sanitizeQuery(query, queryType);
            params.append('host', sanitized);
            endpoint = `https://urlhaus-api.abuse.ch/v1/host/`;
        }

        // abuse.ch now requires an Auth-Key header on all URLhaus API queries.
        const headers = { "Content-Type": "application/x-www-form-urlencoded" };
        const abKey = abuseChKey(req);
        if (abKey) headers['Auth-Key'] = abKey;

        const response = await cachedProvider(req, res, 'urlhaus', params.toString(), abKey, () => axios.post(endpoint, params.toString(), { headers }));
        res.json(response.data);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// MalwareBazaar
app.post('/api/malwarebazaar', scanLimiter, async (req, res) => {
    const { query } = req.body;
    try {
        const queryType = detectQueryType(query);
        if (queryType !== "hash") return res.json({ data: { "Status": "Hash only" } });

        const sanitized = sanitizeQuery(query, 'hash');
        
        // Safe form-encoded encoding (VULN-08)
        const params = new URLSearchParams();
        params.append('query', 'get_info');
        params.append('hash', sanitized);

        // abuse.ch exige Auth-Key em todas as consultas (inclusive MalwareBazaar).
        const headers = { "Content-Type": "application/x-www-form-urlencoded" };
        const abKey = abuseChKey(req);
        if (abKey) headers["Auth-Key"] = abKey;

        const response = await cachedProvider(req, res, 'malwarebazaar', sanitized, abKey, () => axios.post(`https://mb-api.abuse.ch/api/v1/`,
            params.toString(),
            { headers }
        ));
        res.json(response.data);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// ThreatFox (abuse.ch) — IOC -> malware/threat attribution. Accepts ip, domain,
// url and hash. abuse.ch now requires an Auth-Key header on all queries.
app.post('/api/threatfox', scanLimiter, async (req, res) => {
    const { query } = req.body;
    try {
        const queryType = detectQueryType(query);
        if (!["ip", "domain", "url", "hash"].includes(queryType)) {
            return res.json({ data: { "Status": "IP/Domain/URL/Hash only" } });
        }
        const sanitized = sanitizeQuery(query, queryType);

        const headers = { "Content-Type": "application/json" };
        const abKey = abuseChKey(req);
        if (abKey) headers["Auth-Key"] = abKey;

        const response = await cachedProvider(req, res, 'threatfox', sanitized, abKey, () => axios.post(
            `https://threatfox-api.abuse.ch/api/v1/`,
            { query: "search_ioc", search_term: sanitized },
            { headers }
        ));
        // A busca segue por curinga (é o que casa `ip:porta` e URL do host),
        // mas o que não é o indicador consultado não sai daqui.
        res.json(filterExactIocs(response.data, sanitized));
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// PhishTank
app.post('/api/phishtank', scanLimiter, async (req, res) => {
    try {
        if (detectQueryType(req.body.query) !== 'url') return res.status(400).json({ error: 'URL query required' });
        const query = sanitizeQuery(req.body.query, 'url');
        const response = await cachedProvider(req, res, 'phishtank', query, process.env.PHISHTANK_API_KEY || '', async () => ({ data: await phishingSources.phishTank(query) }));
        res.json(response.data);
    } catch (error) { const { status, message } = sanitizeError(error); res.status(status).json({ error: message }); }
});

// PhishStats
app.post('/api/phishstats', scanLimiter, async (req, res) => {
    try {
        const type = detectQueryType(req.body.query);
        if (!['url', 'domain'].includes(type)) return res.status(400).json({ error: 'URL/Domain query required' });
        res.json(await phishingSources.phishStats(sanitizeQuery(req.body.query, type), { fresh: req.body?.fresh === true }));
    } catch (error) { const { status, message } = sanitizeError(error); res.status(status).json({ error: message }); }
});

// Ransomware.live
// A rota POST /api/ransomwarelive saiu junto com o vendor: ela devolvia o feed
// de vítimas recentes ignorando a consulta, e ninguém mais a chamava. Os dados
// continuam servidos por /api/intel/latam-threats e pelo mapa de ameaças, que
// usam a mesma getRecentRansomwareVictims() logo abaixo.

async function getRecentRansomwareVictims() {
    const now = Date.now();
    if (memoryCache.ransomwareVictims.data && memoryCache.ransomwareVictims.expiresAt > now) {
        return memoryCache.ransomwareVictims.data;
    }
    const request = ransomwareLiveRequestOptions(process.env.RANSOMWARE_LIVE_API_KEY);
    let response;
    let source = request.source;
    try {
        response = await axios.get(request.url, request.options);
    } catch (error) {
        if (!process.env.RANSOMWARE_LIVE_API_KEY) throw error;
        console.warn(`Ransomware.live Pro fetch failed: ${error.message}; falling back to public API`);
        const fallback = ransomwareLiveRequestOptions();
        source = fallback.source;
        response = await axios.get(fallback.url, fallback.options);
    }
    const victims = asArray(response.data).map((victim) => normalizeVictim(victim, source))
        .sort((a, b) => new Date(b.discovered || 0) - new Date(a.discovered || 0));
    memoryCache.ransomwareVictims.data = victims;
    memoryCache.ransomwareVictims.expiresAt = now + memoryCache.ransomwareVictims.ttl;
    return victims;
}

async function getRecentThreatFoxIocs(days = 7) {
    const now = Date.now();
    const safeDays = Math.max(1, Math.min(7, Number(days) || 7));
    if (memoryCache.threatFoxRecent.data && memoryCache.threatFoxRecent.expiresAt > now) {
        return memoryCache.threatFoxRecent.data;
    }
    const headers = { 'Content-Type': 'application/json' };
    const abKey = abuseChKey(req);
    if (abKey) headers['Auth-Key'] = abKey;
    const resp = await axios.post('https://threatfox-api.abuse.ch/api/v1/', {
        query: 'get_iocs',
        days: safeDays,
    }, { headers, timeout: 12000 });
    const iocs = asArray(resp.data).map((ioc) => ({
        id: ioc.id || ioc.ioc_id || '',
        value: ioc.ioc || ioc.value || '',
        type: ioc.ioc_type || ioc.threat_type || '',
        malware: ioc.malware_printable || ioc.malware || 'unknown',
        confidence: Number(ioc.confidence_level || 0),
        firstSeen: ioc.first_seen || null,
        lastSeen: ioc.last_seen || null,
        tags: Array.isArray(ioc.tags) ? ioc.tags : [],
        reporter: ioc.reporter || '',
        reference: ioc.reference || '',
        source: 'ThreatFox',
    })).filter((ioc) => ioc.value);
    memoryCache.threatFoxRecent.data = iocs;
    memoryCache.threatFoxRecent.expiresAt = now + memoryCache.threatFoxRecent.ttl;
    return iocs;
}

// Server-side sector pull (Pro only). Cached per sector so an 8-sector focus
// selection costs at most 8 upstream calls, and overlapping selections are free.
// Returns [] when there's no Pro key (the /victims/ filter is Pro-only) so focus
// mode degrades to the global recent feed instead of erroring.
async function getSectorVictims(sector) {
    const request = sectorVictimsRequestOptions(process.env.RANSOMWARE_LIVE_API_KEY, sector);
    if (!request) return [];
    const now = Date.now();
    const key = sector.toLowerCase();
    const cached = memoryCache.sectorVictims.store.get(key);
    if (cached && cached.expiresAt > now) return cached.data;
    try {
        const response = await axios.get(request.url, request.options);
        const victims = asArray(response.data).map((v) => normalizeVictim(v, 'ransomware.live Pro'));
        memoryCache.sectorVictims.store.set(key, { data: victims, expiresAt: now + memoryCache.sectorVictims.ttl });
        return victims;
    } catch (error) {
        console.warn(`Ransomware.live sector "${sector}" fetch failed: ${error.message}`);
        return cached?.data || [];
    }
}

// Fan out across the selected sectors and dedupe (a victim can be double-listed
// if a group re-posts). Falls back to the global recent feed when the Pro key is
// absent so the map is never empty.
async function getPriorityVictims(sectors) {
    const batches = await Promise.all(sectors.map((sector) => getSectorVictims(sector)));
    const flat = batches.flat();
    if (!flat.length) return getRecentRansomwareVictims();
    const seen = new Map();
    for (const victim of flat) {
        const id = victim.id || `${victim.name}@@${victim.group}@@${victim.discovered || victim.published || ''}`;
        if (!seen.has(id)) seen.set(id, victim);
    }
    return [...seen.values()];
}

async function getSectorList() {
    const request = sectorListRequestOptions(process.env.RANSOMWARE_LIVE_API_KEY);
    if (!request) return [];
    const now = Date.now();
    if (memoryCache.sectorList.data && memoryCache.sectorList.expiresAt > now) return memoryCache.sectorList.data;
    const response = await axios.get(request.url, request.options);
    // /listsectors shape varies (array of {sector,count} or a {sector:count} map);
    // normalize to [{ name, count }] sorted by name.
    const raw = response.data;
    const list = Array.isArray(raw)
        ? raw.map((s) => ({ name: String(s.sector ?? s.name ?? s).trim(), count: Number(s.count ?? s.victims ?? 0) }))
        : Object.entries(raw || {}).map(([name, count]) => ({ name: String(name).trim(), count: Number(count) || 0 }));
    const sectors = list.filter((s) => s.name).sort((a, b) => a.name.localeCompare(b.name));
    memoryCache.sectorList.data = sectors;
    memoryCache.sectorList.expiresAt = now + memoryCache.sectorList.ttl;
    return sectors;
}

const parseCsvParam = (value) => String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);

app.get('/api/intel/threat-map', async (req, res) => {
    try {
        const days = Math.max(1, Math.min(30, Number(req.query.days) || 3));
        const sectors = parseCsvParam(req.query.sectors);
        const regions = parseCsvParam(req.query.regions).filter((key) => REGIONS[key]);
        const focus = sectors.length > 0;

        const rawVictims = focus ? await getPriorityVictims(sectors) : await getRecentRansomwareVictims();
        const victims = focus ? filterByRegions(rawVictims, regions) : rawVictims;
        const source = victims.some((victim) => victim.source === 'ransomware.live Pro')
            ? 'ransomware.live Pro'
            : 'ransomware.live';
        res.json(buildThreatMapResponse(victims, {
            generatedAt: new Date().toISOString(),
            days,
            source,
        }));
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// Sector names (for the picker) + the fixed region catalog the focus map accepts.
app.get('/api/intel/sectors', async (_req, res) => {
    try {
        const sectors = await getSectorList().catch((err) => {
            console.warn(`Ransomware.live sector list fetch failed: ${err.message}`);
            return [];
        });
        res.json({
            sectors,
            regions: Object.entries(REGIONS).map(([key, region]) => ({ key, label: region.label })),
            defaultRegions: DEFAULT_FOCUS_REGIONS,
        });
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.get('/api/intel/latam-threats', async (req, res) => {
    try {
        const [victims, iocs] = await Promise.all([
            getRecentRansomwareVictims(),
            getRecentThreatFoxIocs(7).catch((err) => {
                console.warn(`ThreatFox recent IOC fetch failed: ${err.message}`);
                return [];
            }),
        ]);
        const latamVictims = victims.filter((v) => LATAM_COUNTRIES.has(v.country));
        res.json({
            generatedAt: new Date().toISOString(),
            sources: ['ransomware.live', 'ThreatFox'],
            victims: latamVictims.slice(0, 80),
            groups: countBy(latamVictims, (v) => v.group).slice(0, 12),
            sectors: countBy(latamVictims, (v) => v.sector).slice(0, 12),
            countries: countBy(latamVictims, (v) => v.country).map((c) => ({ ...c, countryName: COUNTRY_NAMES[c.name] || c.name })),
            threatFox: {
                count: iocs.length,
                malware: countBy(iocs, (i) => i.malware).slice(0, 10),
                iocs: iocs.slice(0, 30),
            },
        });
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// WHOIS — Who.is snapshot lookup (no paid live refresh).
const lookupWhois = createWhoisLookup({ http: axios, getKey: () => process.env.WHOIS_API_KEY });
const DOMAIN_DNS_HISTORY_PATH = path.join(__dirname, '.domain-dns-history.json');
const domainIntelligence = createDomainIntelligence({ http: axios, getWhoisKey: () => process.env.WHOIS_API_KEY,
    readObservations: () => JSON.parse(fs.readFileSync(DOMAIN_DNS_HISTORY_PATH, 'utf8')),
    saveObservations: data => writeJsonAtomic(DOMAIN_DNS_HISTORY_PATH, data),
});
app.post('/api/domain/:view', requirePremium, scanLimiter, async (req, res) => {
    const methods = { subdomains: 'subdomains', certificates: 'certificates', history: 'history' };
    if (!Object.hasOwn(methods, req.params.view)) return res.status(404).json({ error: 'Unknown domain view' });
    const method = methods[req.params.view];
    try {
        const { hostname } = domainTarget(req.body?.query);
        res.set('Cache-Control', 'private, no-store');
        res.json(await domainIntelligence[method](hostname, req.body.cursor || ''));
    } catch { res.status(400).json({ error: 'Invalid domain or cursor' }); }
});
app.post('/api/whois', scanLimiter, async (req, res) => {
    try {
        if (detectQueryType(req.body.query) !== 'domain') return res.status(400).json({ error: 'Domain query required' });
        res.json(await lookupWhois(sanitizeQuery(req.body.query, 'domain'), { fresh: req.body?.fresh === true }));
    } catch (error) { const { status, message } = sanitizeError(error); res.status(status).json({ error: message }); }
});

// IP Geolocation (Mitigated HTTP/No TLS)
app.post('/api/ipgeo', scanLimiter, async (req, res) => {
    const { query } = req.body;
    try {
        const queryType = detectQueryType(query);
        if (queryType !== "ip") return res.json({ data: { "Status": "IP only" } });

        const sanitized = sanitizeQuery(query, 'ip');

        // VULN-12: Use HTTPS geolocation api (ipwhois.app instead of HTTP ip-api.com)
        const response = await cachedProvider(req, res, 'ipgeo', sanitized, '', () => axios.get(`https://ipwhois.app/json/${sanitized}`));
        const data = response.data;
        
        let reverseHostname = "Unknown";
        try {
            const hostnames = await dns.promises.reverse(sanitized);
            if (hostnames && hostnames.length > 0) {
                reverseHostname = hostnames[0];
            }
        } catch (dnsErr) {
            // VULN-17: Avoid logging client IP addresses directly
            console.log(`Reverse DNS lookup failed:`, dnsErr.message);
        }

        const mappedData = {
            status: data.success ? "success" : "fail",
            country: data.country,
            countryCode: data.country_code,
            regionName: data.region,
            city: data.city,
            timezone: data.timezone,
            isp: data.isp,
            org: data.org,
            as: data.asn,
            // ipwhois.app free returns no proxy/hosting/mobile signal — leave them
            // undefined so the UI shows "Unknown", not a fabricated "No".
            lat: parseFloat(data.latitude || 0),
            lon: parseFloat(data.longitude || 0),
            reverseHostname
        };

        res.json(mappedData);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// OpenPhish
const phishingSources = createPhishingSources({ http: axios, getKey: provider => provider === 'phishstats' ? process.env.PHISHSTATS_API_KEY : process.env.PHISHTANK_API_KEY });
app.get('/api/vendors/activity', (req, res) => {
    res.set('Cache-Control', 'private, no-store');
    res.json(phishingSources.activity());
});
app.post('/api/openphish', scanLimiter, async (req, res) => {
    try {
        const type = detectQueryType(req.body.query);
        if (!['url', 'domain'].includes(type)) return res.status(400).json({ error: 'URL/Domain query required' });
        res.json(await phishingSources.openPhish(sanitizeQuery(req.body.query, type), type, { fresh: req.body?.fresh === true }));
    } catch (error) { const { status, message } = sanitizeError(error); res.status(status).json({ error: message }); }
});

// CTI & CVE Newsletter and CVE Dashboard Endpoints


// Helper to decode HTML/XML entities

// Insert into a Map-backed cache with a hard size cap, evicting the oldest
// entries (insertion order) so these in-memory stores can't grow unbounded.
function cacheSet(store, key, value, max) {
    store.set(key, value);
    if (store.size > max) {
        const excess = store.size - max;
        let i = 0;
        for (const k of store.keys()) {
            if (i++ >= excess) break;
            store.delete(k);
        }
    }
}

// Simple in-memory cache for external feeds & APIs
const memoryCache = {
    newsletter: {
        data: null,
        expiresAt: 0,
        ttl: 10 * 60 * 1000 // 10 minutes
    },
    // LLM-generated actionable analysis per advisory, keyed by `${lang}|${url}`
    newsletterEnrich: {
        store: new Map(),
        ttl: 7 * 24 * 60 * 60 * 1000 // 7 days
    },
    recentCves: {
        data: null,
        expiresAt: 0,
        ttl: 10 * 60 * 1000 // 10 minutes
    },
    exploitedCves: {
        data: null,
        expiresAt: 0,
        ttl: 12 * 60 * 60 * 1000 // 12 hours
    },
    // Full CISA KEV catalog: raw vulnerabilities array (shared source) plus a
    // derived Map<CVE, details> for advisory correlation.
    kev: {
        raw: null,
        map: null,
        expiresAt: 0,
        ttl: 12 * 60 * 60 * 1000 // 12 hours
    },
    patchTuesdayMonths: {
        data: null,
        expiresAt: 0,
        // Doubles as the background refresh interval. The month list is a small
        // document and is what detects a new Patch Tuesday (and the draft ->
        // release swap), so this bounds how long a stale month can be served.
        ttl: 60 * 60 * 1000 // 1 hour
    },
    // Per-month normalized Patch Tuesday summaries, keyed by id (e.g. "2026-Jun")
    patchTuesday: {
        store: new Map(),
        ttl: 24 * 60 * 60 * 1000 // 24 hours
    },
    // Latest SAP Security Patch Day (monthly), scraped from support.sap.com.
    sapPatch: {
        data: null,
        expiresAt: 0,
        ttl: 24 * 60 * 60 * 1000 // 24 hours (Patch Day is monthly)
    },
    ransomwareVictims: {
        data: null,
        expiresAt: 0,
        ttl: 15 * 60 * 1000 // 15 minutes
    },
    threatFoxRecent: {
        data: null,
        expiresAt: 0,
        ttl: 30 * 60 * 1000 // 30 minutes
    },
    // Server-side sector-filtered victim pulls (Pro /victims/?sector=), keyed by
    // lowercased sector name so different focus selections reuse each other's data.
    sectorVictims: {
        store: new Map(), // sector -> { data, expiresAt }
        ttl: 30 * 60 * 1000 // 30 minutes
    },
    // Pro /listsectors — sector names + counts for the UI picker.
    sectorList: {
        data: null,
        expiresAt: 0,
        ttl: 6 * 60 * 60 * 1000 // 6 hours (the taxonomy barely changes)
    }
};

// Full CISA KEV catalog as Map<CVE, {dateAdded,dueDate,ransomware,...}>, cached
// 12h. Used to flag advisories whose CVEs are KNOWN-EXPLOITED in the wild.
// Single source of truth for the CISA KEV catalog. Fetches the raw
// vulnerabilities array at most once per TTL; both getKevMap() (advisory
// correlation) and /api/cves/exploited (dashboard) derive from this, so the
// catalog is no longer fetched twice. Degrades to the last good data on error.
async function getKevCatalog() {
    const now = Date.now();
    if (memoryCache.kev.raw && memoryCache.kev.expiresAt > now) return memoryCache.kev.raw;
    try {
        const resp = await axios.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { timeout: 10000 });
        const raw = Array.isArray(resp.data?.vulnerabilities) ? resp.data.vulnerabilities : [];
        memoryCache.kev.raw = raw;
        memoryCache.kev.map = null; // invalidate derived map so it rebuilds from fresh data
        memoryCache.kev.expiresAt = now + memoryCache.kev.ttl;
        return raw;
    } catch (err) {
        console.warn(`KEV catalog fetch failed: ${err.message}`);
        return memoryCache.kev.raw || [];
    }
}

async function getKevMap() {
    // Refresh the catalog first; getKevCatalog() nulls the derived map when the
    // underlying data is refetched, so a stale map can't be returned here.
    const raw = await getKevCatalog();
    if (memoryCache.kev.map) return memoryCache.kev.map;
    const map = new Map();
    for (const v of raw) {
        if (!v.cveID) continue;
        map.set(v.cveID.toUpperCase(), {
            dateAdded: v.dateAdded,
            dueDate: v.dueDate,
            ransomware: /known/i.test(v.knownRansomwareCampaignUse || ''),
            vendor: v.vendorProject,
            product: v.product,
        });
    }
    memoryCache.kev.map = map;
    return map;
}

// FIRST.org EPSS scores (probability a CVE is exploited in the next 30 days) for
// a set of CVEs. Returns Map<CVE, number(0-1)>. Batched; failures degrade to {}.
async function getEpssMap(cveIds) {
    const map = new Map();
    const ids = [...new Set(cveIds)].filter(Boolean);
    for (let i = 0; i < ids.length; i += 100) {
        const chunk = ids.slice(i, i + 100);
        try {
            const resp = await axios.get('https://api.first.org/data/v1/epss', {
                params: { cve: chunk.join(',') },
                timeout: 8000,
            });
            for (const r of (resp.data?.data || [])) {
                const v = parseFloat(r.epss);
                if (r.cve && !Number.isNaN(v)) map.set(r.cve.toUpperCase(), v);
            }
        } catch (err) {
            console.warn(`EPSS fetch failed: ${err.message}`);
        }
    }
    return map;
}

// ─── Catálogo de feeds RSS (base estática + overrides em disco) ────────────
// CTI_FEEDS é o catálogo built-in. Os overrides ficam num JSON flat (como os
// stores de users/jobs): { disabled: [url…], custom: [{url, source, layer,
// weight_boost}] }. Assim o dono liga/desliga fontes e adiciona novas sem
// mexer no código nem redeployar.
const FEED_SOURCES_PATH = path.join(__dirname, '.feed-sources.json');
const BUILTIN_FEEDS = [...CTI_FEEDS, ...PUBLICATION_SOURCES, ...OT_PUBLICATION_SOURCES, ...REPOSITORY_SOURCES];
function loadFeedOverrides() {
    try {
        const o = JSON.parse(fs.readFileSync(FEED_SOURCES_PATH, 'utf8'));
        return { disabled: Array.isArray(o.disabled) ? o.disabled : [],
                 custom: Array.isArray(o.custom) ? o.custom : [] };
    } catch { return { disabled: [], custom: [] }; }
}
function saveFeedOverrides() {
    try { writeJsonAtomic(FEED_SOURCES_PATH, feedOverrides); }
    catch (e) { console.error('feed sources write failed:', e.message); }
}
let feedOverrides = loadFeedOverrides();

// Saúde por feed, preenchida a cada refresh: { ok, count, error, at }. Deixa a
// UI mostrar quais fontes responderam e quantos itens trouxeram.
const feedHealth = new Map();

// Catálogo efetivo p/ a UI: built-ins + custom, cada um marcado com `builtin`
// (built-in só pode ser desativado, nunca deletado) e `enabled`.
function catalogFeeds() {
    const disabled = new Set(feedOverrides.disabled);
    const builtins = BUILTIN_FEEDS.map((f) => ({ ...f, builtin: true, enabled: !disabled.has(f.url) }));
    const custom = feedOverrides.custom.map((f) => ({ ...f, builtin: false, enabled: !disabled.has(f.url) }));
    return [...builtins, ...custom];
}
// Só os feeds ligados — é o que o coletor realmente busca.
function effectiveFeeds() {
    return catalogFeeds().filter((f) => f.enabled);
}

// Uma falha passageira de rede (timeout, 5xx) costuma se resolver sozinha —
// tentar de novo com um respiro curto evita que ela custe o ciclo de refresh
// inteiro, já que o próximo só vem horas depois. Uma fonte realmente fora do
// ar ainda acaba marcada como falha em feedHealth, só que depois destas
// tentativas em vez de uma.
const FEED_FETCH_RETRIES = 3;
const FEED_RETRY_BACKOFF_MS = [1000, 3000];
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function fetchFeedWithRetry(url, options) {
    for (let attempt = 0; attempt < FEED_FETCH_RETRIES; attempt++) {
        try {
            return await axios.get(url, options);
        } catch (err) {
            // Um 404, uma falha de DNS ou um bloqueio de WAF vão parecer
            // idênticos na próxima tentativa — só vale esperar e tentar de novo
            // quando o erro é do tipo que pode mesmo se resolver sozinho.
            const isLastAttempt = attempt === FEED_FETCH_RETRIES - 1;
            if (isLastAttempt || !isTransientFeedError(err)) throw err;
            await sleep(FEED_RETRY_BACKOFF_MS[attempt]);
        }
    }
}

// Background newsletter feed refresher
const rssCollectionCache = createFeedCache({ directory: path.join(__dirname, '.feed-cache', 'rss'), fs, writeJsonAtomic });
const articleCollectionCache = createFeedCache({ directory: path.join(__dirname, '.feed-cache', 'articles'), fs, writeJsonAtomic });
// Reclassify metadata only; preserve publications and reuse existing body
// caches without issuing hundreds of historical requests on startup.
if (process.env.NODE_ENV !== 'test') try {
    newsArchiveStore.reclassifyPhishing({ bodyFor: link => articleCollectionCache.get(link)?.text || '' });
} catch (error) { console.error('phishing archive reclassification failed:', error.message); }
const previousFeedSnapshot = rssCollectionCache.get('newsletter:snapshot');
if (previousFeedSnapshot?.extractionVersion === EXTRACTION_VERSION && Array.isArray(previousFeedSnapshot.items)) {
    const enabled = new Set([...effectiveFeeds().map((feed) => feed.url), ...SCRAPE_SOURCES.filter((source) => !feedOverrides.disabled.includes(source.url)).map((source) => source.url)]);
    memoryCache.newsletter.data = previousFeedSnapshot.items.filter((item) => enabled.has(item.feedUrl) && new Date(item.pubDate).getTime() >= Date.now() - 30 * 86400000)
        .map((item) => ({ ...item, collectionStatus: 'stale' }));
}
const publicationRequest = createPublicationRequest();
const publicationResolver = createPublicationResolver({ request: publicationRequest });
const repositoryResolver = createRepositoryResolver({ request: publicationRequest });
const feedCollector = createFeedCollector({
    cache: rssCollectionCache, parse: parseFeed,
    resolve: (feed, previous, options) => feed.kind === 'github' ? repositoryResolver(feed, previous, options) : publicationResolver(feed, previous, options),
    onHealth: (url, health) => feedHealth.set(url, health),
    concurrency: Number(process.env.FEED_FETCH_CONCURRENCY) || 6,
    request: (url, { headers }) => fetchFeedWithRetry(url, {
        headers: { 'User-Agent': 'ThreatSumm4ry/1.0 RSS collector', Accept: 'application/rss+xml,application/atom+xml,application/xml,text/xml', ...headers },
        timeout: 8000, responseType: 'text', maxContentLength: 8000000, maxRedirects: 3,
        validateStatus: (status) => (status >= 200 && status < 300) || status === 304,
    }),
});

const refreshNewsletterFeed = singleFlightRefresh(async () => {
    const startedAt = Date.now();
    try {
        const collected = await feedCollector.collect(effectiveFeeds());
        for (const [url, health] of collected.health) feedHealth.set(url, health);
        let scraped = [];
        const sources = SCRAPE_SOURCES.filter((source) => !feedOverrides.disabled.includes(source.url));
        try {
            const result = await collectScraped({
                sources, seen: scrapeSeen, now: new Date(), maxNew: 10,
                fetchText: async (url) => (await fetchFeedWithRetry(url, { headers: { 'User-Agent': BROWSER_UA }, timeout: 8000, maxContentLength: 2000000 })).data,
            });
            // Keep each scraper's last successful publications if it is offline.
            for (const source of sources) {
                const failure = result.errors.find((error) => error.source === source.source);
                const cached = rssCollectionCache.get(source.url);
                const current = result.items.filter((item) => item.source === source.source);
                const cutoff = Date.now() - 30 * 86400000;
                const old = (cached?.items || []).filter((item) => new Date(item.pubDate).getTime() >= cutoff);
                const byLink = new Map(old.map((item) => [item.link, item]));
                for (const item of current) byLink.set(item.link, item);
                const items = [...byLink.values()].sort((a, b) => String(b.pubDate).localeCompare(String(a.pubDate))).slice(0, 100);
                const lastSuccessfulAt = failure ? cached?.lastSuccessfulAt || null : new Date().toISOString();
                if (!failure) rssCollectionCache.set(source.url, { version: 1, items, lastSuccessfulAt });
                scraped.push(...items.map((item) => ({ ...item, feedUrl: source.url, collectionStatus: failure ? 'stale' : 'fresh' })));
                feedHealth.set(source.url, { ok: !failure, count: items.length, fetchedCount: current.length, status: failure ? 'stale' : 'fresh', error: failure?.message || null, lastSuccessfulAt, at: new Date().toISOString() });
            }
            scrapeSeen = Object.fromEntries(Object.entries(result.seen).sort((a, b) => String(b[1]).localeCompare(String(a[1]))).slice(0, 2000));
            writeJsonAtomic(SCRAPE_SEEN_PATH, scrapeSeen);
        } catch (error) { console.error('scraped sources failed:', error.message); }

        const byUrl = new Map();
        for (const item of [...collected.items, ...scraped]) {
            const link = canonicalArticleUrl(item.link);
            if (!link) continue;
            const old = byUrl.get(link);
            if (!old || (old.collectionStatus === 'stale' && item.collectionStatus !== 'stale') || (old.collectionStatus === item.collectionStatus && (item.text || '').length > (old.text || '').length)) byUrl.set(link, { ...item, link });
        }
        // Do not collapse publications by vendor/date before correlation: every
        // advisory and its own CVEs/evidence must survive into the event store.
        const rawItems = [...byUrl.values()];
        const bodies = await collectArticleTexts(rawItems, {
            cache: articleCollectionCache,
            maxFetches: process.env.NEWS_ARTICLE_MAX_FETCHES === undefined ? 40 : Number(process.env.NEWS_ARTICLE_MAX_FETCHES),
            concurrency: Number(process.env.NEWS_IOC_CONCURRENCY) || 3,
            fetchText: async (url) => (await fetchArticleText(url, 32000)).text,
        });
        let unifiedFeed = await enrichFeedItemsAsync(rawItems, {
            texts: bodies.texts, actors: (text) => matchActors(text, actorIndex),
            malware: (text) => matchMalware(text, malwareIndex), campaigns: (text) => matchCampaigns(text, campaignIndex),
            seller: extractSellerHandle, categorize,
        });
        const allCves = [...new Set(unifiedFeed.flatMap((item) => item.cves))];
        const [kevMap, epssMap] = await Promise.all([getKevMap(), getEpssMap(allCves)]);
        applyVulnerabilityContext(unifiedFeed, kevMap, epssMap);
        unifiedFeed.sort((a, b) => b.pubDate.localeCompare(a.pubDate) || a.link.localeCompare(b.link));
        const correlation = await correlateNewsFeedAsync(unifiedFeed, newsStoryStore);
        unifiedFeed = correlation.items;
        try {
            newsArchiveStore.add(unifiedFeed.map((item) => ({ ...item, categories: item.newsCategories })));
        } catch (error) { console.error('news archive update failed:', error.message); }

        // Raw RSS and collected article text remain in the disk caches. The
        // public feed only carries metadata, hashes and extracted evidence.
        for (const item of unifiedFeed) delete item.text;
        rssCollectionCache.set('newsletter:snapshot', { extractionVersion: EXTRACTION_VERSION, at: new Date().toISOString(), items: unifiedFeed });
        memoryCache.newsletter.data = unifiedFeed;
        memoryCache.newsletter.expiresAt = Date.now() + memoryCache.newsletter.ttl;
        try { rssCollectionCache.prune({ maxEntries: Math.max(600, effectiveFeeds().length * 3 + 50) }); articleCollectionCache.prune({ maxEntries: 1500 }); } catch (error) { console.warn('feed cache pruning failed:', error.message); }
        console.log('[feed] cycle', JSON.stringify({ elapsedMs: Date.now() - startedAt, sources: collected.health.size, failedSources: [...collected.health.values()].filter((health) => !health.ok).length, articles: unifiedFeed.length, bodies: bodies.stats, correlation: correlation.stats }));
    } catch (error) { console.error('Failed to background refresh newsletter feeds:', error.message); }
});

// CTI News feed endpoint.
app.get('/api/news/monitoring', requireAuth, (req, res) => {
    res.set('Cache-Control', 'private, no-store');
    res.json({ vendors: VENDOR_CATALOG, preferences: newsMonitoringStore.get(req.user.sub) });
});

app.put('/api/news/monitoring', requireAuth, (req, res) => {
    try {
        const preferences = newsMonitoringStore.set(req.user.sub, req.body);
        res.set('Cache-Control', 'private, no-store');
        res.json({ preferences });
    } catch (error) {
        res.status(error.status || 500).json({ error: error.status === 400 ? error.message : 'Não foi possível salvar o monitoramento.' });
    }
});

// Optional query params: minScore (0-100), severity (Critical|High|Medium|Low),
// category (substring of a category label), layer (1-4), sort (relevance|date).
app.get('/api/newsletter', requirePremium, async (req, res) => {
    try {
        if (!memoryCache.newsletter.data) {
            // Cold start fallback
            await refreshNewsletterFeed();
        }
        if (!memoryCache.newsletter.data) return res.status(503).set('Retry-After', '60').json({ error: 'News feed is not available yet' });
        let data = filterMonitoredNews(memoryCache.newsletter.data || [], newsMonitoringStore.get(req.user.sub), newsStoryStore.all());

        const minScore = parseInt(req.query.minScore, 10);
        const severity = (req.query.severity || '').toString();
        const category = (req.query.category || '').toString().toLowerCase();
        const layer = parseInt(req.query.layer, 10);
        const sort = (req.query.sort || 'date').toString();

        if (!Number.isNaN(minScore)) data = data.filter((i) => (i.score || 0) >= minScore);
        if (severity) data = data.filter((i) => i.severity === severity);
        if (layer) data = data.filter((i) => i.layer === layer);
        if (category) data = data.filter((i) => (i.categories || []).some((c) => c.toLowerCase().includes(category)));

        if (sort === 'relevance') {
            data = [...data].sort((a, b) => (b.score || 0) - (a.score || 0) || new Date(b.pubDate) - new Date(a.pubDate));
        }

        res.set('Cache-Control', 'private, no-store');
        res.json(data);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// Histórias: o mesmo feed agrupado por assunto, com a linha do tempo de fontes.
//   GET /api/news/stories?category=Ransomware&actor=<id>&days=30&limit=50
app.get('/api/news/stories', requirePremium, async (req, res) => {
    try {
        if (!memoryCache.newsletter.data) await refreshNewsletterFeed();
        res.set('Cache-Control', 'private, no-store');
        const stories = newsStoryStore.list({
            category: (req.query.category || '').toString() || undefined,
            actor: (req.query.actor || '').toString() || undefined,
            days: parseInt(req.query.days, 10) || undefined,
        });
        res.json(filterMonitoredStories(stories, newsMonitoringStore.get(req.user.sub))
            .slice(0, Math.max(1, Math.min(parseInt(req.query.limit, 10) || 200, 500))));
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// Arquivo permanente do feed (link, título, fonte, data, categorias) — nunca
// podado, ao contrário de /api/news/stories (60 dias). Alimenta o dashboard
// de tendências de phishing e a exportação em /phishing-analyzer, mas serve
// qualquer categoria, não só Phishing.
//   GET /api/news/archive?category=Phishing&from=2026-08-01&to=2026-10-08
const phishingTechniqueCatalog = JSON.parse(fs.readFileSync(new URL('./data/attack.json', import.meta.url), 'utf8')).techniques;
app.get('/api/phishing/reports', requirePremium, (req, res) => {
    try {
        const options = phishingQuery(req.query);
        if (options.filters.profileId) orgProfileStore.get(req.user.sub, options.filters.profileId);
        const rows = newsArchiveStore.list({
            from: options.range.from,
            to: options.range.to ? `${options.range.to}T23:59:59.999Z` : undefined,
        });
        res.set('Cache-Control', 'private, no-store');
        res.json(buildPhishingDataset(rows, { ...options, profiles: orgProfileStore.list(req.user.sub), techniqueCatalog: phishingTechniqueCatalog }));
    } catch (error) {
        if (error.status && error.publicMessage) return res.status(error.status).json({ error: error.publicMessage });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.get('/api/news/archive', requirePremium, (req, res) => {
    try {
        res.set('Cache-Control', 'private, max-age=300');
        res.json({
            total: newsArchiveStore.size(),
            rows: newsArchiveStore.list({
                category: (req.query.category || '').toString() || undefined,
                source: (req.query.source || '').toString() || undefined,
                from: (req.query.from || '').toString() || undefined,
                to: (req.query.to || '').toString() || undefined,
                limit: Math.min(parseInt(req.query.limit, 10) || 5000, 20000),
            }),
        });
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.get('/api/news/export', requirePremium, (req, res) => {
    try {
        const options = newsExportQuery(req.query);
        // Export the permanent archive, without the live feed's retention or UI pagination.
        const publications = filterMonitoredNews(newsArchiveStore.list(options), newsMonitoringStore.get(req.user.sub), newsStoryStore.all());
        const rows = newsExportRows(publications, options.dataset);
        const filename = `threatsumm4ry-${options.dataset}-${options.from.slice(0, 10)}-${options.to.slice(0, 10)}.${options.format}`;
        res.set('Cache-Control', 'private, no-store');
        res.set('Content-Disposition', `attachment; filename="${filename}"`);
        if (options.format === 'csv') return res.type('text/csv; charset=utf-8').send(newsExportCsv(rows, options.dataset));
        res.json({ generatedAt: new Date().toISOString(), range: { from: options.from, to: options.to }, dataset: options.dataset, publications: publications.length, count: rows.length, rows });
    } catch (error) {
        res.status(error.status || 500).json({ error: error.status === 400 ? error.message : 'Não foi possível exportar o histórico.' });
    }
});

// Quem já mencionou este indicador. Alimenta o Enriquecimento: o achado que
// interessa não é "o IP existe", é "saiu no Unit 42, atribuído ao FunkSec".
// requirePremium igual às outras rotas de notícia — é o mesmo acervo.
//   GET /api/news/mentions?ioc=212.193.31.119
app.get('/api/news/mentions', requirePremium, async (req, res) => {
    const ioc = (req.query.ioc || '').toString().trim();
    if (!ioc || ioc.length > 2048) return res.status(400).json({ error: 'ioc required' });
    try {
        if (!memoryCache.newsletter.data) await refreshNewsletterFeed();
        res.set('Cache-Control', 'private, max-age=300');
        res.json({ ioc, mentions: findMentions(newsStoryStore.all(), ioc) });
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.get('/api/news/domain-mentions', requirePremium, (req, res) => {
    try {
        const { hostname } = domainTarget(req.query.domain);
        res.set('Cache-Control', 'private, no-store');
        res.json({ domain: hostname, mentions: findDomainMentions(newsStoryStore.all(), hostname) });
    } catch { res.status(400).json({ error: 'Invalid domain' }); }
});

app.get('/api/news/stories/:id', requirePremium, (req, res) => {
    const story = newsStoryStore.get(String(req.params.id));
    if (!story) return res.status(404).json({ error: 'story not found' });
    res.set('Cache-Control', 'public, max-age=300');
    const sellerHandle = storySellerHandle(story);
    res.json({
        ...story,
        correlationEvidence: explainCorrelation(story),
        correlationDecisions: explainCorrelationDecisions(story),
        // Relacionado, não fundido: outra história do mesmo vendedor de dark
        // web é informação real, mas vítimas diferentes não são a mesma
        // notícia (ver darkWebHandle.js).
        relatedBySeller: sellerHandle ? findRelatedBySeller(newsStoryStore.all(), sellerHandle, story.id) : [],
    });
});

// ─── Feed Generator · sugestões do boletim diário ─────────────────────────
// Fase 1: itens CTI do dia, vindos do feed unificado (já pontuado/deduplicado),
// servidos como *sugestões* para a curadoria do boletim diário — o analista
// escolhe quais viram boletim. Read-only; reaproveita o cache da newsletter.
//   GET /api/feed/daily-suggestions?hours=36&limit=10&minScore=0
app.get('/api/feed/daily-suggestions', requirePremium, async (req, res) => {
    try {
        if (!memoryCache.newsletter.data) await refreshNewsletterFeed();
        const all = filterMonitoredNews(memoryCache.newsletter.data || [], newsMonitoringStore.get(req.user.sub), newsStoryStore.all());

        const hours = Math.min(Math.max(parseInt(req.query.hours, 10) || 36, 1), 168);
        const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 10, 1), 50);
        const minScore = parseInt(req.query.minScore, 10);
        const cutoff = Date.now() - hours * 60 * 60 * 1000;

        let items = all.filter((i) => {
            const t = new Date(i.pubDate).getTime();
            return Number.isFinite(t) && t >= cutoff && (i.link || '').startsWith('http');
        });
        if (!Number.isNaN(minScore)) items = items.filter((i) => (i.score || 0) >= minScore);

        // Maior relevância primeiro; itens em CISA KEV já sobem via score.
        items.sort((a, b) => (b.score || 0) - (a.score || 0) || new Date(b.pubDate) - new Date(a.pubDate));

        const suggestions = items.slice(0, limit).map((i) => ({
            title: i.title,
            url: i.link,
            source: i.source,
            pubDate: i.pubDate,
            score: i.score || 0,
            severity: i.severity || 'Low',
            cves: i.cves || [],
            kev: !!i.kev,
            reasons: i.reasons || [],
            // tipo de deck sugerido: advisory com CVE tende a "vuln", senão "campaign".
            suggestedType: (i.cves && i.cves.length) ? 'vuln' : 'campaign',
        }));

        res.set('Cache-Control', 'private, no-store');
        res.json({
            generatedAt: new Date().toISOString(),
            windowHours: hours,
            count: suggestions.length,
            suggestions,
        });
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

const OPENROUTER_DAILY_MODEL = process.env.OPENROUTER_DAILY_MODEL || 'openrouter/free';

async function requestDailyNarrative(events, date) {
    if (!process.env.OPENROUTER_API_KEY) throw new Error('OpenRouter is not configured');
    const facts = events.map((event) => ({
        id: event.id,
        title: event.titlePt || event.title,
        source: event.source,
        timestamp: event.timestamp,
        priority: event.priority,
        category: event.category,
        severity: event.severity,
        cves: event.cves,
        kev: event.kev,
        group: event.group,
        countryName: event.countryName,
        sector: event.sector,
    }));
    const response = await axios.post('https://openrouter.ai/api/v1/chat/completions', {
        model: OPENROUTER_DAILY_MODEL,
        temperature: 0.1,
        response_format: { type: 'json_object' },
        messages: [
            {
                role: 'system',
                content: 'Voce e um analista senior de CTI. Responda somente JSON em portugues do Brasil com title, summary (3 a 5 fatos) e attentionTopics (2 a 4 temas com title, assessment, recommendedAction opcional e eventIds). Use apenas os fatos e identificadores fornecidos. '
                    // Quem publica o boletim ja monitora o ambiente do leitor: devolver
                    // esse trabalho pra ele como "recomendacao" cobra do cliente o
                    // servico que ele contratou. O time nao e nomeado de proposito.
                    + 'Em recommendedAction, nunca recomende acoes que ja sao servico do time de CTI que publica este boletim: monitorar o ambiente, verificar logs, criar casos de uso de deteccao ou buscar IOCs no ambiente. '
                    + 'recommendedAction e sempre acao do lado do leitor: aplicar correcao, priorizar por severidade, restringir exposicao, rotacionar credencial, inventariar ativo afetado.',
            },
            { role: 'user', content: JSON.stringify({ date, events: facts }) },
        ],
    }, {
        headers: {
            Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}`,
            'Content-Type': 'application/json',
            'HTTP-Referer': process.env.APP_BASE_URL || 'https://threatsumm4ry.app',
            'X-OpenRouter-Title': 'ThreatSumm4ry Daily',
        },
        timeout: 30000,
    });
    const content = response.data?.choices?.[0]?.message?.content;
    if (typeof content !== 'string' || !content.trim()) throw new Error('OpenRouter returned no content');
    return JSON.parse(content);
}

const dailyEditionGenerator = createEditionGenerator({
    store: dailyEditionStore,
    requestNarrative: requestDailyNarrative,
    getSourceData: async () => {
        if (!memoryCache.newsletter.data) await refreshNewsletterFeed();
        return {
            feed: memoryCache.newsletter.data || [],
            victims: await getRecentRansomwareVictims().catch(() => []),
        };
    },
});

app.get('/api/intel/daily-brief', async (req, res) => {
    try {
        const date = req.query.date == null ? undefined : String(req.query.date);
        res.json(await selectDailyEdition({ date, store: dailyEditionStore, generator: dailyEditionGenerator }));
    } catch (error) {
        if (error.status === 400 || error.status === 404) return res.status(error.status).json({ error: error.message });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// ─── Gestão do catálogo de feeds RSS (monitorados pelo coletor) ────────────
// GET é aberto pra qualquer sessão (o painel de Fontes fica no Advisory Feed,
// que já é gated). As escritas exigem admin. Toda mutação dispara um refresh em
// background pra valer sem esperar o próximo ciclo.
function feedListForClient() {
    const withHealth = (feed) => {
        const h = feedHealth.get(feed.url);
        return {
            url: feed.url, source: feed.source, layer: feed.layer, weight_boost: feed.weight_boost,
            builtin: feed.builtin, enabled: feed.enabled, kind: feed.kind || 'rss',
            health: h ? { ...h } : null,
        };
    };
    // As raspadas entram só na costura de exibição: catalogFeeds()/effectiveFeeds()
    // ficam intocados, senão o coletor de RSS tentaria buscar uma página HTML.
    const scraped = SCRAPE_SOURCES.map((source) => withHealth({
        ...source, builtin: true, enabled: !feedOverrides.disabled.includes(source.url),
    }));
    return [...catalogFeeds().map(withHealth), ...scraped];
}

app.get('/api/feeds', requireAuth, (req, res) => {
    res.json({ feeds: feedListForClient(), isAdmin: isAdmin(req.user.login) });
});

// Adiciona um feed custom. Body: { url, source, layer?, weight_boost? }.
app.post('/api/feeds', requireAdmin, (req, res) => {
    const { url, source } = req.body || {};
    let u;
    try { u = new URL(String(url)); } catch { return res.status(400).json({ error: 'URL inválida' }); }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return res.status(400).json({ error: 'URL deve ser http(s)' });
    const clean = u.toString();
    if (!source || !String(source).trim()) return res.status(400).json({ error: 'nome da fonte obrigatório' });
    const known = new Set([...BUILTIN_FEEDS, ...feedOverrides.custom].map((f) => f.url));
    if (known.has(clean)) return res.status(409).json({ error: 'feed já existe' });
    const layer = Math.min(Math.max(parseInt(req.body.layer, 10) || 2, 1), 4);
    const weight_boost = Math.min(Math.max(parseInt(req.body.weight_boost, 10) || 10, 0), 25);
    feedOverrides.custom.push({ url: clean, source: String(source).trim(), layer, weight_boost });
    // adicionar já implica ligado: garante que não fique num disabled antigo.
    feedOverrides.disabled = feedOverrides.disabled.filter((d) => d !== clean);
    saveFeedOverrides();
    refreshNewsletterFeed({ force: true }).catch(() => {});
    res.status(201).json({ feeds: feedListForClient() });
});

// Liga/desliga um feed (built-in ou custom). Body: { url, enabled }.
app.patch('/api/feeds', requireAdmin, (req, res) => {
    const url = String((req.body || {}).url || '');
    const enabled = !!(req.body || {}).enabled;
    const known = new Set([...BUILTIN_FEEDS, ...feedOverrides.custom].map((f) => f.url));
    if (!known.has(url)) return res.status(404).json({ error: 'feed não encontrado' });
    const set = new Set(feedOverrides.disabled);
    if (enabled) set.delete(url); else set.add(url);
    feedOverrides.disabled = [...set];
    saveFeedOverrides();
    refreshNewsletterFeed({ force: true }).catch(() => {});
    res.json({ feeds: feedListForClient() });
});

// Remove um feed custom (built-ins só podem ser desativados). ?url=…
app.delete('/api/feeds', requireAdmin, (req, res) => {
    const url = String(req.query.url || (req.body || {}).url || '');
    const before = feedOverrides.custom.length;
    feedOverrides.custom = feedOverrides.custom.filter((f) => f.url !== url);
    if (feedOverrides.custom.length === before) {
        return res.status(BUILTIN_FEEDS.some((f) => f.url === url) ? 400 : 404)
            .json({ error: BUILTIN_FEEDS.some((f) => f.url === url) ? 'feed built-in só pode ser desativado' : 'feed não encontrado' });
    }
    feedOverrides.disabled = feedOverrides.disabled.filter((d) => d !== url);
    feedHealth.delete(url);
    saveFeedOverrides();
    refreshNewsletterFeed({ force: true }).catch(() => {});
    res.json({ feeds: feedListForClient() });
});

// ─── Gestão da allow-list premium ──────────────────────────────────────────
// Só admin. Entradas vindas do env (GITHUB_ALLOWED_LOGINS) aparecem marcadas
// como "env" e não são removíveis pela UI — para tirá-las, mexe na env e
// reinicia. O resto vem do store dinâmico em disco e é editável aqui.
// Username GitHub: alfanumérico + hífen, sem hífen no início/fim, até 39 chars.
const VALID_GH_LOGIN = /^[a-z0-9](?:-?[a-z0-9]){0,38}$/;
function allowlistForClient() {
    const seen = new Set();
    const out = [];
    for (const l of ALLOWED_LOGINS) {
        if (seen.has(l)) continue;
        seen.add(l);
        out.push({ login: l, source: 'env', admin: isAdmin(l), removable: false });
    }
    for (const l of dynamicAllowlist) {
        if (seen.has(l)) continue;
        seen.add(l);
        out.push({ login: l, source: 'dynamic', admin: isAdmin(l), removable: true });
    }
    return out;
}

app.get('/api/admin/allowlist', requireAdmin, (req, res) => {
    res.json({ allowlist: allowlistForClient(), org: ALLOWED_ORG || null });
});

// Liga/desliga o gate premium inteiro (chave de desenvolvimento). Só admin.
app.get('/api/admin/premium-open', requireAdmin, (req, res) => {
    res.json({ premiumOpen });
});

app.put('/api/admin/premium-open', requireAdmin, (req, res) => {
    const open = req.body?.premiumOpen === true;
    try { writeJsonAtomic(PREMIUM_OPEN_PATH, open); }
    catch (e) { return res.status(500).json({ error: `falha ao salvar: ${e.message}` }); }
    premiumOpen = open;
    console.warn(`[premium] gate ${open ? 'aberto' : 'fechado'} por ${req.user.login}`);
    res.json({ premiumOpen });
});

// Adiciona um login à allow-list premium dinâmica. Body: { login }.
app.post('/api/admin/allowlist', requireAdmin, (req, res) => {
    const login = String((req.body || {}).login || '').trim().toLowerCase();
    if (!VALID_GH_LOGIN.test(login)) return res.status(400).json({ error: 'login GitHub inválido' });
    if (ALLOWED_LOGINS.includes(login) || dynamicAllowlist.includes(login)) {
        return res.status(409).json({ error: 'usuário já está na lista premium' });
    }
    dynamicAllowlist.push(login);
    saveAllowlist();
    res.status(201).json({ allowlist: allowlistForClient() });
});

// Remove um login da allow-list premium dinâmica (os do env só saem pela env).
app.delete('/api/admin/allowlist', requireAdmin, (req, res) => {
    const login = String(req.query.login || (req.body || {}).login || '').trim().toLowerCase();
    if (ALLOWED_LOGINS.includes(login)) {
        return res.status(400).json({ error: 'premium definido por env só pode ser removido na env do servidor' });
    }
    const before = dynamicAllowlist.length;
    dynamicAllowlist = dynamicAllowlist.filter((l) => l !== login);
    if (dynamicAllowlist.length === before) return res.status(404).json({ error: 'usuário não está na lista premium' });
    saveAllowlist();
    res.json({ allowlist: allowlistForClient() });
});

// Status das chaves de integração do IOC search (admin). Diz o que está
// configurado vs faltando, pra o painel /admin. Reaproveita getKeys()/abuseChKey().
app.get('/api/admin/integrations', requireAdmin, (req, res) => {
    const has = (env) => getKeys(env).length > 0;
    const set = (env) => !!(process.env[env] || '').trim();
    const integrations = [
        { name: 'VirusTotal', env: 'VIRUSTOTAL_API_KEY', configured: has('VIRUSTOTAL_API_KEY'), required: true },
        { name: 'AbuseIPDB', env: 'ABUSEIPDB_API_KEY', configured: has('ABUSEIPDB_API_KEY'), required: true },
        { name: 'AlienVault OTX', env: 'ALIENVAULT_API_KEY', configured: set('ALIENVAULT_API_KEY'), required: false, note: 'sem chave a OTX limita por IP (a VPS dá 500 em lookups de IP)' },
        { name: 'Shodan', env: 'SHODAN_API_KEY', configured: set('SHODAN_API_KEY'), required: true },
        { name: 'abuse.ch (MalwareBazaar/ThreatFox/URLhaus)', env: 'ABUSE_CH_API_KEY', configured: !!abuseChKey(), required: true },
        { name: 'WHOIS', env: 'WHOIS_API_KEY', configured: set('WHOIS_API_KEY'), required: true },
        { name: 'PhishTank', env: 'PHISHTANK_API_KEY', configured: set('PHISHTANK_API_KEY'), required: false },
        { name: 'urlscan.io', env: 'URLSCAN_API_KEY', configured: set('URLSCAN_API_KEY'), required: false, note: 'sem chave a vigilância de marca de phishing não roda' },
    ];
    // Provedores que não precisam de chave nenhuma.
    const keyless = ['PhishStats', 'OpenPhish', 'IP Geolocation', 'Ransomware.live'];
    res.json({ integrations, keyless });
});

// ─── Scans salvos por usuário (histórico do IOC search) ────────────────────
// Store flat por usuário: cada scan guarda a query + o veredito consensual, pra
// revisitar de qualquer dispositivo. De-dup por query (mantém o mais recente),
// cap por usuário. Só a própria sessão lê/escreve os seus.
const SCANS_STORE_PATH = path.join(__dirname, '.scans.json');
function loadScansStore() { try { const o = JSON.parse(fs.readFileSync(SCANS_STORE_PATH, 'utf8')); return (o && typeof o === 'object') ? o : {}; } catch { return {}; } }
function saveScansStore() { try { writeJsonAtomic(SCANS_STORE_PATH, scansStore); } catch (e) { console.error('scans store write failed:', e.message); } }
let scansStore = loadScansStore();   // { userId: [ {id, query, queryType, threatLevel, score, detections, totalVendors, at} ] }
const SCANS_CAP = 100;

app.get('/api/user/scans', requireAuth, (req, res) => {
    res.json({ scans: scansStore[req.user.sub] || [] });
});

app.post('/api/user/scans', requireAuth, (req, res) => {
    const b = req.body || {};
    const query = String(b.query || '').trim();
    if (!query) return res.status(400).json({ error: 'query obrigatória' });
    const entry = {
        id: crypto.randomBytes(6).toString('hex'),
        query: query.slice(0, 512),
        queryType: String(b.queryType || '').slice(0, 16),
        threatLevel: String(b.threatLevel || 'unknown').slice(0, 16),
        score: Number(b.score) || 0,
        detections: Number(b.detections) || 0,
        totalVendors: Number(b.totalVendors) || 0,
        at: new Date().toISOString(),
    };
    const list = (scansStore[req.user.sub] || []).filter((s) => s.query !== entry.query);
    list.unshift(entry);
    scansStore[req.user.sub] = list.slice(0, SCANS_CAP);
    saveScansStore();
    res.status(201).json({ scans: scansStore[req.user.sub] });
});

app.delete('/api/user/scans/:id', requireAuth, (req, res) => {
    scansStore[req.user.sub] = (scansStore[req.user.sub] || []).filter((s) => s.id !== req.params.id);
    saveScansStore();
    res.json({ scans: scansStore[req.user.sub] });
});

// ─── Knowledge: fontes curadas por usuário ─────────────────────────────────
// O feed é um fluxo e some; aqui fica só o que o usuário marcou pra guardar,
// já indexado por técnica/CVE (ver knowledge.js e attackIndex.js). Mesmo
// formato do store de scans: flat por usuário, de-dup por URL, cap, e só a
// própria sessão lê/escreve os seus.
const KNOWLEDGE_STORE_PATH = path.join(__dirname, '.knowledge.json');
function loadKnowledgeStore() { try { const o = JSON.parse(fs.readFileSync(KNOWLEDGE_STORE_PATH, 'utf8')); return (o && typeof o === 'object') ? o : {}; } catch { return {}; } }
function saveKnowledgeStore() { try { writeJsonAtomic(KNOWLEDGE_STORE_PATH, knowledgeStore); } catch (e) { console.error('knowledge store write failed:', e.message); } }
let knowledgeStore = loadKnowledgeStore();   // { userId: [ {id,title,url,host,source,publishedAt,savedAt,techniques,cves} ] }

// Cada item seguido é conferido contra a cobertura ao vivo: `sourceCount` é
// quantos veículos existem agora, `newSources` é o que entrou depois do follow.
// Derivado na leitura, não guardado — o store de stories já é a fonte da verdade
// e duplicar o número criaria duas versões dele para divergirem.
app.get('/api/knowledge', requirePremium, (req, res) => {
    const items = (knowledgeStore[req.user.sub] || []).map((item) => {
        const story = item.storyId ? newsStoryStore.get(item.storyId) : null;
        if (!story) return item;
        const sourceCount = new Set(story.sources.map((s) => s.source)).size;
        return {
            ...item,
            sourceCount,
            newSources: Math.max(0, sourceCount - (item.followedSourceCount || 0)),
            lastSeen: story.lastSeen,
        };
    });
    res.json({ items });
});

app.post('/api/knowledge', requirePremium, async (req, res) => {
    let item;
    try {
        item = normalizeKnowledgeInput(req.body || {});
    } catch (e) {
        return res.status(400).json({ error: e.message });
    }
    // Mesmo guard do /api/feed/generate: a URL salva vira alvo de geração de
    // boletim depois, então não pode apontar para a rede interna.
    try { await assertSafePublicUrl(item.url); } catch (e) { return res.status(400).json({ error: e.message || 'URL rejeitada' }); }

    knowledgeStore[req.user.sub] = addKnowledgeItem(knowledgeStore[req.user.sub] || [], item);
    saveKnowledgeStore();
    res.status(201).json({ items: knowledgeStore[req.user.sub] });
});

app.delete('/api/knowledge/:id', requirePremium, (req, res) => {
    knowledgeStore[req.user.sub] = (knowledgeStore[req.user.sub] || []).filter((k) => k.id !== req.params.id);
    saveKnowledgeStore();
    res.json({ items: knowledgeStore[req.user.sub] });
});

// Segredo compartilhado p/ as rotas servidor-a-servidor (worker).
// Sem FEED_AGENT_SECRET definido, as rotas protegidas ficam desabilitadas (503),
// pra não exporem leitura/escrita de boletim sem auth.
function requireFeedSecret(req, res) {
    const secret = process.env.FEED_AGENT_SECRET;
    if (!secret) { res.status(503).json({ error: 'feed agent secret not configured' }); return false; }
    if (req.get('X-Feed-Secret') !== secret) { res.status(401).json({ error: 'unauthorized' }); return false; }
    return true;
}

// ─── Auth GitHub + BYOK (chaves de fornecedores cifradas em repouso) ────────
// Login via GitHub OAuth (fluxo escrito à mão, sem passport). A sessão é um
// cookie httpOnly assinado por HMAC — mesma origem que o app (Pages serve o app
// e faz proxy de /api pelo túnel), então não há CORS com credenciais. Login é
// aberto; a allow-list controla apenas recursos premium. Cada usuário traz as
// próprias chaves de fornecedores (BYOK): cifradas (AES-256-GCM) e guardadas em
// .users.json; nunca vai pro store de jobs, nunca ao worker público, nunca ao log.

// Chave-mestra p/ cifrar segredos dos usuários. Aceita 64-hex, base64 de 32B, ou
// deriva de uma passphrase via sha256. Sem ela, guardar chave fica desabilitado.
function loadEncKey() {
    const raw = (process.env.SECRETS_ENCRYPTION_KEY || '').trim();
    if (!raw) return null;
    if (/^[0-9a-fA-F]{64}$/.test(raw)) return Buffer.from(raw, 'hex');
    const b = Buffer.from(raw, 'base64');
    if (b.length === 32) return b;
    return crypto.createHash('sha256').update(raw).digest();
}
const ENC_KEY = loadEncKey();
function encryptSecret(plain) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
    const ct = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64');
}
function decryptSecret(blob) {
    const buf = Buffer.from(String(blob), 'base64');
    const d = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, buf.subarray(0, 12));
    d.setAuthTag(buf.subarray(12, 28));
    return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');
}

// Sessão: token compacto <payload>.<hmac>, verificado em tempo constante + exp.
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const SESSION_TTL_S = 7 * 24 * 3600;
const COOKIE_SECURE = process.env.NODE_ENV !== 'development';
const b64url = (buf) => Buffer.from(buf).toString('base64url');
function signSession(payload) {
    const body = b64url(JSON.stringify(payload));
    const sig = b64url(crypto.createHmac('sha256', SESSION_SECRET).update(body).digest());
    return `${body}.${sig}`;
}
function verifySession(token) {
    if (!token || !SESSION_SECRET) return null;
    const [body, sig] = token.split('.');
    if (!body || !sig) return null;
    const expect = b64url(crypto.createHmac('sha256', SESSION_SECRET).update(body).digest());
    const a = Buffer.from(sig), b = Buffer.from(expect);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    try {
        const p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
        return (p.exp && p.exp * 1000 > Date.now()) ? p : null;
    } catch { return null; }
}
function getCookie(req, name) {
    const h = req.headers.cookie;
    if (!h) return null;
    for (const part of h.split(';')) {
        const i = part.indexOf('=');
        if (i > -1 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
    }
    return null;
}

// Store de usuários (flat JSON, como os jobs). apiKeysEnc = chaves BYOK de vendor
// (Shodan/urlscan) cifradas; a geração usa a chave OpenRouter do servidor.
const USERS_STORE_PATH = process.env.USERS_STORE_PATH || path.join(__dirname, '.users.json');
function loadUsers() { try { return JSON.parse(fs.readFileSync(USERS_STORE_PATH, 'utf8')); } catch { return {}; } }
function saveUsers() { try { writeJsonAtomic(USERS_STORE_PATH, usersStore); } catch (e) { console.error('users store write failed:', e.message); } }
let usersStore = loadUsers();   // { githubId: { login, apiKeysEnc, createdAt, updatedAt } }

// Premium allow-list: por login e/ou por org. Login no app é aberto; esta lista
// decide quem acessa recursos premium (relatórios, newsletter).
const ALLOWED_LOGINS = (process.env.GITHUB_ALLOWED_LOGINS || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
const ALLOWED_ORG = (process.env.GITHUB_ALLOWED_ORG || '').trim();

// Allow-list dinâmica: logins que o admin adiciona em runtime pela UI, persistidos
// em disco (como .users.json). Somam-se aos GITHUB_ALLOWED_LOGINS (o env é o seed
// fixo, não removível pela UI) e à org.
const ALLOWLIST_STORE_PATH = path.join(__dirname, '.allowlist.json');
function loadAllowlist() {
    try {
        const arr = JSON.parse(fs.readFileSync(ALLOWLIST_STORE_PATH, 'utf8'));
        return Array.isArray(arr) ? [...new Set(arr.map((s) => String(s).trim().toLowerCase()).filter(Boolean))] : [];
    } catch { return []; }
}
function saveAllowlist() {
    try { writeJsonAtomic(ALLOWLIST_STORE_PATH, dynamicAllowlist); }
    catch (e) { console.error('allowlist store write failed:', e.message); }
}
let dynamicAllowlist = loadAllowlist();

function hasPremiumAccessSync(login) {
    const l = (login || '').toLowerCase();
    return ALLOWED_LOGINS.includes(l) || dynamicAllowlist.includes(l);
}

// Chave de desenvolvimento: com ela ligada, qualquer sessão autenticada passa
// pelo gate premium. Serve pra desenvolver sem ficar comentando o gate no
// código. Só admin liga/desliga, o padrão é desligada e o estado sobrevive a
// restart — se ficar ligada em produção, todo mundo logado vira premium.
const PREMIUM_OPEN_PATH = process.env.PREMIUM_OPEN_PATH || path.join(__dirname, '.premium-open.json');
function loadPremiumOpen() {
    try { return JSON.parse(fs.readFileSync(PREMIUM_OPEN_PATH, 'utf8')) === true; } catch { return false; }
}
let premiumOpen = loadPremiumOpen();
if (premiumOpen) console.warn('[premium] gate aberto: toda sessão autenticada tem premium');

async function resolvePremiumAccess(login, accessToken) {
    const l = login.toLowerCase();
    if (hasPremiumAccessSync(l)) return { allowed: true, viaOrg: false };
    if (ALLOWED_ORG) {
        const r = await axios.get(`https://api.github.com/orgs/${ALLOWED_ORG}/members/${login}`, {
            headers: { Authorization: `Bearer ${accessToken}`, 'User-Agent': 'threatsumm4ry', Accept: 'application/vnd.github+json' },
            validateStatus: () => true, timeout: 10000,
        }).catch(() => ({ status: 0 }));
        if (r.status === 204) return { allowed: true, viaOrg: true };
    }
    return { allowed: false, viaOrg: false };
}

function sessionHasPremium(p) {
    if (premiumOpen) return true;
    return hasPremiumAccessSync(p?.login) || Boolean(ALLOWED_ORG && p?.premiumViaOrg);
}

function requireAuth(req, res, next) {
    const p = verifySession(getCookie(req, 'ts_session'));
    if (!p) return res.status(401).json({ error: 'não autenticado', needAuth: true });
    req.user = p;
    next();
}

function requirePremium(req, res, next) {
    const p = verifySession(getCookie(req, 'ts_session'));
    if (!p) return res.status(401).json({ error: 'não autenticado', needAuth: true });
    if (!sessionHasPremium(p)) {
        return res.status(403).json({ error: 'recurso premium: solicite liberação de acesso', needPremium: true });
    }
    req.user = p;
    next();
}

// Admins podem editar allow-list premium, publicações e catálogo de feeds. Com
// login aberto, admin nunca deve cair para "qualquer usuário": use
// GITHUB_ADMIN_LOGINS ou, como fallback local, GITHUB_ALLOWED_LOGINS.
const ADMIN_LOGINS = (process.env.GITHUB_ADMIN_LOGINS || process.env.GITHUB_ALLOWED_LOGINS || '')
    .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
function isAdmin(login) {
    return ADMIN_LOGINS.includes((login || '').toLowerCase());
}
function requireAdmin(req, res, next) {
    const p = verifySession(getCookie(req, 'ts_session'));
    if (!p) return res.status(401).json({ error: 'não autenticado', needAuth: true });
    if (!isAdmin(p.login)) return res.status(403).json({ error: 'somente administrador' });
    req.user = p;
    next();
}

const APP_BASE_URL = (process.env.APP_BASE_URL || 'https://threatsumm4ry.app').replace(/\/$/, '');
const GH_CLIENT_ID = process.env.GITHUB_OAUTH_CLIENT_ID || '';
const GH_CLIENT_SECRET = process.env.GITHUB_OAUTH_CLIENT_SECRET || '';
const OAUTH_SCOPE = ALLOWED_ORG ? 'read:user read:org' : 'read:user';
const REDIRECT_URI = `${APP_BASE_URL}/api/auth/github/callback`;

// Início do fluxo: guarda um `state` anti-CSRF num cookie curto e redireciona.
app.get('/api/auth/github/login', (req, res) => {
    if (!GH_CLIENT_ID) return res.status(500).json({ error: 'auth não configurado' });
    const state = crypto.randomBytes(16).toString('hex');
    res.cookie('ts_oauth_state', state, { httpOnly: true, secure: COOKIE_SECURE, sameSite: 'lax', path: '/', maxAge: 600000 });
    const wantsSignup = ['1', 'true', 'yes'].includes(String(req.query.signup || '').toLowerCase());
    const u = new URL('https://github.com/login/oauth/authorize');
    u.searchParams.set('client_id', GH_CLIENT_ID);
    u.searchParams.set('redirect_uri', REDIRECT_URI);
    u.searchParams.set('scope', OAUTH_SCOPE);
    u.searchParams.set('state', state);
    u.searchParams.set('allow_signup', wantsSignup ? 'true' : 'false');
    res.redirect(u.toString());
});

// Callback: valida state, troca code->token e cria sessão. Premium é calculado
// separadamente e usado só nos recursos pagos/fechados.
app.get('/api/auth/github/callback', async (req, res) => {
    // Sucesso cai no /profile (mostra identidade + chave); falha volta pro /login.
    const back = (q) => res.redirect(`${APP_BASE_URL}${q === 'ok' ? '/profile' : '/login'}?auth=${q}`);
    try {
        const { code, state } = req.query;
        const saved = getCookie(req, 'ts_oauth_state');
        res.clearCookie('ts_oauth_state', { path: '/' });
        if (!code || !state || !saved || state !== saved) return back('erro');
        const tok = await axios.post('https://github.com/login/oauth/access_token',
            { client_id: GH_CLIENT_ID, client_secret: GH_CLIENT_SECRET, code, redirect_uri: REDIRECT_URI },
            { headers: { Accept: 'application/json' }, timeout: 10000 });
        const accessToken = tok.data?.access_token;
        if (!accessToken) return back('erro');
        const gh = await axios.get('https://api.github.com/user', {
            headers: { Authorization: `Bearer ${accessToken}`, 'User-Agent': 'threatsumm4ry', Accept: 'application/vnd.github+json' },
            timeout: 10000,
        });
        const login = gh.data?.login;
        const id = String(gh.data?.id || '');
        if (!login || !id) return back('erro');
        const premium = await resolvePremiumAccess(login, accessToken);
        const u = usersStore[id] || (usersStore[id] = { login, createdAt: new Date().toISOString() });
        u.login = login;
        u.updatedAt = new Date().toISOString();
        saveUsers();
        setSessionCookie(res, signSession({ sub: id, login, premiumViaOrg: premium.viaOrg, exp: Math.floor(Date.now() / 1000) + SESSION_TTL_S }));
        return back('ok');
    } catch (e) {
        console.error('oauth callback:', e.message);
        return back('erro');
    }
});
function setSessionCookie(res, token) {
    res.cookie('ts_session', token, { httpOnly: true, secure: COOKIE_SECURE, sameSite: 'lax', path: '/', maxAge: SESSION_TTL_S * 1000 });
}

app.get('/api/auth/me', (req, res) => {
    const p = verifySession(getCookie(req, 'ts_session'));
    if (!p) return res.json({ authenticated: false });
    res.json({
        authenticated: true,
        login: p.login,
        isAdmin: isAdmin(p.login),
        isPremium: sessionHasPremium(p),
    });
});

app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('ts_session', { path: '/' });
    res.json({ ok: true });
});

// ─── BYOK genérico: chaves de API por provider, cifradas (apiKeysEnc), usadas nos
// lookups de vendor. A geração de relatórios NÃO usa mais BYOK — roda na chave
// OpenRouter compartilhada do servidor. Nunca devolve valores, só quais providers
// estão configurados.
// Só entram providers cuja chave é REALMENTE lida em alguma consulta.
// Os outros providers (virustotal, abuseipdb, alienvault,
// urlhaus, threatfox, phishtank, whois,
// dnsdumpster) ficavam guardados cifrados, apareciam como "configurado" na tela
// e nenhuma rota os lia — todas leem só process.env. Prometer o que não
// acontece é pior do que não oferecer.
const BYOK_PROVIDERS = new Set(['shodan', 'urlscan', 'abuse_ch']);
function userKeysStatus(u) {
    const out = {};
    const m = (u && u.apiKeysEnc) || {};
    for (const p of BYOK_PROVIDERS) out[p] = !!m[p];
    return out;
}
app.get('/api/user/keys', requireAuth, (req, res) => {
    res.json({ keys: userKeysStatus(usersStore[req.user.sub]) });
});
app.put('/api/user/keys/:provider', requireAuth, (req, res) => {
    if (!ENC_KEY) return res.status(500).json({ error: 'armazenamento de chave não configurado no servidor' });
    const provider = String(req.params.provider || '').toLowerCase();
    if (!BYOK_PROVIDERS.has(provider)) return res.status(400).json({ error: 'provider desconhecido' });
    const key = (req.body?.key || '').toString().trim();
    if (!key || key.length < 8 || key.length > 400) return res.status(400).json({ error: 'chave inválida' });
    const u = usersStore[req.user.sub] || (usersStore[req.user.sub] = { login: req.user.login, createdAt: new Date().toISOString() });
    (u.apiKeysEnc || (u.apiKeysEnc = {}))[provider] = encryptSecret(key);
    u.updatedAt = new Date().toISOString();
    saveUsers();
    res.json({ provider, hasKey: true });
});
app.delete('/api/user/keys/:provider', requireAuth, (req, res) => {
    const provider = String(req.params.provider || '').toLowerCase();
    const u = usersStore[req.user.sub];
    // Apagar aceita provider fora da lista atual, de propósito: quem guardou
    // chave de um dos doze que saíram precisa conseguir removê-la. Guarda
    // estrita aqui prenderia um segredo cifrado no store para sempre.
    if (!BYOK_PROVIDERS.has(provider) && !u?.apiKeysEnc?.[provider]) {
        return res.status(400).json({ error: 'provider desconhecido' });
    }
    if (u) {
        if (u.apiKeysEnc) delete u.apiKeysEnc[provider];
        u.updatedAt = new Date().toISOString();
        saveUsers();
    }
    res.json({ provider, hasKey: false });
});

function getUserApiKey(userId, provider) {
    const encrypted = usersStore[userId]?.apiKeysEnc?.[provider];
    if (!encrypted) return '';
    try { return decryptSecret(encrypted); }
    catch (error) {
        console.error(`failed to decrypt ${provider} key for user:`, error.message);
        return '';
    }
}

function buildExposureScanDeps(ownerId) {
    return {
        axiosClient: shodanClient,
        shodanApiKey: getUserApiKey(ownerId, 'shodan') || process.env.SHODAN_API_KEY,
    };
}

const malwareCatalog = createMalwareCatalog({
    http: axios,
    getKey: ownerId => getUserApiKey(ownerId, 'abuse_ch') || abuseChKey(),
    getPublications: () => newsArchiveStore.list(),
    cacheFile: process.env.MALPEDIA_CACHE_PATH || path.join(__dirname, '.malpedia-cache.json'),
});
app.get('/api/malware/families', requirePremium, scanLimiter, async (req, res) => {
    res.set('Cache-Control', 'private, no-store');
    try { res.json(await malwareCatalog.list(req.user.sub)); }
    catch { res.status(503).json({ error: 'Fontes de malware indisponíveis.' }); }
});
app.get('/api/malware/family', requirePremium, scanLimiter, async (req, res) => {
    res.set('Cache-Control', 'private, no-store');
    const id = req.query.id;
    if (typeof id !== 'string' || id.length > 180 || /[\x00-\x1f]/.test(id)) return res.status(400).json({ error: 'Família inválida.' });
    try { const row = await malwareCatalog.detail(req.user.sub, id); if (!row) return res.status(404).json({ error: 'Família não encontrada.' }); res.json(row); }
    catch { res.status(503).json({ error: 'Fontes de malware indisponíveis.' }); }
});
app.get('/api/malware/sample/:hash', requirePremium, scanLimiter, async (req, res) => {
    res.set('Cache-Control', 'private, no-store');
    if (!/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(req.params.hash)) return res.status(400).json({ error: 'Hash inválido.' });
    try { res.json(await malwareCatalog.samples(req.user.sub, { hash: req.params.hash })); }
    catch { res.status(503).json({ error: 'MalwareBazaar indisponível.' }); }
});

async function runExposureForAsset(asset) {
    return runExposureSnapshot({
        store: exposureStore,
        assetId: asset.id,
        ownerId: asset.ownerId,
        runAttackSurfaceScan,
        scanDeps: buildExposureScanDeps(asset.ownerId),
    });
}

async function runPhishWatchTick() {
    if (process.env.NODE_ENV === 'test') return;
    const profiles = orgProfileStore.allProfiles();
    const clients = new Map(profiles.map((profile) => [profile.id, urlscanClientFor(profile.ownerId)]));
    await runDuePhishWatch({
        store: phishWatchStore,
        profiles: profiles.filter((profile) => clients.get(profile.id).search),
        now: new Date(),
        quotaGroupFor: (profile) => clients.get(profile.id).quotaGroup,
        runOne: async (profile) => {
            await runProfileWatch({ store: phishWatchStore, profile, search: clients.get(profile.id).search });
            await syncTicketsFromHits(profile.ownerId, profile.id);
        },
    });
    // Depois da rodada: o que já está na fila ainda está no ar?
    await recheckTicketDns();
    // E o que ainda nem virou ticket — domínio novo que estava parqueado pode
    // ter subido A/MX na última hora, e ninguém vai notar até o urlscan
    // resolver reescanear por conta própria.
    await recheckHitsDns({ store: phishWatchStore, resolveDns: phishDnsResolver });
}

async function runExposureSchedulerTick() {
    if (process.env.EXPOSURE_WATCHLIST_DISABLE_DAILY === 'true' || process.env.NODE_ENV === 'test') return;
    await runDueExposureSnapshots({ store: exposureStore, now: new Date(), runOne: runExposureForAsset });
}

// ─── Boletim · jobs de geração por URL (1 URL = 1 boletim) ─────────────────
// O front escolhe UMA url e pede a geração (POST generate); um worker na VPS
// (saida-so, porta fechada) faz poll dos pendentes (GET jobs/pending), roda
// o motor pesado, e devolve o JSON (POST job/result, 🔒). O front faz poll do
// job (GET job) e baixa o JSON quando pronto; o PPT é preenchido localmente.
const JOBS_STORE_PATH = process.env.FEED_JOBS_PATH || path.join(__dirname, '.feed-jobs.json');

// Anexos entregues pelo worker: o deck no template SRR e o PDF dele convertido.
// Vão pro DISCO, não pro store: juntos passam de 4 MB e o store é reescrito
// inteiro a cada saveJobs() — carregá-los ali transformaria cada gravação de job
// numa cópia de vários MB.
const DECKS_DIR = path.join(__dirname, '.feed-decks');
const DECK_KINDS = { pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                     pdf: 'application/pdf' };
const deckPath = (id, kind) => path.join(DECKS_DIR, `${id}.${kind}`);
function saveDeck(id, kind, base64) {
    fs.mkdirSync(DECKS_DIR, { recursive: true });
    const tmp = `${deckPath(id, kind)}.tmp`;
    fs.writeFileSync(tmp, Buffer.from(base64, 'base64'));
    fs.renameSync(tmp, deckPath(id, kind));
}
// Roda junto da poda: apaga do disco os decks que não têm mais job.
function sweepDecks() {
    let files;
    try { files = fs.readdirSync(DECKS_DIR); } catch { return; }
    for (const file of orphanDeckFiles(files, jobsStore)) {
        fs.rmSync(path.join(DECKS_DIR, file), { force: true });
    }
}
function loadJobs() { try { return JSON.parse(fs.readFileSync(JOBS_STORE_PATH, 'utf8')); } catch { return {}; } }
function saveJobs() { try { writeJsonAtomic(JOBS_STORE_PATH, jobsStore); } catch (e) { console.error('jobs store write failed:', e.message); } }
let jobsStore = loadJobs();   // { id: { id,url,type,title,status,json,error,createdAt,updatedAt } }

// Boletim entregue não é lixo de fila: fica guardado por dono (ver feedJobs.js).
// Só pending/error têm teto global.
const REPORTS_PER_OWNER = parseInt(process.env.FEED_REPORTS_PER_OWNER, 10) || 200;
function pruneJobs() {
    pruneJobsMap(jobsStore, { maxTransient: 100, keptPerOwner: REPORTS_PER_OWNER });
    sweepDecks();
}

// Expira jobs presos em 'pending' além do TTL (worker caiu / geração longa demais),
// pra não deixar o front em "gerando…" pra sempre nem o worker pegar job morto.
// TTL alto o bastante pra uma fila cheia (FEED_MAX_QUEUE jobs) drenar num worker
// com concorrência 2 mesmo se cada job bater o teto de 240s: 12/2*240s = 24 min.
// Abaixo disso, o usuário no fim da fila via "expirou" sem nada estar quebrado.
const JOB_TTL_MS = parseInt(process.env.FEED_JOB_TTL_MS, 10) || 25 * 60 * 1000;
// Teto de jobs 'pending' aceitos ao mesmo tempo. Ao encher, o próximo /generate
// recebe 429 com a posição na fila em vez de um wait silencioso de dezenas de min.
const FEED_MAX_QUEUE = parseInt(process.env.FEED_MAX_QUEUE, 10) || 12;

// Quantas fontes de uma story consolidada entram numa análise ou num boletim.
// Cada uma custa um scrape e ocupa contexto do prompt; da quinta em diante o
// writeup seguinte quase não acrescenta ao que os anteriores já disseram.
const MAX_STORY_SOURCES = 5;
function pendingCount() {
    return Object.values(jobsStore).filter((j) => j.status === 'pending').length;
}
function expireStaleJobs() {
    const now = Date.now();
    let changed = false;
    for (const j of Object.values(jobsStore)) {
        if (j.status === 'pending' && now - new Date(j.createdAt).getTime() > JOB_TTL_MS) {
            j.status = 'error';
            j.error = 'expirou (worker indisponível ou geração longa demais)';
            j.updatedAt = new Date().toISOString();
            changed = true;
        }
    }
    if (changed) saveJobs();
}

// Front pede a geração de UMA url. Requer login + chave OpenRouter própria (BYOK).
//   POST /api/feed/generate  { url, type?, title?, template?, subtype? }
// type: 'auto' (padrão -- o motor classifica) | 'vuln' | 'campaign'.
// template: 'avancado' (SRR novo, padrão) | 'basico' (SRR V2) | 'premium' (um modelo por subtipo).
// subtype (só importa com template premium): 'auto' (padrão) | 'malware' |
// 'phishing' | 'ransomware' | 'cve_unica' | 'cve_varias'.
app.post('/api/feed/generate', requirePremium, scanLimiter, async (req, res) => {
    try {
        // Mesma forma do /api/newsletter/enrich: `urls` é a story consolidada,
        // `url` segue aceito para uma fonte só.
        const urls = (Array.isArray(req.body?.urls) ? req.body.urls : [req.body?.url])
            .map((value) => (value || '').toString())
            .filter(Boolean)
            .slice(0, MAX_STORY_SOURCES);
        const url = urls[0] || '';
        const type = normalizeDeckRequestType(req.body?.type);
        const title = (req.body?.title || '').toString().slice(0, 300);
        const template = normalizeDeckTemplate(req.body?.template);
        const subtype = normalizeDeckSubtype(req.body?.subtype);
        if (!urls.length || !urls.every((u) => /^https?:\/\//i.test(u))) {
            return res.status(400).json({ error: 'url http(s) obrigatória' });
        }
        // Sem BYOK: a geração usa a chave OpenRouter compartilhada do servidor
        // (OPENROUTER_API_KEY no .env do worker/engine). O acesso já é gated por
        // login + allow-list premium (requirePremium) acima.
        // Sempre valida (sem atalho de "confiar em URL do feed") — o guard SSRF
        // bloqueia IP privado/loopback/metadata. O worker na VPS revalida também.
        // TODAS passam pelo guard, não só a primeira: uma URL segura no array não
        // vouches pelas outras, e o worker vai buscar cada uma.
        for (const target of urls) {
            try { await assertSafePublicUrl(target); } catch (e) { return res.status(400).json({ error: e.message || 'URL rejeitada' }); }
        }
        // Fila cheia: recusa cedo com posição, em vez de aceitar e deixar o job
        // esperar tanto que expira. 503 (não 429) pra não colidir com o rate-limit.
        expireStaleJobs();
        const queued = pendingCount();
        if (queued >= FEED_MAX_QUEUE) {
            return res.status(503).json({
                error: `Servidor ocupado: ${queued} boletins na fila. Tente de novo em alguns minutos.`,
                queueDepth: queued,
                retryable: true,
            });
        }
        const id = crypto.randomUUID();
        const now = new Date().toISOString();
        const documents = prepareFeedJobDocuments(urls, { items: memoryCache.newsletter.data || [], articleCache: articleCollectionCache, rssCache: rssCollectionCache });
        jobsStore[id] = { id, ownerSub: req.user.sub, url, urls, documents, type, template, subtype, title, status: 'pending', json: null, error: null, createdAt: now, updatedAt: now };
        pruneJobs();
        saveJobs();
        res.json({ id, status: 'pending' });
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// Front faz poll do job. Premium.   GET /api/feed/job?id=...
app.get('/api/feed/job', requirePremium, (req, res) => {
    expireStaleJobs();
    const job = jobsStore[(req.query.id || '').toString()];
    if (!job) return res.status(404).json({ error: 'job não encontrado' });
    if (job.ownerSub !== req.user.sub) return res.status(403).json({ error: 'job pertence a outro usuário' });
    // Posição na fila = quantos jobs pending foram criados antes deste (0 = já
    // sendo processado / próximo). Deixa o front mostrar "N na sua frente".
    let queuePosition = 0;
    if (job.status === 'pending') {
        queuePosition = Object.values(jobsStore).filter(
            (j) => j.status === 'pending' && j.createdAt < job.createdAt,
        ).length;
    }
    const clientJob = { ...job };
    delete clientJob.documents;
    res.json({ ...clientJob, queuePosition });
});

// Boletins do usuário, sem o JSON — é a lista de consulta do /relatorios.
// GET /api/feed/jobs
app.get('/api/feed/jobs', requirePremium, (req, res) => {
    expireStaleJobs();
    const jobs = Object.values(jobsStore)
        .filter((j) => j.ownerSub === req.user.sub)
        .sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''))
        .map(jobSummary);
    res.json({ jobs });
});

// Apaga um boletim do usuário.   DELETE /api/feed/job/:id
// Anexo pronto do boletim: o deck no template SRR preenchido na VPS, ou o PDF
// dele convertido. Premium + dono; o PPTX (fonte editável, template SRR) é só
// admin.   GET /api/feed/job/deck?id=...&kind=pptx|pdf
app.get('/api/feed/job/deck', requirePremium, (req, res) => {
    const id = (req.query.id || '').toString();
    const kind = (req.query.kind || 'pptx').toString();
    const job = jobsStore[id];
    if (!job) return res.status(404).json({ error: 'job não encontrado' });
    if (job.ownerSub !== req.user.sub) return res.status(403).json({ error: 'job pertence a outro usuário' });
    if (kind === 'pptx' && !isAdmin(req.user.login)) {
        return res.status(403).json({ error: 'PPTX é somente para administrador' });
    }
    const name = DECK_KINDS[kind] && job.deck?.[kind];
    if (!name || !isJobId(id) || !fs.existsSync(deckPath(id, kind))) {
        return res.status(404).json({ error: `${kind} não disponível para este boletim` });
    }
    // O nome vem do motor (url_report.srr_filename), não é remontado aqui: um
    // segundo lugar aplicando a regra de nome já divergiu uma vez.
    res.type(DECK_KINDS[kind]);
    res.setHeader('Content-Disposition',
        `attachment; filename*=UTF-8''${encodeURIComponent(name)}`);
    fs.createReadStream(deckPath(id, kind)).pipe(res);
});

app.delete('/api/feed/job/:id', requirePremium, (req, res) => {
    const job = jobsStore[req.params.id];
    if (!job) return res.status(404).json({ error: 'job não encontrado' });
    if (job.ownerSub !== req.user.sub) return res.status(403).json({ error: 'job pertence a outro usuário' });
    delete jobsStore[req.params.id];
    if (isJobId(req.params.id)) {
        for (const kind of Object.keys(DECK_KINDS)) fs.rmSync(deckPath(req.params.id, kind), { force: true });
    }
    saveJobs();
    res.json({ id: req.params.id, deleted: true });
});

app.get('/api/feed/job/:id/related', requirePremium, (req, res) => {
    const job = jobsStore[req.params.id];
    if (!job) return res.status(404).json({ error: 'job não encontrado' });
    if (job.ownerSub !== req.user.sub) return res.status(403).json({ error: 'job pertence a outro usuário' });

    const refs = (job.techniques?.length || job.cves?.length) ? job : refsOfReport(job.json);
    const reports = Object.values(jobsStore)
        .filter((candidate) => candidate.id !== job.id && candidate.ownerSub === req.user.sub && candidate.status === 'done')
        .map((candidate) => ({
            ...jobSummary(candidate),
            ...((candidate.techniques?.length || candidate.cves?.length) ? {} : refsOfReport(candidate.json)),
        }));
    res.json(relatedTo(refs, { reports }));
});

// Worker (VPS) lê os jobs pendentes. 🔒   GET /api/feed/jobs/pending
app.get('/api/feed/jobs/pending', (req, res) => {
    if (!requireFeedSecret(req, res)) return;
    expireStaleJobs();
    // Sem BYOK: todo job pending vai pro worker. A chave OpenRouter é do servidor
    // (no .env do worker), não viaja no payload. Só encaminhamos o modelo quando
    // este servidor pinar um DE PROPÓSITO — o --model do worker sobrescreve a
    // cadeia do motor (primário + fallbacks), que é quem sabe o assunto.
    //
    // Variável dedicada, NÃO OPENROUTER_MODEL: essa também alimenta a análise
    // on-demand do próprio site, vive setada em produção (o .env.example a
    // entrega preenchida) e assim pinava o modelo no worker sem ninguém pedir —
    // um modelo lento/degradado ali fazia toda geração bater o teto de 240s.
    // Vazia por padrão: quem decide o modelo do boletim é o motor.
    const workerModel = (process.env.FEED_WORKER_MODEL || '').trim();
    const pending = Object.values(jobsStore)
        .filter((j) => j.status === 'pending')
        .map((j) => ({
            id: j.id,
            url: j.url,
            urls: Array.isArray(j.urls) && j.urls.length ? j.urls : [j.url],
            type: j.type,
            // Job anterior ao campo sai no padrão do motor (SRR_TEMPLATE do worker).
            ...(j.template ? { template: j.template } : {}),
            // Só importa com template premium; 'auto' (padrão) o motor escolhe.
            ...(j.subtype && j.subtype !== 'auto' ? { subtype: j.subtype } : {}),
            title: j.title,
            documents: j.documents?.length ? j.documents : prepareFeedJobDocuments(j.urls || [j.url], { items: memoryCache.newsletter.data || [], articleCache: articleCollectionCache, rssCache: rssCollectionCache }),
            ...(workerModel ? { model: workerModel } : {}),
        }));
    res.json({ pending });
});

// Worker (VPS) devolve o resultado. 🔒   POST /api/feed/job/result {id, json|error}
app.post('/api/feed/job/result', (req, res) => {
    if (!requireFeedSecret(req, res)) return;
    const job = jobsStore[(req.body?.id || '').toString()];
    if (!job) return res.status(404).json({ error: 'job não encontrado' });
    if (req.body?.error) { job.status = 'error'; job.error = String(req.body.error).slice(0, 500); }
    else if (req.body?.json && typeof req.body.json === 'object') {
        job.status = 'done';
        job.error = null;
        job.json = req.body.json;
        // O pedido pode ter sido 'auto' (motor decide depois de raspar a URL);
        // o JSON que volta sempre tem o tipo concreto que o motor escolheu
        // (deck_type), e é esse que o badge da lista deve mostrar -- não 'auto'.
        if (job.json.deck_type === 'vuln' || job.json.deck_type === 'campaign') {
            job.type = job.json.deck_type;
        }
        // Indexa na entrega: é o único momento em que o boletim chega. Guardar
        // techniques/cves no job evita varrer o JSON inteiro a cada listagem.
        Object.assign(job, refsOfReport(job.json));
        // Deck e PDF vêm prontos do worker, que é quem tem os templates e o
        // conversor. Falhar em gravá-los NÃO derruba a entrega: o boletim (JSON)
        // é o resultado, os anexos são dele.
        job.deck = job.deck || {};
        for (const kind of Object.keys(DECK_KINDS)) {
            const blob = req.body[kind];
            if (typeof blob !== 'string' || !blob || !isJobId(job.id)) continue;
            try {
                saveDeck(job.id, kind, blob);
                job.deck[kind] = String(req.body[`${kind}Name`] || '').slice(0, 200)
                    || `${job.id}.${kind}`;
            } catch (e) {
                console.error(`${kind} write failed:`, e.message);
            }
        }
    }
    else return res.status(400).json({ error: 'json ou error obrigatório' });
    job.updatedAt = new Date().toISOString();
    pruneJobs();
    saveJobs();
    res.json({ id: job.id, status: job.status });
});

// ─── OpenRouter-powered on-demand advisory analysis ───────────────────────
const OPENROUTER_BASE_URL = 'https://openrouter.ai/api/v1';
const OPENROUTER_MODEL = process.env.OPENROUTER_MODEL || 'deepseek/deepseek-v4-flash';

// Com mais de uma fonte o resumo vira uma linha por veículo. Um parágrafo único
// funde os relatos numa voz só e apaga de quem é cada afirmação — que é
// justamente o que o leitor abriu o painel para ver.
const newsIntelPrompt = (lang, outlets = []) => (
    'You are a senior Cyber Threat Intelligence analyst. ' +
    'Respond ONLY with a JSON object with these keys:\n' +
    '1. "title": the advisory title, professionally normalized.\n' +
    (outlets.length > 1
        ? '2. "summary": ONE line PER SOURCE, separated by newline characters (\\n), covering these ' +
          `sources in this order: ${outlets.join(', ')}. Each line starts with the source name, then ": ", ` +
          'then what THAT source specifically reports. Keep each line to one or two sentences. Never merge ' +
          'the sources into a single voice, and where they disagree let the difference show. ' +
          'Do NOT prefix the lines with bullets, dashes or numbers.\n'
        : '2. "summary": ONE concise technical paragraph — an executive summary describing WHAT happened ' +
          '(the threat, incident or fact) and why it matters for a SOC/CTI operation.\n') +
    'Do NOT include mitigations, recommendations, remediation steps or IOC lists.\n' +
    // Traduzir jargão quebra a busca do analista e destrói o termo: "estouro de
    // buffer" não casa com nada que ele vai procurar depois, e classe de
    // vulnerabilidade é nome próprio, não descrição.
    'NEVER translate technical terminology — keep it verbatim in English even when the output ' +
    'language is Portuguese. This covers: vulnerability class names (Buffer Overflow, SQL Injection, ' +
    'Cross-Site Scripting, Use-After-Free, Path Traversal, Remote Code Execution, Privilege Escalation, ' +
    'Deserialization, Race Condition, Type Confusion), CVE/CWE identifiers, MITRE ATT&CK tactic and ' +
    'technique names, and every proper noun: malware families, threat actors, tools, vendors, products, ' +
    'protocols and APIs. Only the surrounding prose is translated.\n' +
    `OUTPUT LANGUAGE: ${lang === 'en' ? 'English' : 'Português (Brasil)'}. Respond ONLY the JSON, no extra text.`
);

/**
 * Traduz preservando a terminologia técnica.
 *
 * O Google Translate acha que "Buffer Overflow" é descrição e devolve "estouro
 * de buffer" — termo que não casa com nada que o analista vá pesquisar depois.
 * Os termos saem mascarados e voltam na íntegra.
 *
 * Se algum marcador não sobreviver à ida e volta, o termo teria sumido do
 * texto: nesse caso devolvemos o original em inglês, que é pior de ler e melhor
 * que uma frase com buraco.
 */
async function translateProtected(text, targetLang) {
    const input = String(text || '');
    if (!input.trim()) return '';
    const { masked, terms } = protectTerms(input);
    const translated = await googleTranslate(masked, targetLang);
    if (!terms.length) return translated;
    const restored = restoreTerms(translated, terms);
    return terms.every((term) => restored.includes(term)) ? restored : input;
}

// Free Google Translate endpoint (no key). Returns translated text, or the
// original on any failure. Used as the no-LLM fallback so advisories are at
// least readable in the user's language.
async function googleTranslate(text, targetLang) {
    const input = (text || '').slice(0, 1800);
    if (!input.trim()) return text || '';
    try {
        const resp = await axios.get('https://translate.googleapis.com/translate_a/single', {
            params: { client: 'gtx', sl: 'auto', tl: targetLang, dt: 't', q: input },
            timeout: 8000,
        });
        const segments = resp.data?.[0];
        if (Array.isArray(segments)) {
            return segments.map((s) => (Array.isArray(s) ? s[0] : '')).join('');
        }
    } catch (err) {
        console.warn(`Google Translate failed: ${err.message}`);
    }
    return text || '';
}

// Advanced collection: fetch the full article, extract its readable body (see
// extractReadableText — paragraphs AND the IOC tables) plus any link to an
// external indicator appendix. Best-effort: returns empty on WAF/JS-heavy sites,
// and the caller falls back to the RSS summary.
const BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

async function fetchArticleText(url, textCap = 8000) {
    try {
        const resp = await axios.get(url, {
            headers: { 'User-Agent': BROWSER_UA, Accept: 'text/html,application/xhtml+xml' },
            timeout: 10000,
            maxRedirects: 3,
            maxContentLength: 2000000,
            responseType: 'text',
        });
        return {
            text: extractReadableText(resp.data).slice(0, textCap),
            artifactLinks: collectArtifactLinks(resp.data, url),
        };
    } catch (err) {
        console.warn(`Article fetch failed for ${url}: ${err.message}`);
        return { text: '', artifactLinks: [] };
    }
}

// One hop into the linked indicator appendix (GitHub repo, gist, pastebin).
// Everything fetched here is untrusted, attacker-adjacent text: it feeds the
// deterministic IOC regexes, is size-capped, and each URL — including the ones
// GitHub's API hands back — passes the SSRF guard before any request goes out.
const ARTIFACT_MAX_BYTES = 40_000;
const ARTIFACT_MAX_FILES = 6;

async function fetchArtifactFile(url) {
    await assertSafePublicUrl(url);
    const resp = await axios.get(url, {
        headers: { 'User-Agent': BROWSER_UA, Accept: 'text/plain,*/*' },
        timeout: 8000,
        maxRedirects: 2,
        maxContentLength: ARTIFACT_MAX_BYTES,
        responseType: 'text',
        transformResponse: (d) => d,
    });
    const body = String(resp.data || '').slice(0, ARTIFACT_MAX_BYTES);
    // Nem todo apêndice é arquivo texto: gist.github.com, uma página de release
    // e o pastebin vêm como PÁGINA. Mandar o HTML cru pro extractIOCs publicava
    // a moldura como indicador — github.githubassets.com e todo CDN que estiver
    // num <script src>. O texto legível mantém as linhas do apêndice (td/li/pre)
    // e descarta atributo e <script> de uma vez.
    const isHtml = /^text\/html/i.test(resp.headers?.['content-type'] || '')
        || /^\s*<(?:!doctype|html)\b/i.test(body);
    return isHtml ? extractReadableText(body) : body;
}

// A GitHub folder link resolves to its text files; anything else is fetched as-is.
async function resolveArtifactFiles(link) {
    const gh = githubArtifact(link);
    if (!gh) return [link];
    if (gh.kind === 'raw') return [gh.url];

    await assertSafePublicUrl(gh.url);
    const resp = await axios.get(gh.url, {
        headers: { 'User-Agent': BROWSER_UA, Accept: 'application/vnd.github+json' },
        timeout: 8000,
        maxRedirects: 2,
    });
    return (Array.isArray(resp.data) ? resp.data : [])
        .filter((f) => f?.type === 'file' && f.download_url && f.size < ARTIFACT_MAX_BYTES && ARTIFACT_TEXT_FILE.test(f.name))
        .slice(0, ARTIFACT_MAX_FILES)
        .map((f) => f.download_url);
}

async function fetchIocArtifacts(links) {
    const artifacts = [];
    for (const link of links) {
        try {
            await assertSafePublicUrl(link);
            for (const file of await resolveArtifactFiles(link)) {
                artifacts.push({ origin: link, url: file, text: await fetchArtifactFile(file) });
            }
        } catch (err) {
            console.warn(`IOC artifact fetch failed for ${link}: ${err.message}`);
        }
    }
    return artifacts;
}

// Split readable text into clean sentences (>30 chars).
function splitSentences(text) {
    return String(text || '').replace(/\s+/g, ' ').split(/(?<=[.!?])\s+/).map((s) => s.trim()).filter((s) => s.length > 30);
}

// Concise Executive Summary: the first N lead sentences (capped).
function firstSentences(text, n = 3) {
    return splitSentences(text).slice(0, n).join(' ').slice(0, 650);
}

// Heuristic Impact & Mitigation: sentences about remediation, excluding any
// already used in the Executive Summary (so the two sections don't repeat).
function extractMitigation(text, exclude = '') {
    const used = new Set(splitSentences(exclude));
    const kw = /\b(mitigat\w*|patch\w*|workaround|remediat\w*|disabl\w*|recommend\w*|advisory|hotfix|fixed in|update to|upgrade to|apply the|high-priority|immediate action|affected versions?)\b/i;
    const hits = [];
    for (const s of splitSentences(text)) {
        if (used.has(s)) continue;
        if (kw.test(s)) hits.push(s);
        if (hits.length >= 3) break;
    }
    return hits.join(' ');
}

// Call OpenRouter chat completions; returns parsed JSON or null.
async function openRouterAnalyze(title, content, lang, outlets = []) {
    if (!process.env.OPENROUTER_API_KEY) return null;
    const userPrompt = `Title: ${title}\nOriginal content: ${(content || '').slice(0, 12000)}`;
    try {
        const resp = await axios.post(`${OPENROUTER_BASE_URL}/chat/completions`, {
            model: OPENROUTER_MODEL,
            temperature: 0.1,
            response_format: { type: 'json_object' },
            messages: [
                { role: 'system', content: newsIntelPrompt(lang, outlets) },
                { role: 'user', content: userPrompt },
            ],
        }, {
            headers: {
                Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}`,
                'Content-Type': 'application/json',
                'HTTP-Referer': process.env.APP_BASE_URL || 'https://threatsumm4ry.app',
                'X-OpenRouter-Title': 'ThreatSumm4ry',
            },
            timeout: 30000,
        });
        const text = resp.data?.choices?.[0]?.message?.content;
        if (text) return JSON.parse(text);
    } catch (err) {
        console.warn(`OpenRouter model ${OPENROUTER_MODEL} failed: ${err.message}`);
    }
    return null;
}

// On-demand actionable analysis for a single advisory (looked up in the live feed
// by URL to prevent arbitrary LLM abuse). Returns Executive Summary + Impact/
// Mitigation. Degrades gracefully to the RSS description when OpenRouter is unavailable.
app.post('/api/newsletter/enrich', requirePremium, scanLimiter, async (req, res) => {
    try {
        // `urls` é uma story consolidada (as fontes que o usuário marcou); `url`
        // continua aceito para uma fonte só. O teto existe porque cada URL custa
        // um scrape e entra no prompt: cinco writeups já estouram o orçamento de
        // contexto sem acrescentar muito ao sexto.
        const urls = (Array.isArray(req.body?.urls) ? req.body.urls : [req.body?.url])
            .map((value) => (value || '').toString())
            .filter(Boolean)
            .slice(0, MAX_STORY_SOURCES);
        const lang = req.body?.lang === 'en' ? 'en' : 'pt';
        if (!urls.length) return res.status(400).json({ error: 'Missing advisory url' });

        const feed = memoryCache.newsletter.data || [];
        const items = urls.map((link) => feed.find((i) => i.link === link)).filter(Boolean);
        if (!items.length) return res.status(404).json({ error: 'Advisory not found in current feed' });
        const item = items[0];

        // Ordenado: marcar as mesmas fontes em outra ordem é a mesma análise e
        // tem que acertar o mesmo cache.
        const cacheKey = `${lang}|${[...urls].sort().join('|')}`;
        const now = Date.now();
        const cached = memoryCache.newsletterEnrich.store.get(cacheKey);
        if (cached && cached.expiresAt > now) return res.json(cached.data);

        // Advanced collection: pull the full article body; fall back to RSS summary.
        // Uma fonte que falhe o scrape entra com o resumo do feed em vez de
        // derrubar a análise das outras.
        const fetched = await Promise.all(items.map((i) => fetchArticleText(i.link).catch(() => ({ text: '', artifactLinks: [] }))));
        const fullText = fetched.map((f) => f.text).filter(Boolean).join('\n\n');
        const artifactLinks = [...new Set(fetched.flatMap((f) => f.artifactLinks || []))];
        // Rotular cada corpo pela fonte é o que faz a LLM escrever "a Sophos
        // observou X, enquanto a CISA confirmou Y" em vez de fundir os relatos
        // numa voz só e apagar de quem é cada afirmação.
        const content = items.length > 1
            ? fetched.map((f, n) => `## ${items[n].source}\n${f.text || items[n].description || ''}`).join('\n\n')
            : (fullText || item.description || '');

        // Re-run deterministic enrichment over the FULL article so MITRE ATT&CK,
        // threats, sectors, assets and CVEs reflect the whole story, not just the
        // (often short) RSS summary.
        const intel = scoreArticle(`${items.map((i) => `${i.title} ${i.description || ''}`).join(' ')} ${content}`, item.weight_boost || 0);
        const enriched = localizeEnrichment({
            threats: intel.threats, sectors: intel.sectors, ttps: intel.ttps,
            assets: intel.assets, cves: intel.cves,
        }, lang);

        const ai = await openRouterAnalyze(item.title, content, lang, items.map((i) => i.source));

        // Deterministic IOC sweep over the FULL article (richer than the
        // title+summary set computed at collection) PLUS any linked indicator
        // appendix. High-precision: hashes + defanged network indicators + public
        // IPv4. iocSources is reported even when the fetch failed — a report whose
        // indicators live in a GitHub repo should say so, not show a short list as
        // if it were the whole set.
        const artifacts = await fetchIocArtifacts(artifactLinks);
        // Prose stays defanged-only (low noise); each fetched appendix is a plain
        // indicator list, so allow plain domains/URLs there. Merge + dedupe.
        const iocs = [extractIOCs(content), ...artifacts.map((a) => extractIOCs(a.text, { plaintext: true }))]
            .reduce((acc, cur) => {
                for (const k of Object.keys(acc)) acc[k] = [...new Set([...acc[k], ...cur[k]])];
                return acc;
            }, { ips: [], domains: [], hashes: [], urls: [] });
        const iocSources = artifactLinks.map((url) => ({
            url,
            fetched: artifacts.some((a) => a.origin === url),
        }));

        let payload;
        if (ai && ai.summary) {
            // Single executive-summary paragraph only (prompt no longer asks for
            // impact/mitigation, to save output tokens).
            payload = {
                available: true, source: 'openrouter', scraped: !!fullText, sourceCount: items.length,
                title: ai.title || item.title,
                executiveSummary: String(ai.summary).trim(),
                impactMitigation: '',
                iocs, iocSources, ...enriched,
            };
        } else {
            // No LLM: concise Executive Summary (lead sentences) + a distinct
            // heuristic Impact & Mitigation built from the scraped article.
            const execRaw = firstSentences(content, 3) || item.description || '';
            const mitRaw = extractMitigation(fullText, execRaw);
            if (lang === 'pt') {
                const [t, ex, mit] = await Promise.all([
                    translateProtected(item.title, 'pt'),
                    translateProtected(execRaw, 'pt'),
                    mitRaw ? translateProtected(mitRaw, 'pt') : Promise.resolve(''),
                ]);
                payload = {
                    available: false, source: 'translate', scraped: !!fullText,
                    title: t || item.title, executiveSummary: ex || execRaw, impactMitigation: mit || '', iocs, iocSources, ...enriched,
                };
            } else {
                payload = {
                    available: false, source: 'rss', scraped: !!fullText,
                    title: item.title, executiveSummary: execRaw, impactMitigation: mitRaw || '', iocs, iocSources, ...enriched,
                };
            }
        }

        cacheSet(memoryCache.newsletterEnrich.store, cacheKey, { data: payload, expiresAt: now + memoryCache.newsletterEnrich.ttl }, 500);
        res.json(payload);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// True when an IPv4/IPv6 address is private, loopback, link-local or otherwise
// not a routable public host — the set of targets an SSRF attempt would aim at.
const isPrivateAddress = (ip) => {
    const kind = net.isIP(ip);
    if (kind === 4) {
        const p = ip.split('.').map(Number);
        if (p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;
        const [a, b] = p;
        return (
            a === 0 || a === 10 || a === 127 ||                 // this-net, private, loopback
            (a === 100 && b >= 64 && b <= 127) ||               // CGNAT 100.64/10
            (a === 169 && b === 254) ||                          // link-local
            (a === 172 && b >= 16 && b <= 31) ||                 // private
            (a === 192 && b === 168) ||                          // private
            (a === 192 && b === 0) ||                            // 192.0.0/24 + TEST-NET-1
            (a === 198 && (b === 18 || b === 19)) ||             // benchmarking
            a >= 224                                             // multicast + reserved
        );
    }
    if (kind === 6) {
        const v = ip.toLowerCase();
        return (
            v === '::' || v === '::1' ||                         // unspecified, loopback
            v.startsWith('fe80') || v.startsWith('fc') || v.startsWith('fd') || // link-local, ULA
            v.startsWith('::ffff:') || v.startsWith('::')        // IPv4-mapped / embedded
        );
    }
    return true; // not a recognised IP literal
};

// SSRF guard for user-pasted URLs: enforce http(s), reject embedded credentials
// and non-standard ports, then resolve every A/AAAA record and ensure none point
// at a private/loopback/reserved address. Throws an Error with a safe message.
const assertSafePublicUrl = async (raw) => {
    let parsed;
    try {
        parsed = new URL(raw);
    } catch {
        throw new Error('Invalid URL');
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error('URL must be http(s)');
    }
    if (parsed.username || parsed.password) {
        throw new Error('URL must not contain credentials');
    }
    if (parsed.port && !['', '80', '443'].includes(parsed.port)) {
        throw new Error('Only standard web ports are allowed');
    }
    const host = parsed.hostname.replace(/^\[|\]$/g, '');
    // isPrivateAddress só entende IP literal; para um IP-literal no host (ex.:
    // http://10.0.0.1) bloqueia se for privado. Hostnames (ex.: example.com)
    // são validados logo abaixo pela resolução DNS — net.isIP() devolve 0 p/
    // hostname, então não caímos no `return true` de "não é IP".
    if (host === 'localhost' || (net.isIP(host) && isPrivateAddress(host))) {
        throw new Error('URL resolves to a non-public host');
    }
    let records;
    try {
        records = await dns.promises.lookup(host, { all: true });
    } catch {
        throw new Error('Could not resolve URL host');
    }
    if (!records.length || records.some((r) => isPrivateAddress(r.address))) {
        throw new Error('URL resolves to a non-public host');
    }
};


// Exploited CVEs from CISA KEV
const vulnerabilityCatalog = createVulnerabilityCatalog({
    filePath: process.env.NODE_ENV === 'test' ? ':memory:' : path.join(__dirname, '.vulnerability-catalog.sqlite'),
    nvdApiKey: process.env.NODE_ENV === 'test' ? undefined : process.env.NVD_API_KEY,
    fetchKev: async () => {
        const rows = await getKevCatalog();
        if (memoryCache.kev.expiresAt <= Date.now() || !rows.length) throw new Error('KEV source is stale');
        return rows;
    },
});
const vulnerabilityQueries = process.env.NODE_ENV === 'test' ? null : createVulnerabilityQueries({ filePath: path.join(__dirname, '.vulnerability-catalog.sqlite') });
const vulnerabilityOptimization = process.env.NODE_ENV === 'test' ? Promise.resolve() : optimizeVulnerabilityCatalog(path.join(__dirname, '.vulnerability-catalog.sqlite')).catch(error => { console.warn('Catalog optimization failed:', error.code || error.name); });
async function queryVulnerabilities(method, params) {
    await vulnerabilityOptimization;
    const data = vulnerabilityQueries ? await vulnerabilityQueries.query(method, params) : vulnerabilityCatalog[method](params);
    if (data?.status) data.status = vulnerabilityCatalog.status();
    return data;
}
const catalogUnavailable = (res) => res.status(503).json({ error: 'O catálogo está ocupado. Tente novamente em alguns instantes.' });
app.use('/api/vulnerabilities', (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
// Compatibility for older consumers; only imported source records, no synthetic fallback.
app.get('/api/cves/recent', async (req, res) => {
    res.set('Cache-Control', 'no-store');
    try { res.json((await queryVulnerabilities('list', { size: 50 })).rows.map(row => ({
        id: row.id, cvss: row.cvss, summary: row.description, Published: row.published,
        Modified: row.modified, source: row.source, vectorString: row.vector,
        references: row.references.map(reference => reference.url),
    }))); } catch { catalogUnavailable(res); }
});
app.get('/api/vulnerabilities/overview', async (req, res) => {
    try { res.json(await queryVulnerabilities('overview')); } catch { catalogUnavailable(res); }
});
app.get('/api/vulnerabilities', async (req, res) => { try { res.json(await queryVulnerabilities('list', {
    view: ['listing', 'top', 'weaponized'].includes(req.query.view) ? req.query.view : 'listing',
    query: typeof req.query.q === 'string' ? req.query.q : '',
    severity: typeof req.query.severity === 'string' ? req.query.severity : '',
    vendor: typeof req.query.vendor === 'string' ? req.query.vendor : '',
    signal: typeof req.query.signal === 'string' ? req.query.signal : '',
    page: req.query.page, size: req.query.size,
})); } catch { catalogUnavailable(res); } });
app.post('/api/vulnerabilities/refresh', requireAuth, async (req, res) => {
    await vulnerabilityOptimization;
    void vulnerabilityCatalog.sync({ force: true });
    res.status(202).json({ status: vulnerabilityCatalog.status() });
});
app.get('/api/vulnerabilities/:id', async (req, res) => {
    try {
    const data = await queryVulnerabilities('detail', String(req.params.id).toUpperCase());
    return data ? res.json(data) : res.status(404).json({ error: 'CVE not found in the imported catalog' });
    } catch { catalogUnavailable(res); }
});
app.get('/api/cves/exploited', async (req, res) => {
    const now = Date.now();
    if (memoryCache.exploitedCves.data && memoryCache.exploitedCves.expiresAt > now) {
        return res.json(memoryCache.exploitedCves.data);
    }

    try {
        // Reuse the shared KEV catalog instead of re-fetching the same CISA feed.
        const vulnerabilities = await getKevCatalog();
        const sorted = [...vulnerabilities]
            .sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded))
            .slice(0, 50);

        memoryCache.exploitedCves.data = sorted;
        memoryCache.exploitedCves.expiresAt = now + memoryCache.exploitedCves.ttl;
        return res.json(sorted);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// ============================================================
//  SAP Security Patch Day (scraped monthly HTML)
// ============================================================

// Fetch the latest available SAP Patch Day page and normalize it. Tries the
// latest patch month; if its page 404s (not published yet), falls back one month
// so we always serve the most recent notes that exist.
async function fetchSapPatch() {
    const primary = latestPatchMonth();
    const prevMonth = primary.month === 0 ? 11 : primary.month - 1;
    const prevYear = primary.month === 0 ? primary.year - 1 : primary.year;
    const candidates = [primary.url, monthUrl(prevYear, prevMonth)];

    let lastErr = null;
    for (const url of candidates) {
        try {
            const resp = await axios.get(url, {
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    Accept: 'text/html,application/xhtml+xml',
                },
                timeout: 15000,
                maxRedirects: 3,
                responseType: 'text',
            });
            const { releaseDate, notes } = parseSapNotes(resp.data);
            if (!notes.length) { lastErr = new Error('SAP page had no parseable notes'); continue; }
            const sorted = sortSapNotes(notes);
            return { url, releaseDate, notes: sorted, summary: summarizeSap(sorted) };
        } catch (err) {
            lastErr = err;
            // A non-404 failure (timeout, block, 5xx) won't be fixed by trying an
            // older month — stop and surface it (or serve stale cache upstream).
            if (err.response?.status && err.response.status !== 404) break;
        }
    }
    throw lastErr || new Error('SAP patch fetch failed');
}

// Latest SAP Security Patch Day. Recomputed monthly on demand; cached 24h.
app.get('/api/sap-patch', async (req, res) => {
    const now = Date.now();
    if (memoryCache.sapPatch.data && memoryCache.sapPatch.expiresAt > now) {
        res.set('Cache-Control', 'public, max-age=3600');
        return res.json(memoryCache.sapPatch.data);
    }
    try {
        const data = await fetchSapPatch();
        memoryCache.sapPatch.data = data;
        memoryCache.sapPatch.expiresAt = now + memoryCache.sapPatch.ttl;
        res.set('Cache-Control', 'public, max-age=3600');
        res.json(data);
    } catch (error) {
        // Degrade to stale cache when the live fetch fails; else a clear error.
        if (memoryCache.sapPatch.data) return res.json(memoryCache.sapPatch.data);
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// ============================================================
//  Microsoft Patch Tuesday (MSRC CVRF v3.0) Summary
// ============================================================

const MSRC_BASE = 'https://api.msrc.microsoft.com/cvrf/v3.0';

// Fetch the live list of monthly "Security Updates" from MSRC and cache it
async function fetchAndCacheMonths() {
    const response = await axios.get(`${MSRC_BASE}/updates`, {
        headers: { Accept: 'application/json' },
        timeout: 12000
    });
    const months = (response.data?.value || [])
        .filter(m => /Security Updates/i.test(m.DocumentTitle || '') && !isEarlyDoc(m.DocumentTitle))
        .map(m => ({
            id: m.ID,
            title: m.DocumentTitle,
            initialReleaseDate: m.InitialReleaseDate,
            currentReleaseDate: m.CurrentReleaseDate
        }))
        .sort((a, b) => new Date(b.initialReleaseDate) - new Date(a.initialReleaseDate));

    memoryCache.patchTuesdayMonths.data = months;
    memoryCache.patchTuesdayMonths.expiresAt = Date.now() + memoryCache.patchTuesdayMonths.ttl;
    return months;
}

// Fetch + normalize the CVRF document for one month and cache it.
// Returns null when the month's document is still the pre-release "Early" draft,
// which must never be cached or served — doing so lets it masquerade as the real
// Patch Tuesday for a full TTL after Microsoft swaps in the final document.
// The entry records currentReleaseDate so callers can detect that swap.
async function fetchAndCacheSummary(id) {
    const response = await axios.get(`${MSRC_BASE}/cvrf/${id}`, {
        headers: { Accept: 'application/json' },
        timeout: 20000
    });
    const summary = normalizeCvrf(response.data);
    if (isEarlyDoc(summary.title)) return null;
    cacheSet(
        memoryCache.patchTuesday.store,
        id,
        { data: summary, currentReleaseDate: summary.currentReleaseDate, expiresAt: Date.now() + memoryCache.patchTuesday.ttl },
        36
    );
    return summary;
}

// Background refresher: keeps the month list current (detects each new Patch
// Tuesday within one TTL) and re-normalizes the latest month so mid-month
// revisions by Microsoft are reflected and the cache stays warm.
async function refreshPatchTuesday() {
    try {
        const months = await fetchAndCacheMonths();
        if (months.length) {
            await fetchAndCacheSummary(months[0].id);
            console.log(`[PatchTuesday] Refreshed. Latest month: ${months[0].id}`);
        }
    } catch (error) {
        console.error('Failed to refresh Patch Tuesday data:', error.message);
    }
}

// List available Patch Tuesday months
app.get('/api/patch-tuesday/months', async (req, res) => {
    const now = Date.now();
    if (memoryCache.patchTuesdayMonths.data && memoryCache.patchTuesdayMonths.expiresAt > now) {
        res.set('Cache-Control', 'public, max-age=3600');
        return res.json(memoryCache.patchTuesdayMonths.data);
    }
    try {
        res.set('Cache-Control', 'public, max-age=3600');
        res.json(await fetchAndCacheMonths());
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// Normalized summary for a single Patch Tuesday month (e.g. /api/patch-tuesday/2026-Jun)
app.get('/api/patch-tuesday/:id', async (req, res) => {
    const id = req.params.id;
    if (!/^\d{4}-[A-Za-z]{3}$/.test(id)) {
        return res.status(400).json({ error: 'Invalid month identifier. Expected format YYYY-Mon (e.g. 2026-Jun).' });
    }

    const now = Date.now();
    const cached = memoryCache.patchTuesday.store.get(id);

    // A CVRF document mutates in place behind a stable id (draft -> release, then
    // mid-month revisions), so the id alone is not a sound cache key. The month
    // list is cheap and carries CurrentReleaseDate: treat it as the validator and
    // refetch whenever Microsoft has revised the document we cached.
    const known = memoryCache.patchTuesdayMonths.data?.find(m => m.id === id);
    const revised = cached && known && cached.currentReleaseDate !== known.currentReleaseDate;

    if (cached && !revised && cached.expiresAt > now) {
        res.set('Cache-Control', 'public, max-age=3600');
        return res.json(cached.data);
    }

    try {
        const summary = await fetchAndCacheSummary(id);
        if (!summary) {
            return res.status(404).json({ error: 'Security updates for this month have not been released yet.' });
        }
        res.set('Cache-Control', 'public, max-age=3600');
        res.json(summary);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// Threat actors catalog (MITRE ATT&CK Groups ∪ MISP galaxy) — built offline by
// server/scripts/build-actors.mjs into server/data/actors.json. Public.
// Loaded once — the JSON is static, so the actors list and its country facet are
// computed a single time and cached for the process lifetime.
let ACTORS_CACHE = null;
const loadActors = () => {
    if (ACTORS_CACHE) return ACTORS_CACHE;
    let actors = [];
    try {
        const raw = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'actors.json'), 'utf8'));
        actors = Array.isArray(raw.actors) ? raw.actors : [];
    } catch (err) {
        console.error('Failed to load actors.json (run build-actors.mjs):', err.message);
    }
    // Vitimologia (setor/região atacada) sai da descrição — ver actorProfile.js.
    // Feito uma vez aqui porque a descrição só existe no objeto completo, e a
    // listagem (que é onde os filtros rodam) não carrega descrição.
    let logos = {};
    try { logos = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'actor-logos.json'), 'utf8')).logos || {}; } catch { /* initials remain available */ }
    actors = actors.map((actor) => ({ ...actor, ...actorTargeting(actor), logo: logos[actor.id]?.url || null, logoSource: logos[actor.id]?.source || null }));
    const facet = (key) => [...new Set(actors.flatMap((a) => a[key] || []).filter(Boolean))].sort();
    ACTORS_CACHE = {
        actors,
        countries: [...new Set(actors.map(a => a.country).filter(Boolean))].sort(),
        sectors: facet('sectors'),
        targets: facet('targets'),
    };
    return ACTORS_CACHE;
};

// ─── Contexto da organização ───────────────────────────────────────────────
// Configurar não é consumir, então as rotas de perfil pedem só sessão. A de
// sugestões lê o watchlist e herda o requirePremium dele.
const orgError = (res, error) => {
    if (error && error.status && error.publicMessage) {
        return res.status(error.status).json({ error: error.publicMessage });
    }
    const { status, message } = sanitizeError(error);
    res.status(status).json({ error: message });
};

const knownActorIds = () => new Set(loadActors().actors.map((actor) => actor.id));

// Varrer 1362 atores a cada abertura da tela de Notícias é desperdício: o
// perfil só muda quando alguém edita, e updatedAt já marca isso.
const threatModelCache = new Map();
const cachedThreatModel = (profile) => {
    const key = `${profile.id}:${profile.updatedAt}`;
    if (!threatModelCache.has(key)) {
        if (threatModelCache.size > 50) threatModelCache.clear();
        threatModelCache.set(key, buildThreatModel(profile, loadActors().actors));
    }
    return threatModelCache.get(key);
};

app.get('/api/org/vocab', requireAuth, (_req, res) => {
    res.set('Cache-Control', 'private, max-age=3600');
    res.json({ sectors: ORG_SECTORS, regions: ORG_REGIONS });
});

app.get('/api/org/profiles', requireAuth, (req, res) => {
    res.json({ profiles: orgProfileStore.list(req.user.sub) });
});

app.post('/api/org/profiles', requireAuth, (req, res) => {
    try {
        res.status(201).json(orgProfileStore.create(req.user, req.body || {}, new Date().toISOString(), knownActorIds()));
    } catch (error) { orgError(res, error); }
});

app.patch('/api/org/profiles/:id', requireAuth, (req, res) => {
    try {
        res.json(orgProfileStore.update(req.user.sub, String(req.params.id), req.body || {}, new Date().toISOString(), knownActorIds()));
    } catch (error) { orgError(res, error); }
});

app.delete('/api/org/profiles/:id', requireAuth, (req, res) => {
    if (!orgProfileStore.remove(req.user.sub, String(req.params.id))) {
        return res.status(404).json({ error: 'perfil não encontrado' });
    }
    // Os achados de phishing são do perfil: sem isto viram lixo órfão que
    // ninguém vê e que a retenção nunca alcança.
    phishWatchStore.dropProfile(String(req.params.id));
    phishTicketStore.dropProfile(String(req.params.id));
    res.json({ ok: true });
});

app.get('/api/org/profiles/:id/threat-model', requireAuth, (req, res) => {
    try {
        res.json(cachedThreatModel(orgProfileStore.get(req.user.sub, String(req.params.id))));
    } catch (error) { orgError(res, error); }
});

// Os produtos detectados ficam em finding.product, dentro dos snapshots — um
// por ativo. Varrer aqui evita um N+1 de requisições no navegador.
app.get('/api/org/asset-suggestions', requirePremium, (req, res) => {
    const byProduct = new Map();
    for (const asset of exposureStore.listAssets(req.user.sub)) {
        const snapshot = exposureStore.previousSuccessfulSnapshot(req.user.sub, asset.id);
        for (const finding of snapshot?.findings || []) {
            const product = String(finding.product || '').trim();
            if (!product) continue;
            const entry = byProduct.get(product.toLowerCase()) || { vendor: '', product, versions: [], seenOn: [] };
            if (finding.version && !entry.versions.includes(finding.version)) entry.versions.push(finding.version);
            if (!entry.seenOn.includes(asset.label)) entry.seenOn.push(asset.label);
            byProduct.set(product.toLowerCase(), entry);
        }
    }
    res.json({ suggestions: [...byProduct.values()].sort((a, b) => a.product.localeCompare(b.product)) });
});

// List (slim) + facets. The client fetches once and searches/filters in-memory.
app.get('/api/actors', (req, res) => {
    const { actors, countries, sectors, targets } = loadActors();
    res.set('Cache-Control', 'public, max-age=21600');
    res.json({
        total: actors.length,
        countries,
        sectors,
        targets,
        actors: actors.map(a => ({
            id: a.id, name: a.name, aliases: a.aliases || [], country: a.country || '', logo: a.logo, logoSource: a.logoSource,
            motivation: a.motivation || '', source: a.source,
            sectors: a.sectors || [], targets: a.targets || [],
            technique_count: (a.techniques || []).length,
            techniques: (a.techniques || []).map((technique) => technique.id).filter(Boolean),
        })),
    });
});

// Índice família de malware → grupos, consumido pelo enriquecimento de
// indicadores: ThreatFox e VirusTotal devolvem a família, o cliente quer o
// grupo. Registrado ANTES de /api/actors/:id, senão o :id engole a rota.
let softwareIndexCache = null;
let actorNameIndexCache = null;
app.get('/api/actors/software-index', (req, res) => {
    const { actors } = loadActors();
    softwareIndexCache ||= buildSoftwareIndex(actors);
    // `names` viaja junto porque quem usa um usa o outro: o enriquecimento
    // precisa da ponte família→grupo E de saber se o `adversary` que a OTX
    // mandou é um grupo de verdade ou texto que o analista digitou.
    actorNameIndexCache ||= buildActorNameIndex(actors);
    res.set('Cache-Control', 'public, max-age=21600');
    res.json({ index: softwareIndexCache, names: actorNameIndexCache });
});

// Full detail for one actor.
app.get('/api/actors/activity', requirePremium, (req, res) => {
    res.set('Cache-Control', 'private, no-store');
    res.json({ days: 180, activity: buildActorActivity(actorPublications(newsArchiveStore.all(), newsStoryStore.all())) });
});
app.get('/api/actors/:id/evidence', requirePremium, (req, res) => {
    if (!knownActorIds().has(req.params.id)) return res.status(404).json({ error: 'Actor not found' });
    const days = req.query.days == null ? 180 : Number(req.query.days);
    if (![0, 30, 90, 180, 365].includes(days)) return res.status(400).json({ error: 'Invalid time range' });
    res.set('Cache-Control', 'private, no-store');
    res.json(buildActorEvidence(actorPublications(newsArchiveStore.all(), newsStoryStore.all()), req.params.id, { days }));
});
app.get('/api/actors/:id', (req, res) => {
    const actor = loadActors().actors.find(a => a.id === req.params.id);
    if (!actor) return res.status(404).json({ error: 'actor not found' });
    res.set('Cache-Control', 'public, max-age=21600');
    res.json(actor);
});

// DNS Record Lookup
app.post('/api/dns/lookup', scanLimiter, async (req, res) => {
    const { query } = req.body;
    try {
        const sanitized = sanitizeQuery(query, 'domain');

        const resolveSafe = async (resolverFn) => {
            try {
                return await resolverFn(sanitized);
            } catch (err) {
                return [];
            }
        };

        const [a, aaaa, mx, txt, ns, cname, dumpster] = await Promise.all([
            resolveSafe(dns.promises.resolve4),
            resolveSafe(dns.promises.resolve6),
            resolveSafe(dns.promises.resolveMx),
            resolveSafe(dns.promises.resolveTxt),
            resolveSafe(dns.promises.resolveNs),
            resolveSafe(dns.promises.resolveCname),
            (async () => {
                try {
                    const key = process.env.DNSDUMPSTER_API_KEY;
                    if (!key) return null;
                    const response = await axios.get(`https://api.dnsdumpster.com/domain/${sanitized}`, {
                        headers: { 'X-API-Key': key },
                        timeout: 12000
                    });
                    return response.data;
                } catch (err) {
                    console.error("DNSDumpster API error:", err.message || err);
                    return null;
                }
            })()
        ]);

        const flatTxt = txt.map(record => record.join(' '));

        try { domainIntelligence.observe(sanitized, { A: a, AAAA: aaaa, MX: mx.map(record => `${record.exchange} (priority: ${record.priority})`), TXT: flatTxt, NS: ns, CNAME: cname }); } catch { /* unsupported special-use domains do not enter the history store */ }

        res.json({
            domain: sanitized,
            records: {
                A: a,
                AAAA: aaaa,
                MX: mx.map(record => `${record.exchange} (priority: ${record.priority})`),
                TXT: flatTxt,
                NS: ns,
                CNAME: cname
            },
            dnsDumpster: dumpster
        });
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.post('/api/attack-surface', scanLimiter, async (req, res) => {
    try {
        // BYOK-first: chave do usuário no Settings, fallback pra chave compartilhada
        // do servidor (.env). Endpoint sem auth obrigatória: resolve a sessão se houver.
        const session = verifySession(getCookie(req, 'ts_session'));
        const result = await runAttackSurfaceScan(req.body, buildExposureScanDeps(session?.sub));
        res.json(result);
    } catch (error) {
        if (error.status && error.publicMessage) {
            return res.status(error.status).json({ error: error.publicMessage });
        }
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.get('/api/attack-surface/credits', scanLimiter, async (req, res) => {
    try {
        const session = verifySession(getCookie(req, 'ts_session'));
        res.json(await getShodanCreditStatus(buildExposureScanDeps(session?.sub)));
    } catch (error) {
        if (error.status && error.publicMessage) return res.status(error.status).json({ error: error.publicMessage });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.get('/api/exposure-watchlist/assets', requirePremium, (req, res) => {
    res.json({ assets: exposureStore.listAssets(req.user.sub) });
});

app.post('/api/exposure-watchlist/assets', requirePremium, (req, res) => {
    try {
        const asset = exposureStore.createAsset(req.user, req.body || {});
        res.status(201).json({ asset });
    } catch (error) {
        if (error.status && error.publicMessage) return res.status(error.status).json({ error: error.publicMessage });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.patch('/api/exposure-watchlist/assets/:id', requirePremium, (req, res) => {
    try {
        const asset = exposureStore.updateAsset(req.user.sub, req.params.id, req.body || {});
        res.json({ asset });
    } catch (error) {
        if (error.status && error.publicMessage) return res.status(error.status).json({ error: error.publicMessage });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.delete('/api/exposure-watchlist/assets/:id', requirePremium, (req, res) => {
    const deleted = exposureStore.deleteAsset(req.user.sub, req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Asset not found' });
    res.json({ ok: true });
});

app.post('/api/exposure-watchlist/assets/:id/run', requirePremium, scanLimiter, async (req, res) => {
    try {
        const snapshot = await runExposureSnapshot({
            store: exposureStore, assetId: req.params.id, ownerId: req.user.sub,
            runAttackSurfaceScan, scanDeps: buildExposureScanDeps(req.user.sub),
        });
        res.json({ snapshot, asset: exposureStore.getAsset(req.user.sub, req.params.id) });
    } catch (error) {
        if (error.status && error.publicMessage) return res.status(error.status).json({ error: error.publicMessage });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.get('/api/exposure-watchlist/assets/:id/snapshots', requirePremium, (req, res) => {
    try {
        res.json({ snapshots: exposureStore.listSnapshots(req.user.sub, req.params.id) });
    } catch (error) {
        if (error.status && error.publicMessage) return res.status(error.status).json({ error: error.publicMessage });
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

app.get('/api/exposure-watchlist/changes', requirePremium, (req, res) => {
    res.json({ changes: exposureStore.listChanges(req.user.sub, req.query.limit) });
});

// ─── Vigilância de marca · domínio recém-criado com a marca no nome ────────
// Os termos vigiados são as marcas do perfil da organização: um lugar só
// para o contexto do cliente, em vez de mais um cadastro paralelo.
const phishError = (res, error) => {
    if (error.status && error.publicMessage) return res.status(error.status).json({ error: error.publicMessage });
    const { status, message } = sanitizeError(error);
    res.status(status).json({ error: message });
};

app.get('/api/phishing-watch/hits', requirePremium, (req, res) => {
    const profileId = req.query.profileId ? String(req.query.profileId) : undefined;
    const status = req.query.status ? String(req.query.status) : undefined;
    res.json({
        configured: Boolean(urlscanClientFor(req.user.sub).search),
        hits: phishWatchStore.list(req.user.sub, { profileId, status }),
        run: profileId ? phishWatchStore.runOf(profileId) : null,
        intervalMs: PHISH_LIMITS.runIntervalMs,
    });
});

app.post('/api/phishing-watch/hits/:id/status', requirePremium, async (req, res) => {
    try {
        const status = String((req.body || {}).status || '');
        const hit = phishWatchStore.setStatus(req.user.sub, String(req.params.id), status);
        // Confirmar é dizer "isso é phishing mesmo": vira tarefa na hora, sem
        // depender do score que o robô deu.
        if (status === 'confirmed') await syncTicketsFromHits(req.user.sub, hit.profileId, { manualHitId: hit.id });
        res.json({ hit, ticket: phishTicketStore.byId(hit.id) });
    } catch (error) { phishError(res, error); }
});

app.get('/api/phishing-watch/tickets', requirePremium, (req, res) => {
    const profileId = req.query.profileId ? String(req.query.profileId) : undefined;
    const status = req.query.status ? String(req.query.status) : undefined;
    const tickets = phishTicketStore.list(req.user.sub, { profileId, status });
    res.json({ tickets, digest: buildDailyDigest(phishTicketStore.list(req.user.sub, { profileId })) });
});

app.get('/api/phishing-watch/tickets/:id', requirePremium, (req, res) => {
    try {
        const ticket = phishTicketStore.get(req.user.sub, String(req.params.id));
        const profile = orgProfileStore.get(req.user.sub, ticket.profileId);
        const brand = ticket.term || (profile.brands || [])[0] || '';
        res.json({
            ticket,
            takedown: {
                pt: takedownRequest(ticket, { language: 'pt', brand }),
                en: takedownRequest(ticket, { language: 'en', brand }),
            },
        });
    } catch (error) { phishError(res, error); }
});

app.post('/api/phishing-watch/tickets/:id/status', requirePremium, (req, res) => {
    try {
        const body = req.body || {};
        const ticket = phishTicketStore.setStatus(req.user.sub, String(req.params.id), String(body.status || ''), {
            at: new Date().toISOString(),
            by: req.user.login || 'analista',
            note: String(body.note || '').slice(0, 500),
        });
        res.json({ ticket });
    } catch (error) { phishError(res, error); }
});

app.post('/api/phishing-watch/run', requirePremium, scanLimiter, async (req, res) => {
    const { search } = urlscanClientFor(req.user.sub);
    if (!search) return res.status(500).json({ error: 'Configure uma chave urlscan.io em Chaves de API' });
    try {
        // getProfile confere o dono: perfil de outro usuário responde 404.
        const profile = orgProfileStore.get(req.user.sub, String((req.body || {}).profileId || ''));
        const outcome = await runProfileWatch({ store: phishWatchStore, profile, search });
        const opened = await syncTicketsFromHits(req.user.sub, profile.id);
        res.json({
            ...outcome,
            openedTickets: opened.length,
            hits: phishWatchStore.list(req.user.sub, { profileId: profile.id, status: 'new' }),
            run: phishWatchStore.runOf(profile.id),
        });
    } catch (error) { phishError(res, error); }
});

// Vendors API Status
// Cota restante por base, pra faixa abaixo da barra de busca. Exige login: o
// número expõe o consumo das chaves do servidor, e é o mesmo público que ganha
// isenção do rate limiter — quem não tem limite é quem enxerga o teto real.
app.get('/api/vendors/quotas', requireAuth, async (req, res) => {
    try {
        res.json({ quotas: await quotaReader.read() });
    } catch (error) {
        console.error('vendor quotas failed:', error.message);
        res.status(502).json({ error: 'falha ao ler cotas' });
    }
});

app.get('/api/vendors/status', (req, res) => {
    // Um item por fonte de VENDOR_IOC_SUPPORT (src/services/threatApi.ts), que é
    // quem decide a quem a consulta vai. Faltavam nove nomes aqui, e a tela de
    // Fontes de Dados deixava cada um deles em "VERIFICANDO" para sempre —
    // ausente no mapa é indistinguível de resposta que não chegou. O contador do
    // topo também dividia por 9 enquanto a página mostrava 18 cartões, e contava
    // urlscan.io, que não é cartão nenhum.
    //
    // Use getKeys() so providers configured only via numbered fallback vars
    // (e.g. VIRUSTOTAL2_API_KEY) still report as available.
    const hasKey = (envName) => getKeys(envName).length > 0;
    const status = {
        // Precisam de chave: sem ela a rota responde erro.
        "VirusTotal": hasKey('VIRUSTOTAL_API_KEY'),
        "AbuseIPDB": hasKey('ABUSEIPDB_API_KEY'),
        "Shodan": hasKey('SHODAN_API_KEY') || !!getUserApiKey(verifySession(getCookie(req, 'ts_session'))?.sub, 'shodan'),
        "WHOIS": hasKey('WHOIS_API_KEY'),
        // Conectores públicos permitem consulta sem chave; isto não é um healthcheck.
        "AlienVault OTX": true,
        "URLhaus": !!abuseChKey(req),
        "MalwareBazaar": !!abuseChKey(req),
        "ThreatFox": !!abuseChKey(req),
        "PhishTank": true,
        "PhishStats": true,
        "OpenPhish": true,
        "IP Geolocation": true
    };
    res.json(status);
});

// Serve frontend in production
if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.join(__dirname, '../dist')));
    app.get(/(.*)/, (req, res) => {
        res.sendFile(path.join(__dirname, '../dist/index.html'));
    });
}

function scheduleDailyEdition() {
    const now = new Date();
    const nextRun = new Date(`${new Date(now.getTime() + 21 * 60 * 60 * 1000).toISOString().slice(0, 10)}T03:05:00.000Z`);
    if (nextRun <= now) nextRun.setUTCDate(nextRun.getUTCDate() + 1);
    const timer = setTimeout(async () => {
        try {
            await dailyEditionGenerator.generate(getCompletedDate(new Date()));
        } catch (error) {
            console.error('daily edition scheduled generation failed:', error.message || error);
        } finally {
            scheduleDailyEdition();
        }
    }, nextRun.getTime() - now.getTime());
    timer.unref?.();
}

app.listen(PORT, () => {
    // Unit/API tests invoke collectors explicitly with controlled inputs.
    // Booting a test server must not launch real scheduled collections.
    if (process.env.NODE_ENV === 'test') return;
    console.log(`Server running on port ${PORT}`);
    let vulnerabilityRetries = 0;
    const refreshVulnerabilities = async () => {
        try {
            await vulnerabilityOptimization;
            await vulnerabilityCatalog.sync();
            if (Object.values(vulnerabilityCatalog.status().sources).some(source => ['error', 'stale'].includes(source.status)) && vulnerabilityRetries < 3) {
                vulnerabilityRetries++;
                setTimeout(refreshVulnerabilities, 60_000).unref();
            }
        } catch (error) { console.warn('Vulnerability catalog refresh failed:', error.code || error.name); }
    };
    setTimeout(refreshVulnerabilities, 1000).unref();
    setInterval(() => { vulnerabilityRetries = 0; void refreshVulnerabilities(); }, 6 * 60 * 60 * 1000).unref();
    // Prime the newsletter RSS feed cache and schedule background updates
    refreshNewsletterFeed();
    setInterval(refreshNewsletterFeed, memoryCache.newsletter.ttl);

    // Prime the Patch Tuesday cache and refresh it so each new monthly release
    // (and mid-month revisions) is picked up automatically.
    refreshPatchTuesday();
    setInterval(refreshPatchTuesday, memoryCache.patchTuesdayMonths.ttl);
    if (process.env.NODE_ENV !== 'test' && process.env.EXPOSURE_WATCHLIST_DISABLE_DAILY !== 'true') {
        setTimeout(runExposureSchedulerTick, 30_000);
        setInterval(runExposureSchedulerTick, 15 * 60 * 1000);
        // Mesmo tick de 15 min do exposure; quem decide a hora é o
        // selectDueProfiles, que só deixa passar perfil vencido há uma hora.
        setTimeout(runPhishWatchTick, 60_000);
        setInterval(runPhishWatchTick, 15 * 60 * 1000);
    }
    scheduleDailyEdition();
});
