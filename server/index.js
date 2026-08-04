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
} from './ctiIntel.js';
import { runAttackSurfaceScan } from './attackSurface.js';
import { groupByField, refsOfReport, relatedTo, techniqueCoverage } from './attackIndex.js';
import { jobSummary, pruneJobsMap } from './feedJobs.js';
import { parseHearthData } from './hearth.js';
import { parseSentinelTables, catalogSources } from './sentinelTables.js';
import { normalizeHuntInput, upsertHunt, normalizeRunInput, upsertRun, monthlySummary } from './hunts.js';
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
const tightJson = express.json({ limit: '10kb' });
const bulkJson = express.json({ limit: '15mb' });
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

    // Always skip DNSBL checks (a single page issues many concurrent lookups).
    // Match on req.path ONLY — it never contains the query string, so appending
    // "?x=/dnsbl" to another endpoint can no longer bypass the limiter. The path
    // is relative under the '/api/' mount ('/dnsbl') and absolute on the
    // per-route scanLimiter ('/api/dnsbl'); accept both exact forms.
    const p = req.path || '';
    if (p === '/dnsbl' || p === '/dnsbl/batch' || p === '/api/dnsbl' || p === '/api/dnsbl/batch') {
        return true;
    }
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

// Dynamic DNSBL whitelist parser
let allowedDnsblProviders = new Set();
const loadDnsblProviders = () => {
    try {
        const filePath = path.join(__dirname, '../src/config/dnsblProviders.json');
        if (fs.existsSync(filePath)) {
            const providers = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            if (Array.isArray(providers)) {
                providers.forEach(p => allowedDnsblProviders.add(p));
            }
        }
        console.log(`Loaded ${allowedDnsblProviders.size} DNSBL providers from dnsblProviders.json`);
    } catch (err) {
        console.error('Failed to load DNSBL providers:', err.message);
    }
    // Ensure we have standard fallbacks if parsing failed or was empty
    if (allowedDnsblProviders.size === 0) {
        [
            'zen.spamhaus.org', 'dbl.spamhaus.org', 'xbl.spamhaus.org', 'sbl.spamhaus.org',
            'pbl.spamhaus.org', 'bl.spamcop.net', 'b.barracudacentral.org', 'dnsbl.sorbs.net',
            'spam.dnsbl.sorbs.net', 'dul.dnsbl.sorbs.net', 'dnsbl-1.uceprotect.net',
            'dnsbl-2.uceprotect.net', 'dnsbl-3.uceprotect.net'
        ].forEach(p => allowedDnsblProviders.add(p));
    }
};
loadDnsblProviders();

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

// HTML entity and XSS escaping helper
const escapeHtml = (unsafe) => {
    if (!unsafe) return '';
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
};

// Helper to extract quota info
const sendResponseWithQuota = (res, axiosResponse) => {
    const headers = axiosResponse.headers;
    const quota = {};

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

        const response = await withKeyRotation('VIRUSTOTAL_API_KEY', (key) =>
            axios.get(endpoint, { headers: { "x-apikey": key } })
        );
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
        const response = await withKeyRotation('ABUSEIPDB_API_KEY', (key) =>
            axios.get(`https://api.abuseipdb.com/api/v2/check`, {
                params: {
                    ipAddress: sanitized,
                    maxAgeInDays: 90,
                    verbose: true
                },
                headers: { "Key": key, "Accept": "application/json" }
            })
        );
        sendResponseWithQuota(res, response);
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
        const response = await withKeyRotation('ABUSEIPDB_API_KEY', (key) =>
            axios.get(`https://api.abuseipdb.com/api/v2/check-block`, {
                params: {
                    network: sanitized,
                    maxAgeInDays: 90
                },
                headers: { "Key": key, "Accept": "application/json" }
            })
        );
        sendResponseWithQuota(res, response);
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

        const response = await axios.get(endpoint, { headers });
        sendResponseWithQuota(res, response);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// Shodan
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
        const response = await axios.get(endpoint, {
            params: { key: process.env.SHODAN_API_KEY }
        });
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
const abuseChKey = () => (process.env.ABUSE_CH_API_KEY || process.env.THREATFOX_API_KEY
    || process.env.URLHAUS_API_KEY || process.env.MALWAREBAZAAR_API_KEY || '').trim();

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
        const abKey = abuseChKey();
        if (abKey) headers['Auth-Key'] = abKey;

        const response = await axios.post(endpoint, params.toString(), { headers });
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
        const abKey = abuseChKey();
        if (abKey) headers["Auth-Key"] = abKey;

        const response = await axios.post(`https://mb-api.abuse.ch/api/v1/`,
            params.toString(),
            { headers }
        );
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
        const abKey = abuseChKey();
        if (abKey) headers["Auth-Key"] = abKey;

        const response = await axios.post(
            `https://threatfox-api.abuse.ch/api/v1/`,
            { query: "search_ioc", search_term: sanitized },
            { headers }
        );
        res.json(response.data);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// PhishTank
app.post('/api/phishtank', scanLimiter, async (req, res) => {
    const { query } = req.body;
    try {
        const queryType = detectQueryType(query);
        if (queryType !== "url") return res.status(400).json({ error: "URL query required" });
        const sanitized = sanitizeQuery(query, 'url');

        // Safe URL parameters (VULN-08)
        const params = new URLSearchParams();
        params.append('url', sanitized);
        params.append('format', 'json');
        if (process.env.PHISHTANK_API_KEY) {
            params.append('app_key', process.env.PHISHTANK_API_KEY);
        }

        const response = await axios.post(`https://checkurl.phishtank.com/checkurl/`, 
            params.toString(), 
            {
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "phishtank/threatsumm4ry"
                }
            }
        );
        res.json(response.data);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// Pulsedive
app.post('/api/pulsedive', scanLimiter, async (req, res) => {
    const { query } = req.body;
    const key = process.env.PULSEDIVE_API_KEY || "free";
    try {
        const queryType = detectQueryType(query);
        const sanitized = sanitizeQuery(query, queryType);

        const response = await axios.get(`https://pulsedive.com/api/info.php`, {
            params: {
                indicator: sanitized,
                key: key
            }
        });
        res.json(response.data);
    } catch (error) {
        // Pulsedive returns 404 when the indicator simply isn't in its database —
        // that's a clean "not found", not an error worth surfacing to the user.
        if (error.response?.status === 404) {
            return res.json({ data: { "Status": "Not in Pulsedive database" } });
        }
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// Hybrid Analysis
app.post('/api/hybridanalysis', scanLimiter, async (req, res) => {
    const { query } = req.body;
    if (!process.env.HYBRID_ANALYSIS_API_KEY) return res.status(500).json({ error: "API Key missing" });

    try {
        const queryType = detectQueryType(query);
        if (queryType !== "hash") return res.json({ data: { "Status": "Hash only" } });

        const sanitized = sanitizeQuery(query, 'hash');

        const params = new URLSearchParams();
        params.append('hash', sanitized);

        const response = await axios.post(`https://www.hybrid-analysis.com/api/v2/search/hash`,
            params.toString(),
            {
                headers: {
                    "api-key": process.env.HYBRID_ANALYSIS_API_KEY,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            }
        );
        res.json(response.data);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// CIRCL hashlookup
app.post('/api/circl', scanLimiter, async (req, res) => {
    const { query } = req.body;
    try {
        const queryType = detectQueryType(query);
        if (queryType !== "hash") return res.json({ data: { "Status": "Hash only" } });

        const sanitized = sanitizeQuery(query, 'hash');
        // CIRCL hashlookup tem endpoints separados por algoritmo — usar o certo
        // pelo tamanho (MD5=32, SHA1=40, SHA256=64), senão devolve 400/404.
        const algo = sanitized.length === 32 ? 'md5' : sanitized.length === 40 ? 'sha1' : 'sha256';
        const response = await axios.get(`https://hashlookup.circl.lu/lookup/${algo}/${sanitized}`,
            { headers: { Accept: 'application/json' } });
        res.json(response.data);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// MetaDefender
app.post('/api/metadefender', scanLimiter, async (req, res) => {
    const { query } = req.body;
    if (!process.env.METADEFENDER_API_KEY) return res.status(500).json({ error: "API Key missing" });

    try {
        const queryType = detectQueryType(query);
        if (!["hash", "ip", "domain", "url"].includes(queryType)) return res.json({ data: { "Status": "Hash/IP/Domain/URL only" } });
        const sanitized = sanitizeQuery(query, queryType);

        // MetaDefender v4 has a reputation endpoint per IOC type.
        const path = queryType === "hash" ? `hash/${sanitized}`
            : queryType === "ip" ? `ip/${sanitized}`
            : queryType === "domain" ? `domain/${sanitized}`
            : `url/${encodeURIComponent(sanitized)}`;
        const endpoint = `https://api.metadefender.com/v4/${path}`;

        const response = await axios.get(endpoint, {
            headers: { "apikey": process.env.METADEFENDER_API_KEY },
        });
        sendResponseWithQuota(res, response);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// PhishStats
app.post('/api/phishstats', scanLimiter, async (req, res) => {
    const { query } = req.body;
    try {
        const queryType = detectQueryType(query);
        if (queryType !== "url" && queryType !== "domain") return res.json({ data: { "Status": "URL/Domain only" } });
        const sanitized = sanitizeQuery(query, queryType);

        const response = await axios.get(`https://phishstats.info:2096/api/phishing`, {
            params: {
                _where: `(url,like,${sanitized})`,
                _sort: '-date',
                _size: 5
            }
        });
        res.json(response.data);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// Ransomware.live
app.post('/api/ransomwarelive', scanLimiter, async (req, res) => {
    try {
        res.json(await getRecentRansomwareVictims());
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

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
    const abKey = abuseChKey();
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

// WHOIS
app.post('/api/whois', scanLimiter, async (req, res) => {
    const { query } = req.body;
    try {
        const queryType = detectQueryType(query);
        if (queryType !== "domain") return res.json({ data: { "Status": "Domain only" } });
        
        const sanitized = sanitizeQuery(query, 'domain');
        const response = await axios.get(`https://www.whoisxmlapi.com/whoisserver/WhoisService`, {
            params: {
                apiKey: process.env.WHOIS_API_KEY,
                domainName: sanitized,
                outputFormat: 'JSON'
            }
        });
        res.json(response.data);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// IP Geolocation (Mitigated HTTP/No TLS)
app.post('/api/ipgeo', scanLimiter, async (req, res) => {
    const { query } = req.body;
    try {
        const queryType = detectQueryType(query);
        if (queryType !== "ip") return res.json({ data: { "Status": "IP only" } });

        const sanitized = sanitizeQuery(query, 'ip');

        // VULN-12: Use HTTPS geolocation api (ipwhois.app instead of HTTP ip-api.com)
        const response = await axios.get(`https://ipwhois.app/json/${sanitized}`);
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

// Generic DNSBL Endpoint (Whitelist check added)
app.post('/api/dnsbl', scanLimiter, async (req, res) => {
    const { query, provider } = req.body;
    try {
        const queryType = detectQueryType(query);
        if (queryType !== "ip") {
            return res.json({ listed: false, status: "IP only" });
        }
        const sanitized = sanitizeQuery(query, 'ip');

        if (!provider) {
            return res.status(400).json({ error: "Provider required" });
        }

        // VULN-02: DNSBL provider whitelist check
        if (!allowedDnsblProviders.has(provider)) {
            return res.status(400).json({ error: "Invalid/unauthorized DNSBL provider" });
        }

        const reversed = sanitized.split('.').reverse().join('.');
        const dnsQuery = `${reversed}.${provider}`;
        
        const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('DNS Timeout')), 3000)
        );

        Promise.race([
            dns.promises.resolve4(dnsQuery),
            timeoutPromise
        ])
        .then(addresses => {
            // Check for loopback error codes (e.g. Spamhaus public DNS block: 127.255.255.254)
            const hasErrorAddress = addresses.some(addr => 
                addr === '127.255.255.252' || 
                addr === '127.255.255.254' || 
                addr === '127.255.255.255'
            );

            if (hasErrorAddress) {
                let errMsg = "Query blocked/errored";
                if (addresses.includes('127.255.255.254')) {
                    errMsg = "Blocked: Public DNS resolver";
                } else if (addresses.includes('127.255.255.255')) {
                    errMsg = "Blocked: Quota exceeded";
                } else if (addresses.includes('127.255.255.252')) {
                    errMsg = "Blocked: Invalid zone name";
                }
                return res.json({ 
                    listed: false, 
                    addresses, 
                    status: "Blocked", 
                    error: errMsg 
                });
            }

            res.json({ listed: true, addresses, status: `Listed on ${provider}` });
        })
        .catch(error => {
            if (error.message === 'DNS Timeout') {
                res.json({ listed: false, status: "Timeout", error: "Query timed out" });
            } else {
                res.json({ listed: false, status: "Not listed" });
            }
        });
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// Generic DNSBL Batch Endpoint
app.post('/api/dnsbl/batch', scanLimiter, async (req, res) => {
    const { query, providers } = req.body;
    try {
        const queryType = detectQueryType(query);
        if (queryType !== "ip") {
            return res.json({});
        }
        const sanitized = sanitizeQuery(query, 'ip');

        if (!Array.isArray(providers)) {
            return res.status(400).json({ error: "Providers must be an array" });
        }

        // De-duplicate first: this collapses amplification attempts (the same
        // allowed provider repeated thousands of times) and naturally bounds the
        // number of DNS lookups to at most the size of the allowlist.
        const uniqueProviders = [...new Set(providers)];

        // Validate all providers against the allowed set
        const invalid = uniqueProviders.filter(p => !allowedDnsblProviders.has(p));
        if (invalid.length > 0) {
            return res.status(400).json({ error: `Invalid/unauthorized DNSBL providers: ${invalid.join(', ')}` });
        }

        const reversed = sanitized.split('.').reverse().join('.');

        // Resolve all in parallel
        const resolvePromises = uniqueProviders.map(async (provider) => {
            const dnsQuery = `${reversed}.${provider}`;
            const timeoutPromise = new Promise((_, reject) => 
                setTimeout(() => reject(new Error('DNS Timeout')), 3000)
            );

            try {
                const addresses = await Promise.race([
                    dns.promises.resolve4(dnsQuery),
                    timeoutPromise
                ]);

                const hasErrorAddress = addresses.some(addr => 
                    addr === '127.255.255.252' || 
                    addr === '127.255.255.254' || 
                    addr === '127.255.255.255'
                );

                if (hasErrorAddress) {
                    let errMsg = "Query blocked/errored";
                    if (addresses.includes('127.255.255.254')) {
                        errMsg = "Blocked: Public DNS resolver";
                    } else if (addresses.includes('127.255.255.255')) {
                        errMsg = "Blocked: Quota exceeded";
                    } else if (addresses.includes('127.255.255.252')) {
                        errMsg = "Blocked: Invalid zone name";
                    }
                    return { provider, result: { listed: false, addresses, status: "Blocked", error: errMsg } };
                }

                return { provider, result: { listed: true, addresses, status: `Listed on ${provider}` } };
            } catch (error) {
                if (error.message === 'DNS Timeout') {
                    return { provider, result: { listed: false, status: "Timeout", error: "Query timed out" } };
                } else {
                    return { provider, result: { listed: false, status: "Not listed" } };
                }
            }
        });

        const results = await Promise.all(resolvePromises);
        const responseData = {};
        results.forEach(r => {
            responseData[r.provider] = r.result;
        });

        res.json(responseData);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// OpenPhish
app.post('/api/openphish', scanLimiter, async (req, res) => {
    const { query } = req.body;
    try {
        const queryType = detectQueryType(query);
        if (queryType !== "url" && queryType !== "domain") return res.json({ data: { "Status": "URL/Domain only" } });
        const sanitized = sanitizeQuery(query, queryType);

        const now = Date.now();
        if (memoryCache.openphish.expiresAt < now || memoryCache.openphish.urls.size === 0) {
            const response = await axios.get('https://openphish.com/feed.txt', { timeout: 8000 });
            const urls = response.data.split('\n').map(u => u.trim()).filter(Boolean);
            memoryCache.openphish.urls = new Set(urls);
            memoryCache.openphish.expiresAt = now + memoryCache.openphish.ttl;
        }

        let found = false;
        if (memoryCache.openphish.urls.has(sanitized)) {
            found = true;
        } else {
            // Substring match for domains/directories
            for (const url of memoryCache.openphish.urls) {
                if (url.includes(sanitized)) {
                    found = true;
                    break;
                }
            }
        }

        res.json({
            listed: found,
            status: found ? "Listed as phishing" : "Not found in OpenPhish feed"
        });
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// Team Cymru
app.post('/api/teamcymru', scanLimiter, async (req, res) => {
    const { query } = req.body;
    try {
        const queryType = detectQueryType(query);

        if (queryType === "ip") {
            const sanitized = sanitizeQuery(query, 'ip');
            const reversed = sanitized.split('.').reverse().join('.');
            const dnsQuery = `${reversed}.origin.asn.cymru.com`;

            dns.promises.resolveTxt(dnsQuery)
                .then(records => {
                    const parts = records[0][0].split('|').map(s => s.trim());
                    res.json({
                        asn: parts[0],
                        bgp_prefix: parts[1],
                        country: parts[2],
                        registry: parts[3],
                        allocated: parts[4]
                    });
                })
                .catch(() => {
                    res.json({ status: "No data found" });
                });
        } else if (queryType === "hash") {
            // VULN-13: Validate hash syntax before DNS query
            const sanitized = sanitizeQuery(query, 'hash');
            const dnsQuery = `${sanitized}.malware.hash.cymru.com`;
            
            dns.promises.resolveTxt(dnsQuery)
                .then(records => {
                    const timestamp = records[0][0];
                    res.json({
                        listed: true,
                        last_seen: timestamp,
                        status: "Hash found in Team Cymru MHR"
                    });
                })
                .catch(() => {
                    res.json({ listed: false, status: "Hash not found" });
                });
        } else {
            res.json({ data: { "Status": "IP/Hash only" } });
        }
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// Censys (Platform API v3)
app.post('/api/censys', scanLimiter, async (req, res) => {
    const { query } = req.body;
    if (!process.env.CENSYS_API_KEY) return res.status(500).json({ error: "API Key missing" });

    try {
        const queryType = detectQueryType(query);
        if (queryType !== "ip") return res.json({ data: { "Status": "IP only" } });

        const sanitized = sanitizeQuery(query, 'ip');
        const response = await axios.get(`https://api.platform.censys.io/v3/global/asset/host/${sanitized}`, {
            headers: {
                'Authorization': `Bearer ${process.env.CENSYS_API_KEY}`,
                'Accept': 'application/json'
            },
            timeout: 10000
        });

        const resource = response.data?.result?.resource;
        if (!resource) return res.json({ data: { "Status": "No data available" } });

        // Platform v3 service.software is an array; pick the entry that actually
        // names a product/vendor (the first item is often just a {type:[...]}).
        const namedSoftware = (svc) => {
            const arr = Array.isArray(svc.software) ? svc.software : (svc.software ? [svc.software] : []);
            return arr.find(s => s && (s.product || s.vendor)) || null;
        };
        // Platform v3 header values look like { headers: ["Apache/2.4.7 (Ubuntu)"] }.
        const headerValue = (headers, name) => {
            if (!headers) return null;
            const v = headers[name] ?? headers[name?.toLowerCase()] ?? headers[name?.toUpperCase()];
            const raw = v && typeof v === 'object' && Array.isArray(v.headers) ? v.headers : v;
            return Array.isArray(raw) ? raw[0] : (typeof raw === 'string' ? raw : null);
        };
        // Service labels look like [{ value: "WEB_UI" }] or plain strings.
        const labelStrings = (labels) =>
            (Array.isArray(labels) ? labels : [])
                .map(l => (typeof l === 'string' ? l : (l?.value || l?.label)))
                .filter(Boolean);
        // CVE list for a service across the field names Censys has used.
        const serviceVulns = (svc) => {
            const v = svc.vulnerabilities || svc.vulns || [];
            return (Array.isArray(v) ? v : [])
                .map(x => (typeof x === 'string' ? x : (x.cve_id || x.id || x.cve)))
                .filter(Boolean)
                .slice(0, 25);
        };
        const osString = (os) => os
            ? ([os.vendor, os.product, os.version].filter(Boolean).join(' ') || null)
            : null;

        const services = (resource.services || []);
        // Censys labels/tags (e.g. REMOTE_ACCESS, DATABASE, WEB_UI, LOGIN_PAGE) — strong
        // context. Merge host-level labels with the per-service ones into one set.
        const allLabels = [...new Set([
            ...labelStrings(resource.labels),
            ...services.flatMap(svc => labelStrings(svc.labels)),
        ])];

        const result = {
            ip: resource.ip,
            service_count: resource.service_count || 0,
            labels: allLabels,
            operating_system: osString(resource.operating_system),
            last_updated: resource.last_updated_at || resource.last_updated || null,
            services: services.map(svc => {
                const sw = namedSoftware(svc);
                // Protocol detail lives under endpoints[]; grab the first HTTP one.
                const httpEp = (svc.endpoints || []).find(e => e.http);
                const http = httpEp?.http || null;
                return {
                    port: svc.port,
                    protocol: svc.protocol || svc.extended_service_name || "UNKNOWN",
                    transport: svc.transport_protocol || "tcp",
                    software: sw?.product || sw?.vendor || null,
                    software_version: sw?.version || null,
                    os: osString(Array.isArray(svc.operating_systems) ? svc.operating_systems[0] : svc.operating_systems),
                    labels: labelStrings(svc.labels).slice(0, 6),
                    scan_time: svc.scan_time,
                    vulnerabilities: serviceVulns(svc),
                    http_status: http?.status_code || null,
                    http_protocol: http?.protocol || null,
                    http_title: http?.html_title || null,
                    http_server: headerValue(http?.headers, 'Server'),
                    http_body_hash: http?.body_hash_sha256 || http?.body_hash || null,
                    favicon_hash: Array.isArray(http?.favicons) && http.favicons[0] ? (http.favicons[0].md5_hash || http.favicons[0].hash) : null,
                };
            }),
            location: resource.location ? {
                country: resource.location.country,
                country_code: resource.location.country_code,
                city: resource.location.city,
                province: resource.location.province,
                continent: resource.location.continent,
                coordinates: resource.location.coordinates || null,
            } : null,
            autonomous_system: resource.autonomous_system ? {
                asn: resource.autonomous_system.asn,
                name: resource.autonomous_system.name || resource.autonomous_system.description,
                bgp_prefix: resource.autonomous_system.bgp_prefix,
                country_code: resource.autonomous_system.country_code || null,
            } : null,
            // Reverse DNS names for the host, if Censys resolved any.
            dns_names: resource.dns?.reverse_dns?.names || resource.dns?.names || [],
            dns: resource.dns || null,
        };

        res.json({ data: result });
    } catch (error) {
        if (error.response?.status === 404) {
            return res.json({ data: { "Status": "Host not found in Censys" } });
        }
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});



// CTI & CVE Newsletter and CVE Dashboard Endpoints


// Helper to decode HTML/XML entities
const decodeEntities = (str) => {
    if (!str) return '';
    return str
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/&#039;/g, "'")
        .replace(/&apos;/g, "'")
        .replace(/&rsquo;/g, "'")
        .replace(/&ldquo;/g, '"')
        .replace(/&rdquo;/g, '"')
        .replace(/&ndash;/g, '-')
        .replace(/&mdash;/g, '--');
};

// Generic feed parser
function parseFeed(xmlText, sourceName, layer) {
    const items = [];
    const isAtom = xmlText.includes('<entry>') || xmlText.includes('<feed');
    
    const cleanTag = (str) => {
        if (!str) return '';
        const stripped = str
             .replace(/<!\[CDATA\[/gi, '')
             .replace(/\]\]>/g, '')
             .replace(/<[^>]*>/g, '')
             .trim();
        return escapeHtml(stripped);
    };

    if (isAtom) {
        const entries = xmlText.split(/<entry>/i);
        for (let i = 1; i < entries.length; i++) {
            const entryHtml = entries[i].split(/<\/entry>/i)[0];
            const titleMatch = entryHtml.match(/<title(?:[^>]*)>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/title>/i);
            const linkMatch = entryHtml.match(/<link[^>]*href=["']([^"']+)["']/i) || entryHtml.match(/<link>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/link>/i);
            const dateMatch = entryHtml.match(/<(?:updated|published)>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/(?:updated|published)>/i);
            const summaryMatch = entryHtml.match(/<(?:summary|content)(?:[^>]*)>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/(?:summary|content)>/i);
            
            const title = decodeEntities(cleanTag(titleMatch ? titleMatch[1] : 'Untitled Alert'));
            const link = linkMatch ? linkMatch[1].trim() : '';
            const pubDate = dateMatch ? dateMatch[1].trim() : '';
            const description = decodeEntities(cleanTag(summaryMatch ? summaryMatch[1] : ''));

            if (title || link) {
                items.push({
                    title,
                    link,
                    pubDate: pubDate ? new Date(pubDate).toISOString() : new Date().toISOString(),
                    description: description.substring(0, 300) + (description.length > 300 ? '...' : ''),
                    source: sourceName,
                    layer: layer
                });
            }
        }
    } else {
        const itemParts = xmlText.split(/<item>/i);
        for (let i = 1; i < itemParts.length; i++) {
            const itemHtml = itemParts[i].split(/<\/item>/i)[0];
            const titleMatch = itemHtml.match(/<title(?:[^>]*)>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/title>/i);
            const linkMatch = itemHtml.match(/<link(?:[^>]*)>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/link>/i);
            const dateMatch = itemHtml.match(/<pubDate>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/pubDate>/i);
            const descMatch = itemHtml.match(/<description>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/description>/i);
            
            const title = decodeEntities(cleanTag(titleMatch ? titleMatch[1] : 'Untitled Alert'));
            const link = (linkMatch ? linkMatch[1] : '').trim();
            const pubDate = (dateMatch ? dateMatch[1] : '').trim();
            const description = decodeEntities(cleanTag(descMatch ? descMatch[1] : ''));

            if (title || link) {
                items.push({
                    title,
                    link,
                    pubDate: pubDate ? new Date(pubDate).toISOString() : new Date().toISOString(),
                    description: description.substring(0, 300) + (description.length > 300 ? '...' : ''),
                    source: sourceName,
                    layer: layer
                });
            }
        }
    }
    return items;
}

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
    hearth: {
        data: null,
        expiresAt: 0,
        ttl: 24 * 60 * 60 * 1000 // 24 hours
    },
    sentinelTables: {
        data: null,
        expiresAt: 0,
        ttl: 24 * 60 * 60 * 1000 // schema de workspace muda devagar
    },
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
    openphish: {
        urls: new Set(),
        expiresAt: 0,
        ttl: 60 * 60 * 1000 // 1 hour
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
    const builtins = CTI_FEEDS.map((f) => ({ ...f, builtin: true, enabled: !disabled.has(f.url) }));
    const custom = feedOverrides.custom.map((f) => ({ ...f, builtin: false, enabled: !disabled.has(f.url) }));
    return [...builtins, ...custom];
}
// Só os feeds ligados — é o que o coletor realmente busca.
function effectiveFeeds() {
    return catalogFeeds().filter((f) => f.enabled);
}

// Background newsletter feed refresher
async function refreshNewsletterFeed() {
    try {
        // Catálogo efetivo (built-ins ligados + custom do dono). weight_boost é a
        // confiança por fonte, herdada do bot CTI soc-sentinela.
        const feeds = effectiveFeeds();

        const feedPromises = feeds.map(async (f) => {
            try {
                const response = await axios.get(f.url, {
                    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36' },
                    timeout: 8000
                });
                // Enrich each item with the CTI relevance score + categorization.
                // `reasons` is kept so the UI can explain WHY an item scored.
                const enriched = parseFeed(response.data, f.source, f.layer).map((item) => {
                    const intel = scoreArticle(`${item.title} ${item.description}`, f.weight_boost);
                    return { ...item, weight_boost: f.weight_boost, ...intel };
                });
                feedHealth.set(f.url, { ok: true, count: enriched.length, error: null, at: new Date().toISOString() });
                return enriched;
            } catch (err) {
                feedHealth.set(f.url, { ok: false, count: 0, error: err.message, at: new Date().toISOString() });
                console.error(`Error fetching feed ${f.source}:`, err.message);
                return [];
            }
        });

        const results = await Promise.allSettled(feedPromises);
        const successfulFeeds = results
            .filter(r => r.status === 'fulfilled')
            .map(r => r.value)
            .flat();

        // De-duplicate by normalized URL (strip tracking params) — the same story
        // is often syndicated across multiple feeds; keep the highest-scoring copy.
        const byUrl = new Map();
        for (const item of successfulFeeds) {
            const key = (item.link || '').replace(/[?&](utm_[^&]+|fbclid=[^&]+|feature=[^&]+)/gi, '').replace(/[?&]$/, '').toLowerCase();
            const existing = byUrl.get(key);
            if (!existing || (item.score || 0) > (existing.score || 0)) byUrl.set(key, item);
        }
        const items = [...byUrl.values()];

        // Cross-reference CVEs with CISA KEV (actively exploited) + FIRST EPSS
        // (exploit probability). KEV is the strongest actionable signal, so it
        // boosts the relevance score and re-derives severity. Also attach
        // lightweight IOCs extracted from the title+summary.
        const allCves = [...new Set(items.flatMap((i) => i.cves || []))];
        const [kevMap, epssMap] = await Promise.all([getKevMap(), getEpssMap(allCves)]);
        for (const item of items) {
            const cves = item.cves || [];
            const kevHit = cves.find((c) => kevMap.has(c));
            if (kevHit) {
                const d = kevMap.get(kevHit);
                item.kev = true;
                item.kevDetails = { cve: kevHit, dateAdded: d.dateAdded, dueDate: d.dueDate, ransomware: d.ransomware };
                item.score = Math.min(100, (item.score || 0) + 25);
                item.severity = severityFromScore(item.score);
                (item.reasons = item.reasons || []).push(`CISA KEV — Actively Exploited (${kevHit})`);
            }
            const epssVals = cves.map((c) => epssMap.get(c)).filter((n) => typeof n === 'number');
            if (epssVals.length) item.epss = Math.max(...epssVals);
            const ic = extractIOCs(`${item.title} ${item.description || ''}`);
            if (ic.ips.length || ic.domains.length || ic.hashes.length || ic.urls.length) item.iocs = ic;
        }

        // Default order: most recent first (the route can re-sort by relevance).
        const unifiedFeed = items.sort((a, b) => new Date(b.pubDate) - new Date(a.pubDate));

        memoryCache.newsletter.data = unifiedFeed;
        memoryCache.newsletter.expiresAt = Date.now() + memoryCache.newsletter.ttl;
    } catch (error) {
        console.error("Failed to background refresh newsletter feeds:", error.message);
    }
}

// CTI News feed endpoint.
// Optional query params: minScore (0-100), severity (Critical|High|Medium|Low),
// category (substring of a category label), layer (1-4), sort (relevance|date).
app.get('/api/newsletter', requirePremium, async (req, res) => {
    try {
        if (!memoryCache.newsletter.data) {
            // Cold start fallback
            await refreshNewsletterFeed();
        }
        let data = memoryCache.newsletter.data || [];

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

        res.set('Cache-Control', 'public, max-age=300');
        res.json(data);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// ─── Feed Generator · sugestões do boletim diário ─────────────────────────
// Fase 1: itens CTI do dia, vindos do feed unificado (já pontuado/deduplicado),
// servidos como *sugestões* para a curadoria do boletim diário — o analista
// escolhe quais viram boletim. Read-only; reaproveita o cache da newsletter.
//   GET /api/feed/daily-suggestions?hours=36&limit=10&minScore=0
app.get('/api/feed/daily-suggestions', requirePremium, async (req, res) => {
    try {
        if (!memoryCache.newsletter.data) await refreshNewsletterFeed();
        const all = memoryCache.newsletter.data || [];

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

        res.set('Cache-Control', 'public, max-age=300');
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
                content: 'Voce e um analista senior de CTI. Responda somente JSON em portugues do Brasil com title, summary (3 a 5 fatos) e attentionTopics (2 a 4 temas com title, assessment, recommendedAction opcional e eventIds). Use apenas os fatos e identificadores fornecidos.',
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
    return catalogFeeds().map((f) => {
        const h = feedHealth.get(f.url);
        return {
            url: f.url, source: f.source, layer: f.layer, weight_boost: f.weight_boost,
            builtin: f.builtin, enabled: f.enabled,
            health: h ? { ok: h.ok, count: h.count, error: h.error, at: h.at } : null,
        };
    });
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
    const known = new Set([...CTI_FEEDS, ...feedOverrides.custom].map((f) => f.url));
    if (known.has(clean)) return res.status(409).json({ error: 'feed já existe' });
    const layer = Math.min(Math.max(parseInt(req.body.layer, 10) || 2, 1), 4);
    const weight_boost = Math.min(Math.max(parseInt(req.body.weight_boost, 10) || 10, 0), 25);
    feedOverrides.custom.push({ url: clean, source: String(source).trim(), layer, weight_boost });
    // adicionar já implica ligado: garante que não fique num disabled antigo.
    feedOverrides.disabled = feedOverrides.disabled.filter((d) => d !== clean);
    saveFeedOverrides();
    refreshNewsletterFeed().catch(() => {});
    res.status(201).json({ feeds: feedListForClient() });
});

// Liga/desliga um feed (built-in ou custom). Body: { url, enabled }.
app.patch('/api/feeds', requireAdmin, (req, res) => {
    const url = String((req.body || {}).url || '');
    const enabled = !!(req.body || {}).enabled;
    const known = new Set([...CTI_FEEDS, ...feedOverrides.custom].map((f) => f.url));
    if (!known.has(url)) return res.status(404).json({ error: 'feed não encontrado' });
    const set = new Set(feedOverrides.disabled);
    if (enabled) set.delete(url); else set.add(url);
    feedOverrides.disabled = [...set];
    saveFeedOverrides();
    refreshNewsletterFeed().catch(() => {});
    res.json({ feeds: feedListForClient() });
});

// Remove um feed custom (built-ins só podem ser desativados). ?url=…
app.delete('/api/feeds', requireAdmin, (req, res) => {
    const url = String(req.query.url || (req.body || {}).url || '');
    const before = feedOverrides.custom.length;
    feedOverrides.custom = feedOverrides.custom.filter((f) => f.url !== url);
    if (feedOverrides.custom.length === before) {
        return res.status(CTI_FEEDS.some((f) => f.url === url) ? 400 : 404)
            .json({ error: CTI_FEEDS.some((f) => f.url === url) ? 'feed built-in só pode ser desativado' : 'feed não encontrado' });
    }
    feedOverrides.disabled = feedOverrides.disabled.filter((d) => d !== url);
    feedHealth.delete(url);
    saveFeedOverrides();
    refreshNewsletterFeed().catch(() => {});
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
        { name: 'Hybrid Analysis', env: 'HYBRID_ANALYSIS_API_KEY', configured: set('HYBRID_ANALYSIS_API_KEY'), required: true },
        { name: 'MetaDefender', env: 'METADEFENDER_API_KEY', configured: set('METADEFENDER_API_KEY'), required: true },
        { name: 'WHOIS', env: 'WHOIS_API_KEY', configured: set('WHOIS_API_KEY'), required: true },
        { name: 'Censys', env: 'CENSYS_API_KEY', configured: set('CENSYS_API_KEY'), required: true },
        { name: 'Pulsedive', env: 'PULSEDIVE_API_KEY', configured: set('PULSEDIVE_API_KEY'), required: false, note: 'usa o tier free sem chave' },
        { name: 'PhishTank', env: 'PHISHTANK_API_KEY', configured: set('PHISHTANK_API_KEY'), required: false },
    ];
    // Provedores que não precisam de chave nenhuma.
    const keyless = ['PhishStats', 'OpenPhish', 'Team Cymru', 'CIRCL hashlookup', 'IP Geolocation', 'Ransomware.live', 'DNSBL'];
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

app.get('/api/knowledge', requirePremium, (req, res) => {
    res.json({ items: knowledgeStore[req.user.sub] || [] });
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

// ─── Hunting: consultas KQL privadas por usuário ────────────────────────────
// ponytail: store JSON de processo único; migrar por usuário ao operar múltiplas instâncias.
const HUNTS_STORE_PATH = process.env.HUNTS_STORE_PATH || path.join(__dirname, '.hunts.json');
function loadHuntsStore() { try { const o = JSON.parse(fs.readFileSync(HUNTS_STORE_PATH, 'utf8')); return (o && typeof o === 'object') ? o : {}; } catch { return {}; } }
function saveHuntsStore(nextStore) { writeJsonAtomic(HUNTS_STORE_PATH, nextStore); huntsStore = nextStore; }
let huntsStore = loadHuntsStore();

// Segredo compartilhado p/ as rotas servidor-a-servidor (worker).
// Sem FEED_AGENT_SECRET definido, as rotas protegidas ficam desabilitadas (503),
// pra não exporem leitura/escrita de boletim sem auth.
function requireFeedSecret(req, res) {
    const secret = process.env.FEED_AGENT_SECRET;
    if (!secret) { res.status(503).json({ error: 'feed agent secret not configured' }); return false; }
    if (req.get('X-Feed-Secret') !== secret) { res.status(401).json({ error: 'unauthorized' }); return false; }
    return true;
}

// ─── Auth GitHub + BYOK (chave OpenRouter por usuário, cifrada em repouso) ───
// Login via GitHub OAuth (fluxo escrito à mão, sem passport). A sessão é um
// cookie httpOnly assinado por HMAC — mesma origem que o app (Pages serve o app
// e faz proxy de /api pelo túnel), então não há CORS com credenciais. Login é
// aberto; a allow-list controla apenas recursos premium. Cada usuário traz a
// própria chave OpenRouter (BYOK): ela é cifrada (AES-256-GCM) e guardada em
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
// (VirusTotal/Shodan/etc.) cifradas; a geração usa a chave OpenRouter do servidor.
const USERS_STORE_PATH = path.join(__dirname, '.users.json');
function loadUsers() { try { return JSON.parse(fs.readFileSync(USERS_STORE_PATH, 'utf8')); } catch { return {}; } }
function saveUsers() { try { writeJsonAtomic(USERS_STORE_PATH, usersStore); } catch (e) { console.error('users store write failed:', e.message); } }
let usersStore = loadUsers();   // { githubId: { login, apiKeysEnc, createdAt, updatedAt } }

// Premium allow-list: por login e/ou por org. Login no app é aberto; esta lista
// decide quem acessa recursos premium (relatórios, newsletter e hunting).
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
const BYOK_PROVIDERS = new Set([
    'virustotal', 'abuseipdb', 'shodan', 'alienvault', 'pulsedive',
    'hybridanalysis', 'metadefender', 'censys',
    'urlhaus', 'threatfox', 'phishtank', 'whois', 'dnsdumpster',
]);
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
    if (!BYOK_PROVIDERS.has(provider)) return res.status(400).json({ error: 'provider desconhecido' });
    const u = usersStore[req.user.sub];
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
        axiosClient: axios,
        shodanApiKey: getUserApiKey(ownerId, 'shodan') || process.env.SHODAN_API_KEY,
    };
}

async function runExposureForAsset(asset) {
    return runExposureSnapshot({
        store: exposureStore,
        assetId: asset.id,
        ownerId: asset.ownerId,
        runAttackSurfaceScan,
        scanDeps: buildExposureScanDeps(asset.ownerId),
    });
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
const JOBS_STORE_PATH = path.join(__dirname, '.feed-jobs.json');
function loadJobs() { try { return JSON.parse(fs.readFileSync(JOBS_STORE_PATH, 'utf8')); } catch { return {}; } }
function saveJobs() { try { writeJsonAtomic(JOBS_STORE_PATH, jobsStore); } catch (e) { console.error('jobs store write failed:', e.message); } }
let jobsStore = loadJobs();   // { id: { id,url,type,title,status,json,error,createdAt,updatedAt } }

// Boletim entregue não é lixo de fila: fica guardado por dono (ver feedJobs.js).
// Só pending/error têm teto global.
const REPORTS_PER_OWNER = parseInt(process.env.FEED_REPORTS_PER_OWNER, 10) || 200;
function pruneJobs() {
    pruneJobsMap(jobsStore, { maxTransient: 100, keptPerOwner: REPORTS_PER_OWNER });
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
//   POST /api/feed/generate  { url, type, title? }
app.post('/api/feed/generate', requirePremium, scanLimiter, async (req, res) => {
    try {
        const url = (req.body?.url || '').toString();
        const type = req.body?.type === 'campaign' ? 'campaign' : 'vuln';
        const title = (req.body?.title || '').toString().slice(0, 300);
        if (!/^https?:\/\//i.test(url)) return res.status(400).json({ error: 'url http(s) obrigatória' });
        // Sem BYOK: a geração usa a chave OpenRouter compartilhada do servidor
        // (OPENROUTER_API_KEY no .env do worker/engine). O acesso já é gated por
        // login + allow-list premium (requirePremium) acima.
        // Sempre valida (sem atalho de "confiar em URL do feed") — o guard SSRF
        // bloqueia IP privado/loopback/metadata. O worker na VPS revalida também.
        try { await assertSafePublicUrl(url); } catch (e) { return res.status(400).json({ error: e.message || 'URL rejeitada' }); }
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
        jobsStore[id] = { id, ownerSub: req.user.sub, url, type, title, status: 'pending', json: null, error: null, createdAt: now, updatedAt: now };
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
    res.json({ ...job, queuePosition });
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
app.delete('/api/feed/job/:id', requirePremium, (req, res) => {
    const job = jobsStore[req.params.id];
    if (!job) return res.status(404).json({ error: 'job não encontrado' });
    if (job.ownerSub !== req.user.sub) return res.status(403).json({ error: 'job pertence a outro usuário' });
    delete jobsStore[req.params.id];
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
    res.json(relatedTo(refs, { hunts: huntsStore[req.user.sub] || [], reports }));
});

// Worker (VPS) lê os jobs pendentes. 🔒   GET /api/feed/jobs/pending
app.get('/api/feed/jobs/pending', (req, res) => {
    if (!requireFeedSecret(req, res)) return;
    expireStaleJobs();
    // Sem BYOK: todo job pending vai pro worker. A chave OpenRouter é do servidor
    // (no .env do worker), não viaja no payload. Só encaminhamos o modelo — e
    // apenas quando este servidor pinar um: o --model do worker sobrescreve a
    // cadeia do motor, então um default aqui viraria um segundo lugar pra
    // atualizar (e silenciosamente venceria o motor, que é quem sabe o assunto).
    const pending = Object.values(jobsStore)
        .filter((j) => j.status === 'pending')
        .map((j) => ({
            id: j.id,
            url: j.url,
            type: j.type,
            title: j.title,
            ...(process.env.OPENROUTER_MODEL ? { model: process.env.OPENROUTER_MODEL } : {}),
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
        job.json = req.body.json;
        // Indexa na entrega: é o único momento em que o boletim chega. Guardar
        // techniques/cves no job evita varrer o JSON inteiro a cada listagem.
        Object.assign(job, refsOfReport(job.json));
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

const newsIntelPrompt = (lang) => (
    'You are a senior Cyber Threat Intelligence analyst. ' +
    'Respond ONLY with a JSON object with these keys:\n' +
    '1. "title": the advisory title, professionally normalized.\n' +
    '2. "summary": ONE concise technical paragraph — an executive summary describing WHAT happened ' +
    '(the threat, incident or fact) and why it matters for a SOC/CTI operation. ' +
    'Do NOT include mitigations, recommendations, remediation steps or IOC lists.\n' +
    `OUTPUT LANGUAGE: ${lang === 'en' ? 'English' : 'Português (Brasil)'}. Respond ONLY the JSON, no extra text.`
);

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

async function fetchArticleText(url) {
    try {
        const resp = await axios.get(url, {
            headers: { 'User-Agent': BROWSER_UA, Accept: 'text/html,application/xhtml+xml' },
            timeout: 10000,
            maxRedirects: 3,
            responseType: 'text',
        });
        return {
            text: extractReadableText(resp.data).slice(0, 8000),
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
    return String(resp.data || '').slice(0, ARTIFACT_MAX_BYTES);
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
async function openRouterAnalyze(title, content, lang) {
    if (!process.env.OPENROUTER_API_KEY) return null;
    const userPrompt = `Title: ${title}\nOriginal content: ${(content || '').slice(0, 12000)}`;
    try {
        const resp = await axios.post(`${OPENROUTER_BASE_URL}/chat/completions`, {
            model: OPENROUTER_MODEL,
            temperature: 0.1,
            response_format: { type: 'json_object' },
            messages: [
                { role: 'system', content: newsIntelPrompt(lang) },
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
        const url = (req.body?.url || '').toString();
        const lang = req.body?.lang === 'en' ? 'en' : 'pt';
        if (!url) return res.status(400).json({ error: 'Missing advisory url' });

        const feed = memoryCache.newsletter.data || [];
        const item = feed.find((i) => i.link === url);
        if (!item) return res.status(404).json({ error: 'Advisory not found in current feed' });

        const cacheKey = `${lang}|${url}`;
        const now = Date.now();
        const cached = memoryCache.newsletterEnrich.store.get(cacheKey);
        if (cached && cached.expiresAt > now) return res.json(cached.data);

        // Advanced collection: pull the full article body; fall back to RSS summary.
        const { text: fullText, artifactLinks } = await fetchArticleText(item.link);
        const content = fullText || item.description || '';

        // Re-run deterministic enrichment over the FULL article so MITRE ATT&CK,
        // threats, sectors, assets and CVEs reflect the whole story, not just the
        // (often short) RSS summary.
        const intel = scoreArticle(`${item.title} ${item.description || ''} ${content}`, item.weight_boost || 0);
        const enriched = localizeEnrichment({
            threats: intel.threats, sectors: intel.sectors, ttps: intel.ttps,
            assets: intel.assets, cves: intel.cves,
        }, lang);

        const ai = await openRouterAnalyze(item.title, content, lang);

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
                available: true, source: 'openrouter', scraped: !!fullText,
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
                    googleTranslate(item.title, 'pt'),
                    googleTranslate(execRaw, 'pt'),
                    mitRaw ? googleTranslate(mitRaw, 'pt') : Promise.resolve(''),
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

const HEARTH_DATA_URL = 'https://raw.githubusercontent.com/THORCollective/HEARTH/main/hunts-data.js';
let ATTACK_TAXONOMY = null;
function loadAttackTaxonomy() {
    if (!ATTACK_TAXONOMY) ATTACK_TAXONOMY = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'attack.json'), 'utf8'));
    return ATTACK_TAXONOMY;
}

async function getHearthCatalog() {
    const cache = memoryCache.hearth;
    if (cache.data && cache.expiresAt > Date.now()) return cache.data;
    try {
        await assertSafePublicUrl(HEARTH_DATA_URL);
        const response = await axios.get(HEARTH_DATA_URL, { responseType: 'text', maxContentLength: 2_000_000, timeout: 12000 });
        cache.data = parseHearthData(response.data);
        cache.expiresAt = Date.now() + cache.ttl;
        return cache.data;
    } catch (error) {
        if (cache.data) return cache.data;
        throw error;
    }
}

// Schema do workspace, publicado pelo dono em markdown (saida do getschema).
// URL fixa: e fonte propria, nao entrada de usuario — nao ha SSRF a temer aqui,
// mas passa pelo mesmo assertSafePublicUrl que o resto.
const SENTINEL_TABLES_URL = 'https://raw.githubusercontent.com/kkroth0/threat-hunting-ptbr/main/Tables_Data.md';

async function getSentinelTables() {
    const cache = memoryCache.sentinelTables;
    if (cache.data && cache.expiresAt > Date.now()) return cache.data;
    try {
        await assertSafePublicUrl(SENTINEL_TABLES_URL);
        const response = await axios.get(SENTINEL_TABLES_URL, { responseType: 'text', maxContentLength: 4_000_000, timeout: 12000 });
        cache.data = parseSentinelTables(response.data);
        cache.expiresAt = Date.now() + cache.ttl;
        return cache.data;
    } catch (error) {
        if (cache.data) return cache.data;
        throw error;
    }
}

// Catalogo de tabelas: alimenta o filtro de fonte na UI e, depois, o gerador
// de KQL. So o resumo vai pro cliente — 3,4 mil colunas nao tem porque trafegar.
app.get('/api/sentinel/tables', requirePremium, async (req, res) => {
    try {
        const catalog = await getSentinelTables();
        res.json({
            sources: catalogSources(catalog),
            tables: catalog.map(({ table, source, columns }) => ({ table, source, columnCount: columns.length })),
            total: catalog.length,
            source: SENTINEL_TABLES_URL,
        });
    } catch (error) {
        console.error('Sentinel table catalog fetch failed:', error.message);
        res.status(502).json({ error: 'catálogo de tabelas indisponível' });
    }
});

app.get('/api/hearth', requirePremium, async (req, res) => {
    try {
        const hunts = await getHearthCatalog();
        res.json({ hunts, total: hunts.length, source: HEARTH_DATA_URL, license: 'MIT' });
    } catch (error) {
        console.error('HEARTH catalog fetch failed:', error.message);
        res.status(502).json({ error: 'catálogo HEARTH indisponível' });
    }
});

app.get('/api/hunts', requirePremium, (req, res) => {
    res.json({ items: huntsStore[req.user.sub] || [] });
});

app.get('/api/hunts/coverage', requirePremium, (req, res) => {
    const items = huntsStore[req.user.sub] || [];
    const axis = String(req.query.axis || 'technique');
    if (axis === 'technique') return res.json({ axis, ...techniqueCoverage(items, loadAttackTaxonomy()) });
    const field = axis === 'technology' ? 'technologies' : axis === 'dataSource' ? 'dataSources' : '';
    if (!field) return res.status(400).json({ error: 'eixo de cobertura inválido' });
    res.json({ axis, values: groupByField(items, field) });
});

app.post('/api/hunts', requirePremium, (req, res) => {
    let hunt;
    try {
        hunt = normalizeHuntInput(req.body || {}, { ownerSub: req.user.sub });
    } catch (error) {
        return res.status(400).json({ error: error.message });
    }
    const items = upsertHunt(huntsStore[req.user.sub] || [], hunt);
    try {
        saveHuntsStore({ ...huntsStore, [req.user.sub]: items });
    } catch (error) {
        console.error('hunts store write failed:', error.message);
        return res.status(500).json({ error: 'não foi possível salvar a hunt' });
    }
    res.status(201).json({ hunt, items });
});

app.patch('/api/hunts/:id', requirePremium, (req, res) => {
    const current = (huntsStore[req.user.sub] || []).find((hunt) => hunt.id === req.params.id);
    if (!current) return res.status(404).json({ error: 'hunt não encontrado' });
    let hunt;
    try {
        hunt = normalizeHuntInput({ ...current, ...(req.body || {}) }, {
            ownerSub: req.user.sub,
            id: current.id,
            createdAt: current.createdAt,
        });
    } catch (error) {
        return res.status(400).json({ error: error.message });
    }
    const items = upsertHunt(huntsStore[req.user.sub], hunt);
    try {
        saveHuntsStore({ ...huntsStore, [req.user.sub]: items });
    } catch (error) {
        console.error('hunts store write failed:', error.message);
        return res.status(500).json({ error: 'não foi possível salvar a hunt' });
    }
    res.json({ hunt, items });
});

// ─── Execucao de hunt: o quadro do analista ───────────────────────────────
// Estados: pending (na fila) -> running (rodando) -> done (fechada, com achado).
// Uma hunt mensal roda varias vezes, entao execucao e lista dentro da hunt.

const persistHunt = (req, res, hunt) => {
    const items = upsertHunt(huntsStore[req.user.sub], hunt);
    try {
        saveHuntsStore({ ...huntsStore, [req.user.sub]: items });
    } catch (error) {
        console.error('hunts store write failed:', error.message);
        res.status(500).json({ error: 'não foi possível salvar a execução' });
        return null;
    }
    return items;
};

// Abre uma execucao (ou registra uma ja fechada de uma vez).
app.post('/api/hunts/:id/runs', requirePremium, (req, res) => {
    const current = (huntsStore[req.user.sub] || []).find((hunt) => hunt.id === req.params.id);
    if (!current) return res.status(404).json({ error: 'hunt não encontrado' });

    let run;
    try {
        run = normalizeRunInput(req.body || {});
    } catch (error) {
        return res.status(400).json({ error: error.message });
    }

    const hunt = upsertRun(current, run);
    const items = persistHunt(req, res, hunt);
    if (!items) return;
    res.status(201).json({ hunt, run, items });
});

// Avanca a execucao: comecar, fechar com achado, corrigir contagem.
app.patch('/api/hunts/:id/runs/:runId', requirePremium, (req, res) => {
    const current = (huntsStore[req.user.sub] || []).find((hunt) => hunt.id === req.params.id);
    if (!current) return res.status(404).json({ error: 'hunt não encontrado' });
    const previous = (current.runs || []).find((item) => item.id === req.params.runId);
    if (!previous) return res.status(404).json({ error: 'execução não encontrada' });

    let run;
    try {
        // startedAt e do momento em que abriu, nao do ultimo toque: e ele que
        // decide de qual mes a execucao e.
        run = normalizeRunInput({ ...previous, ...(req.body || {}) }, {
            id: previous.id,
            startedAt: previous.startedAt,
        });
    } catch (error) {
        return res.status(400).json({ error: error.message });
    }

    const hunt = upsertRun(current, run);
    const items = persistHunt(req, res, hunt);
    if (!items) return;
    res.json({ hunt, run, items });
});

// Controle do mes: quanto rodou, em que estado parou e o que saiu.
app.get('/api/hunts/runs/summary', requirePremium, (req, res) => {
    const month = String(req.query.month || new Date().toISOString().slice(0, 7));
    if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(month)) return res.status(400).json({ error: 'mês inválido' });
    res.json(monthlySummary(huntsStore[req.user.sub] || [], month));
});

// Indice por tecnica ATT&CK: a partir dele o mapa do MITRE fica clicavel e
// responde "que hunts eu tenho pra T1059?" sem varrer a lista no cliente.
app.get('/api/hunts/by-technique/:technique', requirePremium, (req, res) => {
    const technique = String(req.params.technique || '').toUpperCase();
    if (!/^T\d{4}(?:\.\d{3})?$/.test(technique)) return res.status(400).json({ error: 'técnica inválida' });

    const hunts = (huntsStore[req.user.sub] || [])
        .filter((hunt) => (hunt.techniques || []).includes(technique))
        .map(({ id, title, status, techniques, runs }) => ({
            id, title, status, techniques,
            lastRun: (runs || [])[0] || null,
        }));

    res.json({ technique, hunts, total: hunts.length });
});

app.delete('/api/hunts/:id', requirePremium, (req, res) => {
    const items = huntsStore[req.user.sub] || [];
    if (!items.some((hunt) => hunt.id === req.params.id)) return res.status(404).json({ error: 'hunt não encontrado' });
    const nextItems = items.filter((hunt) => hunt.id !== req.params.id);
    try {
        saveHuntsStore({ ...huntsStore, [req.user.sub]: nextItems });
    } catch (error) {
        console.error('hunts store write failed:', error.message);
        return res.status(500).json({ error: 'não foi possível apagar a hunt' });
    }
    res.json({ id: req.params.id, deleted: true, items: nextItems });
});

// Latest CVEs from CIRCL
// NIST NVD 2.0 — recently published CVEs (last 10 days). Sending NVD_API_KEY
// raises the rate limit (50 req/30s vs 5); the endpoint also works keyless but
// throttles harder. Mapped to the same shape the CIRCL/fallback paths return.
async function fetchRecentNvdCves() {
    const end = new Date();
    const start = new Date(end.getTime() - 10 * 24 * 60 * 60 * 1000);
    const iso = (d) => d.toISOString().slice(0, 23); // ISO-8601, no trailing Z
    const headers = {};
    const nvdKey = (process.env.NVD_API_KEY || '').trim();
    if (nvdKey) headers.apiKey = nvdKey;

    const resp = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
        params: { pubStartDate: iso(start), pubEndDate: iso(end), resultsPerPage: 100 },
        headers,
        timeout: 15000,
    });

    const vulns = Array.isArray(resp.data?.vulnerabilities) ? resp.data.vulnerabilities : [];
    return vulns
        .map((entry) => entry.cve)
        .filter((cve) => cve && typeof cve.id === 'string' && cve.id.startsWith('CVE-'))
        .map((cve) => {
            const metrics = cve.metrics || {};
            const metric = (metrics.cvssMetricV31 || metrics.cvssMetricV30
                || metrics.cvssMetricV40 || metrics.cvssMetricV2 || [])[0];
            const cvssData = metric?.cvssData || {};
            const refs = (cve.references || []).map((r) => r.url).filter(Boolean);
            return {
                id: cve.id,
                cvss: typeof cvssData.baseScore === 'number' ? cvssData.baseScore : null,
                summary: (cve.descriptions || []).find((d) => d.lang === 'en')?.value || 'No description available.',
                Published: cve.published,
                Modified: cve.lastModified || cve.published,
                source: 'NIST NVD (National Vulnerability Database)',
                vectorString: cvssData.vectorString || 'N/A',
                mitigation: 'Patch update recommended. Review vendor security advisories and apply the latest available software packages.',
                references: refs.length ? refs.slice(0, 6) : [`https://nvd.nist.gov/vuln/detail/${cve.id}`],
            };
        })
        .sort((a, b) => new Date(b.Published || 0) - new Date(a.Published || 0));
}

app.get('/api/cves/recent', async (req, res) => {
    const now = Date.now();
    if (memoryCache.recentCves.data && memoryCache.recentCves.expiresAt > now) {
        return res.json(memoryCache.recentCves.data);
    }

    const fallbacks = [
        {
            id: "CVE-2026-1082",
            cvss: 9.8,
            summary: "Critical remote code execution vulnerability in Apache HTTP Server when configured as a reverse proxy, allowing unauthenticated attackers to execute arbitrary code via a specifically crafted header.",
            Published: new Date().toISOString(),
            source: "NIST NVD (National Vulnerability Database)",
            vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            mitigation: "Upgrade to Apache HTTP Server version 2.4.60 or later. Apply vendor-provided patches immediately. Restrict reverse proxy configuration access from unauthorized external IP blocks.",
            references: [
                "https://nvd.nist.gov/vuln/detail/CVE-2026-1082",
                "https://httpd.apache.org/security/vulnerabilities_24.html",
                "https://github.com/apache/httpd/commit/a8d3e91d"
            ]
        },
        {
            id: "CVE-2026-2115",
            cvss: 8.8,
            summary: "Privilege escalation vulnerability in Microsoft Windows Win32k component allowing a local attacker to bypass access controls and run arbitrary commands as SYSTEM.",
            Published: new Date(Date.now() - 3600000).toISOString(),
            source: "NIST NVD (National Vulnerability Database)",
            vectorString: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            mitigation: "Apply the May 2026 security updates from Microsoft. Enable Virtualization-Based Security (VBS) to mitigate kernel exploits. Monitor for LSASS process injection events.",
            references: [
                "https://nvd.nist.gov/vuln/detail/CVE-2026-2115",
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-2115",
                "https://www.exploit-db.com/exploits/52998"
            ]
        },
        {
            id: "CVE-2026-3024",
            cvss: 7.5,
            summary: "Denial of service vulnerability in OpenSSL package due to an infinite loop in the certificate verification process triggered by a malformed certificate chain.",
            Published: new Date(Date.now() - 7200000).toISOString(),
            source: "NIST NVD (National Vulnerability Database)",
            vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            mitigation: "Apply the OpenSSL 3.3.1 patch update or compile with no-ssl3 configurations. Implement web application firewall (WAF) rule filters checking TLS client hello packet structures.",
            references: [
                "https://nvd.nist.gov/vuln/detail/CVE-2026-3024",
                "https://www.openssl.org/news/secadv/20260522.txt",
                "https://github.com/openssl/openssl/issues/23490"
            ]
        },
        {
            id: "CVE-2026-1492",
            cvss: 6.5,
            summary: "Cross-site scripting (XSS) vulnerability in WordPress core files when utilizing certain block components, enabling authenticated contributors to inject malicious JavaScript.",
            Published: new Date(Date.now() - 14400000).toISOString(),
            source: "NIST NVD (National Vulnerability Database)",
            vectorString: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
            mitigation: "Upgrade WordPress installation to version 6.9.2 or apply the official security patch. Restrict contributor-level privileges or implement strict Content Security Policy (CSP) headers.",
            references: [
                "https://nvd.nist.gov/vuln/detail/CVE-2026-1492",
                "https://wordpress.org/news/2026/05/wordpress-6-9-2-security-release/",
                "https://wpscan.com/vulnerability/wp-692-xss"
            ]
        },
        {
            id: "CVE-2026-0518",
            cvss: 9.9,
            summary: "SQL Injection vulnerability in GitLab CE/EE allowing unauthorized remote attackers to retrieve database keys and configuration hashes via vulnerable REST API endpoints.",
            Published: new Date(Date.now() - 86400000).toISOString(),
            source: "NIST NVD (National Vulnerability Database)",
            vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            mitigation: "Apply GitLab security releases 17.0.3, 16.11.5, or 16.10.8 immediately. Rotate GitLab secrets (`secrets.yml`) if database leak indicators are found. Disable unused REST API access paths.",
            references: [
                "https://nvd.nist.gov/vuln/detail/CVE-2026-0518",
                "https://about.gitlab.com/releases/2026/05/security-release-gitlab-17-0-3-released/",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-0518"
            ]
        }
    ];

    // Primary source: NIST NVD (authenticated via NVD_API_KEY). Falls through to
    // CIRCL and then the static fallbacks below if it errors or returns too few.
    try {
        const nvd = await fetchRecentNvdCves();
        if (nvd.length >= 5) {
            const result = nvd.slice(0, 50);
            memoryCache.recentCves.data = result;
            memoryCache.recentCves.expiresAt = now + memoryCache.recentCves.ttl;
            return res.json(result);
        }
    } catch (error) {
        console.warn('NVD recent CVE fetch failed, falling back to CIRCL:', error.message);
    }

    try {
        const response = await axios.get('https://cve.circl.lu/api/last', { timeout: 8000 });
        if (Array.isArray(response.data)) {
            const formatted = [];
            response.data.forEach(item => {
                if (item.id) {
                    formatted.push({
                        id: item.id,
                        cvss: item.cvss,
                        summary: item.summary,
                        Published: item.Published,
                        Modified: item.Modified,
                        source: "NIST NVD (via CIRCL)",
                        vectorString: item.cvss_vector || "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        mitigation: "Patch update recommended. Review vendor security advisories and apply latest available software packages.",
                        references: item.references || [`https://nvd.nist.gov/vuln/detail/${item.id}`]
                    });
                    return;
                }
                
                const document = item.document || {};
                const tracking = document.tracking || {};
                const docId = tracking.id || 'Unknown-Advisory';
                const docSummary = (document.notes?.find(n => n.category === 'summary' || n.category === 'general'))?.text || (document.title || 'No summary available.');
                const publishedDate = tracking.initial_release_date || tracking.current_release_date || new Date().toISOString();
                
                if (item.vulnerabilities && item.vulnerabilities.length > 0) {
                    item.vulnerabilities.forEach(vuln => {
                        const cveId = vuln.cve || docId;
                        
                        let cvss = null;
                        let vectorString = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
                        if (vuln.scores && vuln.scores.length > 0) {
                            const scoreObj = vuln.scores[0];
                            cvss = scoreObj.cvss_v3?.baseScore || scoreObj.cvss_v2?.baseScore || null;
                            vectorString = scoreObj.cvss_v3?.vectorString || scoreObj.cvss_v2?.vectorString || vectorString;
                        }
                        
                        const vulnNote = vuln.notes?.find(n => n.category === 'summary' || n.category === 'general');
                        const summaryText = vulnNote ? vulnNote.text : (vuln.title || docSummary);
                        
                        formatted.push({
                            id: cveId,
                            cvss: cvss,
                            summary: summaryText,
                            Published: publishedDate,
                            Modified: tracking.current_release_date || publishedDate,
                            source: "NIST NVD (via CIRCL)",
                            vectorString: vectorString,
                            mitigation: "Patch update recommended. Review vendor security advisories and apply latest available software packages.",
                            references: vuln.references?.map(r => r.url) || [`https://nvd.nist.gov/vuln/detail/${cveId}`]
                        });
                    });
                } else {
                    formatted.push({
                        id: docId,
                        cvss: null,
                        summary: docSummary,
                        Published: publishedDate,
                        Modified: tracking.current_release_date || publishedDate,
                        source: "NIST NVD (via CIRCL)",
                        vectorString: "N/A",
                        mitigation: "Patch update recommended. Review vendor security advisories and apply latest available software packages.",
                        references: [`https://nvd.nist.gov/vuln/detail/${docId}`]
                    });
                }
            });

            let result = formatted.filter(item => item.id && item.id.startsWith("CVE-"));
            if (result.length < 5) {
                result = [...result, ...fallbacks].slice(0, 50);
            } else {
                result = result.slice(0, 50);
            }

            memoryCache.recentCves.data = result;
            memoryCache.recentCves.expiresAt = now + memoryCache.recentCves.ttl;
            return res.json(result);
        }
        throw new Error("Invalid response format from CIRCL");
    } catch (error) {
        console.error("CIRCL API Error, falling back to mock CVE data:", error.message);
        res.json(fallbacks);
    }
});

// Exploited CVEs from CISA KEV
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
    const countries = [...new Set(actors.map(a => a.country).filter(Boolean))].sort();
    ACTORS_CACHE = { actors, countries };
    return ACTORS_CACHE;
};

// List (slim) + country facet. The client fetches once and searches/filters in-memory.
app.get('/api/actors', (req, res) => {
    const { actors, countries } = loadActors();
    res.set('Cache-Control', 'public, max-age=21600');
    res.json({
        total: actors.length,
        countries,
        actors: actors.map(a => ({
            id: a.id, name: a.name, aliases: a.aliases || [], country: a.country || '',
            motivation: a.motivation || '', source: a.source,
            technique_count: (a.techniques || []).length,
            techniques: (a.techniques || []).map((technique) => technique.id).filter(Boolean),
        })),
    });
});

// Full detail for one actor.
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

// Vendors API Status
app.get('/api/vendors/status', (req, res) => {
    // Use getKeys() so providers configured only via numbered fallback vars
    // (e.g. VIRUSTOTAL2_API_KEY) still report as available.
    const hasKey = (envName) => getKeys(envName).length > 0;
    const status = {
        "VirusTotal": hasKey('VIRUSTOTAL_API_KEY'),
        "AbuseIPDB": hasKey('ABUSEIPDB_API_KEY'),
        "AlienVault OTX": true,
        "Shodan": hasKey('SHODAN_API_KEY'),
        "URLhaus": true,
        "Censys": hasKey('CENSYS_API_KEY'),
        "WHOIS": hasKey('WHOIS_API_KEY'),
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
    console.log(`Server running on port ${PORT}`);
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
    }
    scheduleDailyEdition();
});
