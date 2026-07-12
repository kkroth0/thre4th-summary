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
import { scoreArticle, localizeEnrichment, severityFromScore, extractIOCs, CTI_FEEDS } from './ctiIntel.js';

dotenv.config({ path: '../.env' });

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
        methods: ['GET', 'POST', 'OPTIONS'],
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
    return p === '/dnsbl' || p === '/dnsbl/batch' || p === '/api/dnsbl' || p === '/api/dnsbl/batch';
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

// Regex & Sanitization
const SAFE_IP_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;
const SAFE_DOMAIN_REGEX = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const SAFE_HASH_REGEX = /^[a-fA-F0-9]{32,64}$/;
const SAFE_CIDR_REGEX = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

const sanitizeQuery = (query, expectedType) => {
    const trimmed = query?.trim();
    if (!trimmed) throw new Error('Empty query');
    if (trimmed.length > 2048) throw new Error('Query too long');

    switch (expectedType) {
        case 'ip': {
            if (!SAFE_IP_REGEX.test(trimmed)) throw new Error('Invalid IP format');
            const octets = trimmed.split('.').map(Number);
            if (octets.some(o => o > 255 || o < 0)) throw new Error('Invalid IP octet');
            if (octets[0] === 10 || octets[0] === 127 ||
                (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
                (octets[0] === 192 && octets[1] === 168) ||
                (octets[0] === 169 && octets[1] === 254) ||
                trimmed === '0.0.0.0') {
                throw new Error('Internal/reserved IP not allowed');
            }
            return trimmed;
        }
        case 'cidr': {
            if (!SAFE_CIDR_REGEX.test(trimmed)) throw new Error('Invalid CIDR format');
            const [ipPart, maskPart] = trimmed.split('/');
            const mask = parseInt(maskPart, 10);
            if (mask < 0 || mask > 32) throw new Error('Invalid CIDR mask');
            const octets = ipPart.split('.').map(Number);
            if (octets.some(o => o > 255 || o < 0)) throw new Error('Invalid IP octet in CIDR');
            if (octets[0] === 10 || octets[0] === 127 ||
                (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
                (octets[0] === 192 && octets[1] === 168) ||
                (octets[0] === 169 && octets[1] === 254) ||
                ipPart === '0.0.0.0') {
                throw new Error('Internal/reserved CIDR block not allowed');
            }
            return trimmed;
        }
        case 'domain':
            if (!SAFE_DOMAIN_REGEX.test(trimmed)) throw new Error('Invalid domain format');
            if (trimmed.length > 253) throw new Error('Domain too long');
            return trimmed;
        case 'hash':
            if (!SAFE_HASH_REGEX.test(trimmed)) throw new Error('Invalid hash format');
            return trimmed;
        case 'url': {
            try {
                const parsed = new URL(trimmed);
                if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
                    throw new Error('Only http/https protocols allowed');
                }
                const hostname = parsed.hostname;
                if (SAFE_IP_REGEX.test(hostname)) {
                    const octets = hostname.split('.').map(Number);
                    if (octets[0] === 10 || octets[0] === 127 ||
                        (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
                        (octets[0] === 192 && octets[1] === 168) ||
                        (octets[0] === 169 && octets[1] === 254) ||
                        hostname === '0.0.0.0') {
                        throw new Error('Internal/reserved IP URL not allowed');
                    }
                }
                if (['localhost', 'localhost.localdomain'].includes(hostname.toLowerCase()) || hostname.endsWith('.local')) {
                    throw new Error('Local domains not allowed');
                }
                return trimmed;
            } catch (e) {
                throw new Error('Invalid URL: ' + e.message);
            }
        }
        default:
            throw new Error('Unknown expected type');
    }
};

const detectQueryType = (query) => {
    if (!query) return "unknown";
    const trimmed = query.trim();
    if (trimmed.length > 2048) return "unknown";

    if (/^(http|https):\/\/[^ "]+$/.test(trimmed)) return "url";
    if (/^[a-fA-F0-9]{32}$/.test(trimmed)) return "hash";
    if (/^[a-fA-F0-9]{40}$/.test(trimmed)) return "hash";
    if (/^[a-fA-F0-9]{64}$/.test(trimmed)) return "hash";
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) return "ip";
    if (/^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(trimmed)) return "domain";

    return "unknown";
};

// Security middleware to validate query format on requests
const validateRequest = (req, res, next) => {
    if (req.method === 'POST' && req.body?.query) {
        const type = detectQueryType(req.body.query);
        if (type === "unknown") {
            return res.status(400).json({ error: "Invalid query format. Must be a valid IP, Domain, Hash, or URL." });
        }
    }
    next();
};
app.use(validateRequest);

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

// Criminal IP
app.post('/api/criminalip', scanLimiter, async (req, res) => {
    const { query } = req.body;
    if (!process.env.CRIMINALIP_API_KEY) return res.status(500).json({ error: "API Key missing" });

    try {
        const queryType = detectQueryType(query);
        if (queryType !== "ip" && queryType !== "domain") return res.json({ data: { "Status": "IP/Domain only" } });
        const sanitized = sanitizeQuery(query, queryType);

        const endpoint = queryType === "ip"
            ? `https://api.criminalip.io/v1/ip/data`
            : `https://api.criminalip.io/v1/domain/reports`;

        const response = await axios.get(endpoint, {
            params: queryType === "ip" ? { ip: sanitized } : { query: sanitized },
            headers: { "x-api-key": process.env.CRIMINALIP_API_KEY },
        });
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
        const response = await axios.get(`https://api.ransomware.live/recentvictims`);
        res.json(response.data);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

const LATAM_COUNTRIES = new Set([
    'AR', 'BO', 'BR', 'CL', 'CO', 'CR', 'CU', 'DO', 'EC', 'GT', 'HN', 'MX',
    'NI', 'PA', 'PE', 'PR', 'PY', 'SV', 'UY', 'VE', 'BZ', 'GY', 'SR', 'GF',
]);

const COUNTRY_NAMES = {
    AR: 'Argentina', BO: 'Bolivia', BR: 'Brazil', CL: 'Chile', CO: 'Colombia',
    CR: 'Costa Rica', CU: 'Cuba', DO: 'Dominican Republic', EC: 'Ecuador',
    GT: 'Guatemala', HN: 'Honduras', MX: 'Mexico', NI: 'Nicaragua', PA: 'Panama',
    PE: 'Peru', PR: 'Puerto Rico', PY: 'Paraguay', SV: 'El Salvador', UY: 'Uruguay',
    VE: 'Venezuela', US: 'United States of America', ES: 'Spain', IT: 'Italy',
    PL: 'Poland', DE: 'Germany', FR: 'France', GB: 'United Kingdom', CA: 'Canada',
};

const asArray = (v) => Array.isArray(v) ? v : (Array.isArray(v?.data) ? v.data : []);
const countBy = (items, fn) => {
    const map = new Map();
    for (const item of items) {
        const key = fn(item);
        if (!key) continue;
        map.set(key, (map.get(key) || 0) + 1);
    }
    return [...map.entries()].sort((a, b) => b[1] - a[1]).map(([name, count]) => ({ name, count }));
};

function normalizeVictim(v) {
    const country = String(v.country || v.country_code || '').trim().toUpperCase();
    const name = String(v.post_title || v.victim || v.name || v.website || 'Unknown victim').trim();
    return {
        name,
        website: v.website || '',
        group: String(v.group_name || v.group || 'unknown').trim(),
        country,
        countryName: COUNTRY_NAMES[country] || country || 'Unknown',
        sector: String(v.activity || v.sector || 'Not Found').trim(),
        published: v.published || v.discovered || v.date || null,
        discovered: v.discovered || v.published || v.date || null,
        description: v.description && v.description !== 'N/A' ? String(v.description).slice(0, 500) : '',
        screenshot: v.screenshot || '',
        source: 'ransomware.live',
    };
}

async function getRecentRansomwareVictims() {
    const now = Date.now();
    if (memoryCache.ransomwareVictims.data && memoryCache.ransomwareVictims.expiresAt > now) {
        return memoryCache.ransomwareVictims.data;
    }
    const resp = await axios.get('https://api.ransomware.live/recentvictims', {
        timeout: 10000,
        maxRedirects: 3,
    });
    const victims = asArray(resp.data).map(normalizeVictim)
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

app.get('/api/intel/threat-map', async (req, res) => {
    try {
        const days = Math.max(1, Math.min(180, Number(req.query.days) || 90));
        const since = Date.now() - days * 24 * 60 * 60 * 1000;
        const victims = (await getRecentRansomwareVictims())
            .filter((v) => !v.discovered || new Date(v.discovered).getTime() >= since);
        const countries = countBy(victims, (v) => v.country)
            .map((c) => ({ ...c, countryName: COUNTRY_NAMES[c.name] || c.name }));
        const groups = countBy(victims, (v) => v.group).slice(0, 12);
        res.json({
            generatedAt: new Date().toISOString(),
            windowDays: days,
            source: 'ransomware.live',
            victims: victims.slice(0, 80),
            countries,
            groups,
            topCountry: countries[0] || null,
            activeGroups: groups.length,
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
            isp: data.isp,
            org: data.org,
            as: data.asn,
            proxy: false,
            hosting: false,
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
    // Guided Threat Hunting packs (from the Python hunt-service), keyed by `${lang}|${url}`.
    huntPack: {
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
        ttl: 6 * 60 * 60 * 1000 // 6 hours
    },
    // Per-month normalized Patch Tuesday summaries, keyed by id (e.g. "2026-Jun")
    patchTuesday: {
        store: new Map(),
        ttl: 24 * 60 * 60 * 1000 // 24 hours
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
    try { fs.writeFileSync(FEED_SOURCES_PATH, JSON.stringify(feedOverrides, null, 2)); }
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

app.get('/api/intel/daily-brief', async (req, res) => {
    try {
        if (!memoryCache.newsletter.data) await refreshNewsletterFeed();
        const feed = memoryCache.newsletter.data || [];
        const now = Date.now();
        const dayMs = 24 * 60 * 60 * 1000;
        const recent = feed.filter((item) => {
            const t = new Date(item.pubDate || item.date || 0).getTime();
            return Number.isFinite(t) && now - t <= 36 * 60 * 60 * 1000;
        });
        const highSignal = recent.filter((item) => (item.score || 0) >= 65 || item.kev);
        const kev = recent.filter((item) => item.kev);
        const cves = [...new Set(recent.flatMap((item) => item.cves || []))];
        const critical = recent.filter((item) => String(item.severity || '').toLowerCase() === 'critical');
        const victims = (await getRecentRansomwareVictims().catch(() => []))
            .filter((v) => !v.discovered || now - new Date(v.discovered).getTime() <= dayMs)
            .slice(0, 12);
        const latamVictims = victims.filter((v) => LATAM_COUNTRIES.has(v.country));
        const verdict = kev.length || highSignal.length >= 6 || victims.length >= 8 ? 'hot'
            : highSignal.length || victims.length ? 'watch'
            : 'calm';
        const top = [...recent]
            .sort((a, b) => (b.kev ? 25 : 0) + (b.score || 0) - ((a.kev ? 25 : 0) + (a.score || 0)))
            .slice(0, 10);

        res.json({
            generatedAt: new Date().toISOString(),
            title: verdict === 'hot'
                ? 'Dia quente: priorize exploração ativa, ransomware e advisories críticos'
                : verdict === 'watch'
                    ? 'Dia de atenção: sinais relevantes em advisories e ransomware'
                    : 'Dia calmo: monitore CVEs novas e mantenha correções planejadas',
            verdict,
            summary: {
                totalAdvisories: recent.length,
                critical: critical.length,
                kev: kev.length,
                cves: cves.length,
                ransomwareVictims: victims.length,
                latamVictims: latamVictims.length,
            },
            highlights: top.map((item) => ({
                title: item.title,
                titlePt: item.titlePt,
                link: item.link,
                source: item.source,
                pubDate: item.pubDate,
                score: item.score || 0,
                severity: item.severity || 'Low',
                cves: item.cves || [],
                kev: !!item.kev,
                reasons: item.reasons || [],
            })),
            ransomware: {
                victims,
                groups: countBy(victims, (v) => v.group).slice(0, 8),
                latam: latamVictims,
            },
            sources: ['RSS advisories', 'CISA KEV', 'FIRST EPSS', 'ransomware.live'],
        });
    } catch (error) {
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
        { name: 'Criminal IP', env: 'CRIMINALIP_API_KEY', configured: set('CRIMINALIP_API_KEY'), required: true },
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

// ─── Publicações / Advisories (blog do CISO advisor) ───────────────────────
// Posts em Markdown, store flat em disco (como .users.json). Leitura é pública,
// mas só de publicados; rascunhos e qualquer escrita são só admin. O slug é a
// chave estável na URL. Sem render de Markdown no servidor — o corpo vai cru pro
// cliente, que renderiza (react-markdown, sem HTML bruto, então sem risco de XSS).
const POSTS_STORE_PATH = path.join(__dirname, '.posts.json');
function loadPosts() { try { const a = JSON.parse(fs.readFileSync(POSTS_STORE_PATH, 'utf8')); return Array.isArray(a) ? a : []; } catch { return []; } }
function savePosts() { try { fs.writeFileSync(POSTS_STORE_PATH, JSON.stringify(postsStore, null, 2)); } catch (e) { console.error('posts store write failed:', e.message); } }
let postsStore = loadPosts();

function slugify(s) {
    return String(s).toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '')
        .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80) || 'post';
}
function uniqueSlug(base, ignoreId) {
    let slug = base, n = 2;
    while (postsStore.some((p) => p.slug === slug && p.id !== ignoreId)) slug = `${base}-${n++}`;
    return slug;
}
function normTags(t) {
    const arr = Array.isArray(t) ? t : (typeof t === 'string' ? t.split(',') : []);
    return [...new Set(arr.map((x) => String(x).trim()).filter(Boolean))].slice(0, 12);
}
// Resumo p/ a listagem: tudo menos o corpo (economiza payload).
function postCard(p) {
    const { body, ...rest } = p;
    return rest;
}
// true se a sessão atual é de um admin (leitura opcional: não exige login).
function sessionAdmin(req) {
    const p = verifySession(getCookie(req, 'ts_session'));
    return !!(p && isAdmin(p.login));
}

// Lista. Público vê só publicados (mais novo primeiro); admin vê tudo.
app.get('/api/posts', (req, res) => {
    const admin = sessionAdmin(req);
    const list = postsStore
        .filter((p) => admin || p.published)
        .sort((a, b) => String(b.publishedAt || b.createdAt).localeCompare(String(a.publishedAt || a.createdAt)))
        .map(postCard);
    res.json({ posts: list, isAdmin: admin });
});

// Post por slug (com corpo). Rascunho só admin.
app.get('/api/posts/:slug', (req, res) => {
    const admin = sessionAdmin(req);
    const p = postsStore.find((x) => x.slug === req.params.slug);
    if (!p || (!p.published && !admin)) return res.status(404).json({ error: 'publicação não encontrada' });
    res.json({ post: p, isAdmin: admin });
});

// Cria. Admin. Body: { title, summary, body, tags, published, slug? }.
app.post('/api/posts', requireAdmin, (req, res) => {
    const b = req.body || {};
    const title = String(b.title || '').trim();
    if (!title) return res.status(400).json({ error: 'título obrigatório' });
    const now = new Date().toISOString();
    const published = !!b.published;
    const post = {
        id: crypto.randomBytes(8).toString('hex'),
        slug: uniqueSlug(slugify(b.slug || title)),
        title,
        summary: String(b.summary || '').trim(),
        body: String(b.body || ''),
        tags: normTags(b.tags),
        author: req.user.login,
        published,
        createdAt: now,
        updatedAt: now,
        publishedAt: published ? now : null,
    };
    postsStore.push(post);
    savePosts();
    res.status(201).json({ post });
});

// Edita (parcial). Admin. :id na rota.
app.patch('/api/posts/:id', requireAdmin, (req, res) => {
    const p = postsStore.find((x) => x.id === req.params.id);
    if (!p) return res.status(404).json({ error: 'publicação não encontrada' });
    const b = req.body || {};
    if (b.title !== undefined) {
        const t = String(b.title).trim();
        if (!t) return res.status(400).json({ error: 'título obrigatório' });
        p.title = t;
    }
    if (b.summary !== undefined) p.summary = String(b.summary).trim();
    if (b.body !== undefined) p.body = String(b.body);
    if (b.tags !== undefined) p.tags = normTags(b.tags);
    if (b.slug !== undefined) p.slug = uniqueSlug(slugify(b.slug || p.title), p.id);
    if (b.published !== undefined) {
        const np = !!b.published;
        if (np && !p.published) p.publishedAt = new Date().toISOString();
        p.published = np;
    }
    p.updatedAt = new Date().toISOString();
    savePosts();
    res.json({ post: p });
});

// Remove. Admin.
app.delete('/api/posts/:id', requireAdmin, (req, res) => {
    const before = postsStore.length;
    postsStore = postsStore.filter((x) => x.id !== req.params.id);
    if (postsStore.length === before) return res.status(404).json({ error: 'publicação não encontrada' });
    savePosts();
    res.json({ ok: true });
});

// RSS 2.0 dos Advisories publicados — distribuição do blog (leitores, agregadores).
app.get('/api/advisories/feed.xml', (req, res) => {
    const base = APP_BASE_URL;
    const published = postsStore
        .filter((p) => p.published)
        .sort((a, b) => String(b.publishedAt || b.createdAt).localeCompare(String(a.publishedAt || a.createdAt)))
        .slice(0, 50);
    const items = published.map((p) => {
        const link = `${base}/advisories/${p.slug}`;
        const date = new Date(p.publishedAt || p.createdAt).toUTCString();
        const cats = (p.tags || []).map((t) => `<category>${escapeHtml(t)}</category>`).join('');
        return `    <item>
      <title>${escapeHtml(p.title)}</title>
      <link>${escapeHtml(link)}</link>
      <guid isPermaLink="false">${escapeHtml(p.id)}</guid>
      <pubDate>${date}</pubDate>
      <description>${escapeHtml(p.summary || '')}</description>
      ${cats}
    </item>`;
    }).join('\n');
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>ThreatSumm4ry · Advisories</title>
    <link>${base}/advisories</link>
    <description>Análises e alertas sobre campanhas, ameaças e tendências.</description>
    <language>pt-br</language>
    <atom:link href="${base}/api/advisories/feed.xml" rel="self" type="application/rss+xml"/>
${items}
  </channel>
</rss>`;
    res.set('Content-Type', 'application/rss+xml; charset=utf-8');
    res.set('Cache-Control', 'public, max-age=300');
    res.send(xml);
});

// ─── Scans salvos por usuário (histórico do IOC search) ────────────────────
// Store flat por usuário: cada scan guarda a query + o veredito consensual, pra
// revisitar de qualquer dispositivo. De-dup por query (mantém o mais recente),
// cap por usuário. Só a própria sessão lê/escreve os seus.
const SCANS_STORE_PATH = path.join(__dirname, '.scans.json');
function loadScansStore() { try { const o = JSON.parse(fs.readFileSync(SCANS_STORE_PATH, 'utf8')); return (o && typeof o === 'object') ? o : {}; } catch { return {}; } }
function saveScansStore() { try { fs.writeFileSync(SCANS_STORE_PATH, JSON.stringify(scansStore, null, 2)); } catch (e) { console.error('scans store write failed:', e.message); } }
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
function saveUsers() { try { fs.writeFileSync(USERS_STORE_PATH, JSON.stringify(usersStore, null, 2)); } catch (e) { console.error('users store write failed:', e.message); } }
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
    try { fs.writeFileSync(ALLOWLIST_STORE_PATH, JSON.stringify(dynamicAllowlist, null, 2)); }
    catch (e) { console.error('allowlist store write failed:', e.message); }
}
let dynamicAllowlist = loadAllowlist();

function hasPremiumAccessSync(login) {
    const l = (login || '').toLowerCase();
    return ALLOWED_LOGINS.includes(l) || dynamicAllowlist.includes(l);
}

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
    'hybridanalysis', 'metadefender', 'criminalip', 'censys',
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

// ─── Boletim · jobs de geração por URL (1 URL = 1 boletim) ─────────────────
// O front escolhe UMA url e pede a geração (POST generate); um worker na VPS
// (saida-so, porta fechada) faz poll dos pendentes (GET jobs/pending), roda
// o motor pesado, e devolve o JSON (POST job/result, 🔒). O front faz poll do
// job (GET job) e baixa o JSON quando pronto; o PPT é preenchido localmente.
const JOBS_STORE_PATH = path.join(__dirname, '.feed-jobs.json');
function loadJobs() { try { return JSON.parse(fs.readFileSync(JOBS_STORE_PATH, 'utf8')); } catch { return {}; } }
function saveJobs() { try { fs.writeFileSync(JOBS_STORE_PATH, JSON.stringify(jobsStore, null, 2)); } catch (e) { console.error('jobs store write failed:', e.message); } }
let jobsStore = loadJobs();   // { id: { id,url,type,title,status,json,error,createdAt,updatedAt } }

function pruneJobs(max = 100) {
    const ids = Object.keys(jobsStore).sort((a, b) => (jobsStore[a].createdAt || '').localeCompare(jobsStore[b].createdAt || ''));
    while (ids.length > max) { const id = ids.shift(); delete jobsStore[id]; }
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
    if (job.ownerSub && job.ownerSub !== req.user.sub) return res.status(403).json({ error: 'job pertence a outro usuário' });
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

// Worker (VPS) lê os jobs pendentes. 🔒   GET /api/feed/jobs/pending
app.get('/api/feed/jobs/pending', (req, res) => {
    if (!requireFeedSecret(req, res)) return;
    expireStaleJobs();
    // Sem BYOK: todo job pending vai pro worker. A chave OpenRouter é do servidor
    // (no .env do worker), não viaja no payload. Só encaminhamos o modelo.
    const pending = Object.values(jobsStore)
        .filter((j) => j.status === 'pending')
        .map((j) => ({
            id: j.id,
            url: j.url,
            type: j.type,
            title: j.title,
            model: process.env.OPENROUTER_MODEL || 'deepseek/deepseek-chat-v3.1',
        }));
    res.json({ pending });
});

// Worker (VPS) devolve o resultado. 🔒   POST /api/feed/job/result {id, json|error}
app.post('/api/feed/job/result', (req, res) => {
    if (!requireFeedSecret(req, res)) return;
    const job = jobsStore[(req.body?.id || '').toString()];
    if (!job) return res.status(404).json({ error: 'job não encontrado' });
    if (req.body?.error) { job.status = 'error'; job.error = String(req.body.error).slice(0, 500); }
    else if (req.body?.json && typeof req.body.json === 'object') { job.status = 'done'; job.json = req.body.json; }
    else return res.status(400).json({ error: 'json ou error obrigatório' });
    job.updatedAt = new Date().toISOString();
    saveJobs();
    res.json({ id: job.id, status: job.status });
});

// ─── OpenRouter-powered on-demand advisory analysis ───────────────────────
const OPENROUTER_BASE_URL = 'https://openrouter.ai/api/v1';
const OPENROUTER_MODEL = process.env.OPENROUTER_MODEL || 'deepseek/deepseek-chat-v3.1';

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

// Advanced collection: fetch the full article and extract its readable body
// text (paragraphs), mirroring the bot's deep-content step. Dependency-free
// heuristic; returns '' if the page can't be fetched/parsed (then we fall back
// to the RSS summary). Best-effort and tolerant of WAF/JS-heavy sites.
const ARTICLE_BOILERPLATE = /^(advertisement|scroll to continue|related\s*:|written by|subscribe|sign up|sponsored|©|cookie|share this|read more|tags:|follow us|newsletter|sign up to)/i;

function extractReadableText(html) {
    try {
        const $ = cheerio.load(html);
        // Strip non-content chrome
        $('script,style,noscript,nav,aside,footer,header,form,iframe,figure,figcaption,.ad,.ads,.advertisement,.related,.newsletter,.share,.social,[class*="promo"],[class*="sidebar"]').remove();
        // Pick the densest content root (article/main, else body)
        let root = $('article').first();
        if (!root.length) root = $('main').first();
        if (!root.length) root = $('body');
        const paras = [];
        root.find('p').each((_, el) => {
            const t = $(el).text().replace(/\s+/g, ' ').trim();
            if (t.length > 45 && !ARTICLE_BOILERPLATE.test(t) && !/\(@\w+\)\s+is\s+(a|the|senior|managing)/i.test(t)) {
                paras.push(t);
            }
        });
        return paras.join('\n\n');
    } catch {
        return '';
    }
}

async function fetchArticleText(url) {
    try {
        const resp = await axios.get(url, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                Accept: 'text/html,application/xhtml+xml',
            },
            timeout: 10000,
            maxRedirects: 3,
            responseType: 'text',
        });
        return extractReadableText(resp.data).slice(0, 8000);
    } catch (err) {
        console.warn(`Article fetch failed for ${url}: ${err.message}`);
        return '';
    }
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
        const fullText = await fetchArticleText(item.link);
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
        // title+summary set computed at collection). High-precision: hashes +
        // defanged network indicators + public IPv4.
        const iocs = extractIOCs(content);

        let payload;
        if (ai && ai.summary) {
            // Single executive-summary paragraph only (prompt no longer asks for
            // impact/mitigation, to save output tokens).
            payload = {
                available: true, source: 'openrouter', scraped: !!fullText,
                title: ai.title || item.title,
                executiveSummary: String(ai.summary).trim(),
                impactMitigation: '',
                iocs, ...enriched,
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
                    title: t || item.title, executiveSummary: ex || execRaw, impactMitigation: mit || '', iocs, ...enriched,
                };
            } else {
                payload = {
                    available: false, source: 'rss', scraped: !!fullText,
                    title: item.title, executiveSummary: execRaw, impactMitigation: mitRaw || '', iocs, ...enriched,
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

// Guided Threat Hunting: proxy to the Python hunt-service which scrapes the
// report (Scrapling), runs OpenRouter + Pydantic validation/retry, and returns a
// defanged structured Hunt Pack. Advisories from the live feed are trusted by
// their allowlisted URL; any other pasted URL must pass the SSRF guard above so
// this can't be used to scan internal infrastructure.
app.post('/api/newsletter/hunt-pack', requirePremium, scanLimiter, async (req, res) => {
    try {
        const url = (req.body?.url || '').toString();
        const lang = req.body?.lang === 'en' ? 'en' : 'pt';
        if (!url) return res.status(400).json({ error: 'Missing advisory url' });

        if (!process.env.HUNT_SERVICE_URL) {
            return res.status(503).json({ error: 'Threat hunting service not configured' });
        }

        const feed = memoryCache.newsletter.data || [];
        const item = feed.find((i) => i.link === url);

        // Feed advisories carry a known-good title; pasted URLs are validated for
        // SSRF before we let the scraper anywhere near them.
        let title = '';
        if (item) {
            title = item.title;
        } else {
            try {
                await assertSafePublicUrl(url);
            } catch (e) {
                return res.status(400).json({ error: e.message || 'URL rejected' });
            }
        }

        const cacheKey = `${lang}|${url}`;
        const now = Date.now();
        const cached = memoryCache.huntPack.store.get(cacheKey);
        if (cached && cached.expiresAt > now) return res.json(cached.data);

        const response = await axios.post(
            `${process.env.HUNT_SERVICE_URL.replace(/\/$/, '')}/hunt-pack`,
            { url, lang, title },
            {
                headers: {
                    'Content-Type': 'application/json',
                    ...(process.env.HUNT_SERVICE_SECRET ? { 'X-Hunt-Secret': process.env.HUNT_SERVICE_SECRET } : {}),
                },
                // Browser scraping + LLM + validation retries can be slow, and a
                // free host may be cold-starting; allow a generous budget.
                timeout: 120000,
            }
        );

        cacheSet(memoryCache.huntPack.store, cacheKey, { data: response.data, expiresAt: now + memoryCache.huntPack.ttl }, 200);
        res.json(response.data);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
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
//  Microsoft Patch Tuesday (MSRC CVRF v3.0) Summary
// ============================================================

const MSRC_BASE = 'https://api.msrc.microsoft.com/cvrf/v3.0';
const SEVERITY_RANK = { Critical: 4, Important: 3, Moderate: 2, Low: 1 };

const stripHtml = (str) => (str || '').replace(/<[^>]*>/g, ' ').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ').trim();

// Classify a vulnerability into a single product family using its title + affected product names
const classifyFamily = (title, productNames) => {
    const hay = `${title || ''} ${productNames.join(' ')}`.toLowerCase();
    if (/azure|microsoft entra|defender for/.test(hay)) return 'Azure & Cloud';
    if (/sharepoint/.test(hay)) return 'SharePoint';
    if (/exchange/.test(hay)) return 'Exchange Server';
    if (/sql server/.test(hay)) return 'SQL Server';
    if (/\.net|visual studio|asp\.net|nuget|powershell/.test(hay)) return 'Developer Tools & .NET';
    if (/office|word|excel|powerpoint|outlook|visio|onenote|\baccess\b|publisher/.test(hay)) return 'Microsoft Office';
    if (/\bedge\b|chromium/.test(hay)) return 'Microsoft Edge';
    if (/dynamics/.test(hay)) return 'Dynamics 365';
    if (/system center/.test(hay)) return 'System Center';
    if (/windows|win32|kernel|hyper-v|\brdp\b|smb|\bdns\b|tcp\/ip|active directory/.test(hay)) return 'Windows';
    return 'Other Microsoft Products';
};

const parseExploitStatus = (str) => {
    const s = str || '';
    const m = (re) => (s.match(re)?.[1] || '').trim();
    return {
        exploited: /Exploited:\s*Yes/i.test(s),
        publiclyDisclosed: /Publicly Disclosed:\s*Yes/i.test(s),
        exploitability: m(/Latest Software Release:\s*([^;]+)/i) || 'N/A'
    };
};

// Transform a raw CVRF document into a compact, presentation-ready summary
const normalizeCvrf = (doc) => {
    const productNameById = {};
    for (const p of (doc.ProductTree?.FullProductName || [])) {
        productNameById[p.ProductID] = p.Value;
    }

    const totals = { total: 0, critical: 0, important: 0, moderate: 0, low: 0, unknown: 0, exploited: 0, disclosed: 0, exploitMoreLikely: 0 };
    const byImpact = {};
    const byFamily = {};
    const vulnerabilities = [];

    for (const v of (doc.Vulnerability || [])) {
        if (!v.CVE) continue;
        const threats = v.Threats || [];

        // Highest severity across products (Threat Type 3)
        let severity = null, sevRank = 0;
        for (const t of threats) {
            if (t.Type !== 3) continue;
            const val = t.Description?.Value;
            if (val && SEVERITY_RANK[val] && SEVERITY_RANK[val] > sevRank) { severity = val; sevRank = SEVERITY_RANK[val]; }
        }

        // Impact / vulnerability category (Threat Type 0)
        const impact = threats.find(t => t.Type === 0 && t.Description?.Value)?.Description?.Value || 'Other';

        // Exploit status (Threat Type 1)
        const ex = parseExploitStatus(threats.find(t => t.Type === 1)?.Description?.Value);

        // Highest CVSS base score + its vector
        let cvss = 0, vector = '';
        for (const c of (v.CVSSScoreSets || [])) {
            if ((c.BaseScore || 0) > cvss) { cvss = c.BaseScore; vector = c.Vector || ''; }
        }

        const affectedIds = (v.ProductStatuses || []).find(s => s.Type === 3)?.ProductID || [];
        const productNames = affectedIds.map(id => productNameById[id]).filter(Boolean);
        const family = classifyFamily(v.Title?.Value, productNames);

        // KB / vendor fixes (Remediation Type 2)
        const kbSet = new Map();
        for (const r of (v.Remediations || [])) {
            if (r.Type === 2 && r.Description?.Value) {
                kbSet.set(r.Description.Value, r.URL || `https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB${r.Description.Value}`);
            }
        }

        const description = stripHtml((v.Notes || []).find(n => n.Type === 2)?.Value).slice(0, 600);
        const cwe = Array.isArray(v.CWE) ? (v.CWE[0]?.Value || '') : (v.CWE?.Value || '');

        // Tallies
        totals.total++;
        if (severity === 'Critical') totals.critical++;
        else if (severity === 'Important') totals.important++;
        else if (severity === 'Moderate') totals.moderate++;
        else if (severity === 'Low') totals.low++;
        else totals.unknown++;
        if (ex.exploited) totals.exploited++;
        if (ex.publiclyDisclosed) totals.disclosed++;
        if (/More Likely/i.test(ex.exploitability)) totals.exploitMoreLikely++;
        byImpact[impact] = (byImpact[impact] || 0) + 1;
        byFamily[family] = (byFamily[family] || 0) + 1;

        vulnerabilities.push({
            cve: v.CVE,
            title: v.Title?.Value || '',
            description,
            cwe,
            severity: severity || 'Unknown',
            impact,
            cvss: cvss || null,
            vector,
            exploited: ex.exploited,
            publiclyDisclosed: ex.publiclyDisclosed,
            exploitability: ex.exploitability,
            family,
            productCount: affectedIds.length,
            kbs: [...kbSet.entries()].map(([kb, url]) => ({ kb, url })),
            releaseDate: v.ReleaseDate || null
        });
    }

    // Sort by exploited, then disclosed, then CVSS desc
    vulnerabilities.sort((a, b) =>
        (b.exploited - a.exploited) ||
        (b.publiclyDisclosed - a.publiclyDisclosed) ||
        ((b.cvss || 0) - (a.cvss || 0))
    );

    const sortEntries = (obj) => Object.entries(obj).sort((a, b) => b[1] - a[1]).map(([name, count]) => ({ name, count }));

    return {
        id: doc.DocumentTracking?.Identification?.ID?.Value || '',
        title: doc.DocumentTitle?.Value || '',
        initialReleaseDate: doc.DocumentTracking?.InitialReleaseDate || null,
        currentReleaseDate: doc.DocumentTracking?.CurrentReleaseDate || null,
        totals,
        byImpact: sortEntries(byImpact),
        byFamily: sortEntries(byFamily),
        topCves: vulnerabilities.slice(0, 12),
        vulnerabilities
    };
};

// Fetch the live list of monthly "Security Updates" from MSRC and cache it
async function fetchAndCacheMonths() {
    const response = await axios.get(`${MSRC_BASE}/updates`, {
        headers: { Accept: 'application/json' },
        timeout: 12000
    });
    const months = (response.data?.value || [])
        .filter(m => /Security Updates/i.test(m.DocumentTitle || ''))
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

// Fetch + normalize the CVRF document for one month and cache it
async function fetchAndCacheSummary(id) {
    const response = await axios.get(`${MSRC_BASE}/cvrf/${id}`, {
        headers: { Accept: 'application/json' },
        timeout: 20000
    });
    const summary = normalizeCvrf(response.data);
    cacheSet(memoryCache.patchTuesday.store, id, { data: summary, expiresAt: Date.now() + memoryCache.patchTuesday.ttl }, 36);
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
        res.set('Cache-Control', 'public, max-age=21600');
        return res.json(memoryCache.patchTuesdayMonths.data);
    }
    try {
        res.set('Cache-Control', 'public, max-age=21600');
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
    if (cached && cached.expiresAt > now) {
        res.set('Cache-Control', 'public, max-age=3600');
        return res.json(cached.data);
    }

    try {
        res.set('Cache-Control', 'public, max-age=3600');
        res.json(await fetchAndCacheSummary(id));
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

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    // Prime the newsletter RSS feed cache and schedule background updates
    refreshNewsletterFeed();
    setInterval(refreshNewsletterFeed, memoryCache.newsletter.ttl);

    // Prime the Patch Tuesday cache and refresh it so each new monthly release
    // (and mid-month revisions) is picked up automatically.
    refreshPatchTuesday();
    setInterval(refreshPatchTuesday, memoryCache.patchTuesdayMonths.ttl);
});
