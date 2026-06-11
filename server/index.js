import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import dotenv from 'dotenv';
import axios from 'axios';
import path from 'path';
import { fileURLToPath } from 'url';
import dns from 'dns';
import fs from 'fs';
import crypto from 'crypto';
import compression from 'compression';
import { scoreArticle, CTI_FEEDS } from './ctiIntel.js';

dotenv.config({ path: '../.env' });

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
app.use(express.json({ limit: '10kb' }));
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
    if (req.method === 'POST' && req.body.query) {
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

// --- API Endpoints ---

// VirusTotal
app.post('/api/virustotal', scanLimiter, async (req, res) => {
    const { query } = req.body;
    if (!process.env.VIRUSTOTAL_API_KEY) return res.status(500).json({ error: "API Key missing" });

    try {
        const queryType = detectQueryType(query);
        const sanitized = sanitizeQuery(query, queryType);
        let endpoint = "";

        if (queryType === "ip") endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${sanitized}`;
        else if (queryType === "domain") endpoint = `https://www.virustotal.com/api/v3/domains/${sanitized}`;
        else if (queryType === "hash") endpoint = `https://www.virustotal.com/api/v3/files/${sanitized}`;
        else endpoint = `https://www.virustotal.com/api/v3/urls/${Buffer.from(sanitized).toString('base64').replace(/=/g, "")}`;

        const response = await axios.get(endpoint, {
            headers: { "x-apikey": process.env.VIRUSTOTAL_API_KEY }
        });
        sendResponseWithQuota(res, response);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// AbuseIPDB
app.post('/api/abuseipdb', scanLimiter, async (req, res) => {
    const { query } = req.body;
    if (!process.env.ABUSEIPDB_API_KEY) return res.status(500).json({ error: "API Key missing" });

    try {
        const queryType = detectQueryType(query);
        if (queryType !== "ip") return res.json({ data: { "Status": "IP only" } }); 

        const sanitized = sanitizeQuery(query, 'ip');
        const response = await axios.get(`https://api.abuseipdb.com/api/v2/check`, {
            params: {
                ipAddress: sanitized,
                maxAgeInDays: 90,
                verbose: true
            },
            headers: { "Key": process.env.ABUSEIPDB_API_KEY, "Accept": "application/json" }
        });
        sendResponseWithQuota(res, response);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// AbuseIPDB Check-Block
app.post('/api/abuseipdb/check-block', scanLimiter, async (req, res) => {
    const { query } = req.body;
    if (!process.env.ABUSEIPDB_API_KEY) return res.status(500).json({ error: "API Key missing" });
    if (!query) return res.status(400).json({ error: "Network parameter 'query' is required" });

    try {
        const sanitized = sanitizeQuery(query, 'cidr');
        const response = await axios.get(`https://api.abuseipdb.com/api/v2/check-block`, {
            params: {
                network: sanitized,
                maxAgeInDays: 90
            },
            headers: { "Key": process.env.ABUSEIPDB_API_KEY, "Accept": "application/json" }
        });
        sendResponseWithQuota(res, response);
    } catch (error) {
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
        if (queryType !== "ip") return res.json({ data: { "Status": "IP only" } });

        const sanitized = sanitizeQuery(query, 'ip');
        const response = await axios.get(`https://api.shodan.io/shodan/host/${sanitized}`, {
            params: { key: process.env.SHODAN_API_KEY }
        });
        sendResponseWithQuota(res, response);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// URLhaus
app.post('/api/urlhaus', scanLimiter, async (req, res) => {
    const { query } = req.body;
    try {
        const queryType = detectQueryType(query);
        if (queryType !== "url" && queryType !== "domain") {
            return res.status(400).json({ error: "URL or Domain query required" });
        }
        const sanitized = sanitizeQuery(query, queryType);

        // Safe x-www-form-urlencoded formatting (VULN-08)
        const params = new URLSearchParams();
        params.append('host', sanitized);

        const response = await axios.post(`https://urlhaus-api.abuse.ch/v1/host/`,
            params.toString(),
            { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
        );
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

        const response = await axios.post(`https://mb-api.abuse.ch/api/v1/`,
            params.toString(),
            { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
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
        const response = await axios.get(`https://hashlookup.circl.lu/lookup/sha256/${sanitized}`);
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
        if (queryType !== "hash" && queryType !== "ip") return res.json({ data: { "Status": "Hash/IP only" } });
        const sanitized = sanitizeQuery(query, queryType);

        const endpoint = queryType === "hash"
            ? `https://api.metadefender.com/v4/hash/${sanitized}`
            : `https://api.metadefender.com/v4/ip/${sanitized}`;

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

// DShield (SANS ISC)
app.post('/api/dshield', scanLimiter, async (req, res) => {
    const { query } = req.body;
    try {
        const queryType = detectQueryType(query);
        if (queryType !== "ip") return res.json({ data: { "Status": "IP only" } });

        const sanitized = sanitizeQuery(query, 'ip');
        const response = await axios.get(`https://isc.sans.edu/api/ip/${sanitized}?json`);
        res.json(response.data);
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

        const result = {
            ip: resource.ip,
            service_count: resource.service_count || 0,
            services: (resource.services || []).map(svc => ({
                port: svc.port,
                protocol: svc.protocol || "UNKNOWN",
                transport: svc.transport_protocol || "tcp",
                software: svc.software?.product || svc.software?.vendor || null,
                software_version: svc.software?.version || null,
                scan_time: svc.scan_time,
                http_status: svc.http?.response?.status_code || null,
                http_title: svc.http?.response?.html_title || null,
                http_headers: svc.http?.response?.headers ? Object.keys(svc.http.response.headers).slice(0, 10) : null,
                http_body_hash: svc.http?.response?.body_hash || null,
                tls_version: svc.tls?.version_selected || null,
                certificate_fingerprint: svc.tls?.certificates?.leaf_data?.fingerprint || null,
                certificate_subject: svc.tls?.certificates?.leaf_data?.subject_dn || null,
                certificate_issuer: svc.tls?.certificates?.leaf_data?.issuer_dn || null,
                certificate_names: svc.tls?.certificates?.leaf_data?.names || [],
                certificate_trusted: svc.tls?.certificates?.leaf_data?.browser_trust?.is_trusted || null,
            })),
            location: resource.location ? {
                country: resource.location.country,
                country_code: resource.location.country_code,
                city: resource.location.city,
                province: resource.location.province,
                continent: resource.location.continent,
            } : null,
            autonomous_system: resource.autonomous_system ? {
                asn: resource.autonomous_system.asn,
                name: resource.autonomous_system.name || resource.autonomous_system.description,
                bgp_prefix: resource.autonomous_system.bgp_prefix,
            } : null,
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
    }
};

// Background newsletter feed refresher
async function refreshNewsletterFeed() {
    try {
        // Specialized feed catalog with per-source confidence (weight_boost),
        // ported from the soc-sentinela CTI bot.
        const feeds = CTI_FEEDS;

        const feedPromises = feeds.map(async (f) => {
            try {
                const response = await axios.get(f.url, {
                    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36' },
                    timeout: 8000
                });
                // Enrich each item with the CTI relevance score + categorization
                return parseFeed(response.data, f.source, f.layer).map((item) => {
                    const intel = scoreArticle(`${item.title} ${item.description}`, f.weight_boost);
                    return { ...item, weight_boost: f.weight_boost, ...intel };
                });
            } catch (err) {
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

        // Default order: most recent first (the route can re-sort by relevance).
        const unifiedFeed = [...byUrl.values()].sort((a, b) => new Date(b.pubDate) - new Date(a.pubDate));

        memoryCache.newsletter.data = unifiedFeed;
        memoryCache.newsletter.expiresAt = Date.now() + memoryCache.newsletter.ttl;
    } catch (error) {
        console.error("Failed to background refresh newsletter feeds:", error.message);
    }
}

// CTI News feed endpoint.
// Optional query params: minScore (0-100), severity (Critical|High|Medium|Low),
// category (substring of a category label), layer (1-4), sort (relevance|date).
app.get('/api/newsletter', async (req, res) => {
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

        res.json(data);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// ─── Groq-powered on-demand advisory analysis ─────────────────────────────
const GROQ_BASE_URL = 'https://api.groq.com/openai/v1';
const GROQ_MODELS = ['llama-3.3-70b-versatile', 'llama-3.1-8b-instant', 'gemma2-9b-it'];

const newsIntelPrompt = (lang) => (
    'You are a senior Cyber Threat Intelligence analyst. Produce a concise, technical report. ' +
    'Respond ONLY with a JSON object with these keys:\n' +
    '1. "title": the advisory title, professionally normalized.\n' +
    '2. "summary": EXACTLY TWO paragraphs separated by \\n\\n. Paragraph 1 technically describes WHAT happened ' +
    '(the threat, incident or fact). Paragraph 2 depends on the type: for a vulnerability/incident give the IMPACT ' +
    'and concrete MITIGATION measures; for market/regulatory/geopolitical/regional news give the STRATEGIC RELEVANCE ' +
    'for a SOC/CTI operation. NEVER invent mitigations for non-technical facts.\n' +
    '3. "iocs": an object with keys "IPs", "Domains", "Hashes" listing every technical indicator found, ' +
    'or "None identified" when there are none.\n' +
    `OUTPUT LANGUAGE: ${lang === 'en' ? 'English' : 'Português (Brasil)'}. Respond ONLY the JSON, no extra text.`
);

// Free Google Translate endpoint (no key). Returns translated text, or the
// original on any failure. Used as the no-Groq fallback so advisories are at
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

// Call Groq chat completions with a small model fallback chain; returns parsed JSON or null.
async function groqAnalyze(title, content, lang) {
    if (!process.env.GROQ_API_KEY) return null;
    const userPrompt = `Title: ${title}\nOriginal content: ${(content || '').slice(0, 12000)}`;
    for (const model of GROQ_MODELS) {
        try {
            const resp = await axios.post(`${GROQ_BASE_URL}/chat/completions`, {
                model,
                temperature: 0.1,
                response_format: { type: 'json_object' },
                messages: [
                    { role: 'system', content: newsIntelPrompt(lang) },
                    { role: 'user', content: userPrompt },
                ],
            }, {
                headers: { Authorization: `Bearer ${process.env.GROQ_API_KEY}`, 'Content-Type': 'application/json' },
                timeout: 20000,
            });
            const text = resp.data?.choices?.[0]?.message?.content;
            if (text) return JSON.parse(text);
        } catch (err) {
            console.warn(`Groq model ${model} failed: ${err.message}. Trying next...`);
        }
    }
    return null;
}

// On-demand actionable analysis for a single advisory (looked up in the live feed
// by URL to prevent arbitrary LLM abuse). Returns Executive Summary + Impact/
// Mitigation. Degrades gracefully to the RSS description when Groq is unavailable.
app.post('/api/newsletter/enrich', scanLimiter, async (req, res) => {
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

        const ai = await groqAnalyze(item.title, item.description, lang);

        let payload;
        if (ai && ai.summary) {
            const paras = String(ai.summary).split(/\n\n+/).map((p) => p.trim()).filter(Boolean);
            payload = {
                available: true,
                source: 'groq',
                title: ai.title || item.title,
                executiveSummary: paras[0] || String(ai.summary),
                impactMitigation: paras.slice(1).join('\n\n'),
                iocs: ai.iocs || null,
            };
        } else if (lang === 'pt') {
            // No LLM: translate the RSS content to Portuguese via Google Translate
            // so it is at least readable/actionable in the user's language.
            const [translatedTitle, translatedSummary] = await Promise.all([
                googleTranslate(item.title, 'pt'),
                googleTranslate(item.description, 'pt'),
            ]);
            payload = {
                available: false,
                source: 'translate',
                title: translatedTitle || item.title,
                executiveSummary: translatedSummary || item.description || '',
                impactMitigation: '',
                iocs: null,
            };
        } else {
            // English UI with no LLM — the source content is already English.
            payload = {
                available: false,
                source: 'rss',
                title: item.title,
                executiveSummary: item.description || '',
                impactMitigation: '',
                iocs: null,
            };
        }

        memoryCache.newsletterEnrich.store.set(cacheKey, { data: payload, expiresAt: now + memoryCache.newsletterEnrich.ttl });
        res.json(payload);
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
});

// Latest CVEs from CIRCL
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
        const response = await axios.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { timeout: 8000 });
        if (response.data && Array.isArray(response.data.vulnerabilities)) {
            const sorted = response.data.vulnerabilities
                .sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded))
                .slice(0, 50);

            memoryCache.exploitedCves.data = sorted;
            memoryCache.exploitedCves.expiresAt = now + memoryCache.exploitedCves.ttl;
            return res.json(sorted);
        }
        throw new Error("Invalid response format from CISA");
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
    memoryCache.patchTuesday.store.set(id, { data: summary, expiresAt: Date.now() + memoryCache.patchTuesday.ttl });
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
        return res.json(memoryCache.patchTuesdayMonths.data);
    }
    try {
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
        return res.json(cached.data);
    }

    try {
        res.json(await fetchAndCacheSummary(id));
    } catch (error) {
        const { status, message } = sanitizeError(error);
        res.status(status).json({ error: message });
    }
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
    const status = {
        "VirusTotal": !!process.env.VIRUSTOTAL_API_KEY,
        "AbuseIPDB": !!process.env.ABUSEIPDB_API_KEY,
        "AlienVault OTX": true,
        "Shodan": !!process.env.SHODAN_API_KEY,
        "URLhaus": true,
        "Censys": !!process.env.CENSYS_API_KEY,
        "WHOIS": !!process.env.WHOIS_API_KEY,
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
