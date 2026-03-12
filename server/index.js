import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import axios from 'axios';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config({ path: '../.env' });

// Ensure VITE_ prefixed keys from frontend .env are available to backend
Object.keys(process.env).forEach(key => {
    if (key.startsWith('VITE_')) {
        const standardKey = key.replace('VITE_', '');
        if (!process.env[standardKey]) {
            process.env[standardKey] = process.env[key];
        }
    }
});

const app = express();
const PORT = process.env.PORT || 3001;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 500, // limit each IP to 500 requests per windowMs (increased for progressive loading)
    message: 'Too many requests, please try again later.'
});
app.use('/api/', limiter);

// Helper to detect query type
// Helper to detect query type (Strict Validation)
const detectQueryType = (query) => {
    if (!query) return "unknown";
    const trimmed = query.trim();

    // URL
    if (/^(http|https):\/\/[^ "]+$/.test(trimmed)) return "url";

    // Hash (MD5, SHA1, SHA256)
    if (/^[a-fA-F0-9]{32}$/.test(trimmed)) return "hash";
    if (/^[a-fA-F0-9]{40}$/.test(trimmed)) return "hash";
    if (/^[a-fA-F0-9]{64}$/.test(trimmed)) return "hash";

    // IPv4
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) return "ip";

    // Domain
    if (/^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(trimmed)) return "domain";

    return "unknown";
};

// Security Middleware
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

// Helper to extract quota info
const sendResponseWithQuota = (res, axiosResponse) => {
    const headers = axiosResponse.headers;
    const quota = {};

    // Common rate limit headers
    if (headers['x-ratelimit-remaining']) quota.remaining = headers['x-ratelimit-remaining'];
    if (headers['x-ratelimit-limit']) quota.limit = headers['x-ratelimit-limit'];
    if (headers['x-ratelimit-reset']) quota.reset = headers['x-ratelimit-reset'];

    // Vendor specific headers
    // VirusTotal
    if (headers['x-daily-requests-left']) quota.daily_remaining = headers['x-daily-requests-left'];

    // AbuseIPDB
    if (headers['x-ratelimit-remaining']) quota.remaining = headers['x-ratelimit-remaining'];

    res.json({
        data: axiosResponse.data,
        quota: Object.keys(quota).length > 0 ? quota : undefined
    });
};

// --- API Endpoints ---

// VirusTotal
app.post('/api/virustotal', async (req, res) => {
    const { query } = req.body;
    if (!process.env.VIRUSTOTAL_API_KEY) return res.status(500).json({ error: "API Key missing" });

    try {
        const queryType = detectQueryType(query);
        let endpoint = "";

        if (queryType === "ip") endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${query}`;
        else if (queryType === "domain") endpoint = `https://www.virustotal.com/api/v3/domains/${query}`;
        else if (queryType === "hash") endpoint = `https://www.virustotal.com/api/v3/files/${query}`;
        else endpoint = `https://www.virustotal.com/api/v3/urls/${btoa(query).replace(/=/g, "")}`;

        const response = await axios.get(endpoint, {
            headers: { "x-apikey": process.env.VIRUSTOTAL_API_KEY }
        });
        sendResponseWithQuota(res, response);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// AbuseIPDB
app.post('/api/abuseipdb', async (req, res) => {
    const { query } = req.body;
    if (!process.env.ABUSEIPDB_API_KEY) return res.status(500).json({ error: "API Key missing" });

    const queryType = detectQueryType(query);
    if (queryType !== "ip") return res.json({ data: { "Status": "IP only" } }); // Return 200 with message to match frontend expectation

    try {
        const response = await axios.get(`https://api.abuseipdb.com/api/v2/check`, {
            params: {
                ipAddress: query,
                maxAgeInDays: 90,  // Get reports from last 90 days
                verbose: true      // Include report details
            },
            headers: { "Key": process.env.ABUSEIPDB_API_KEY, "Accept": "application/json" }
        });
        sendResponseWithQuota(res, response);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// AlienVault OTX
app.post('/api/alienvault', async (req, res) => {
    const { query } = req.body;
    const headers = {};
    if (process.env.ALIENVAULT_API_KEY) headers["X-OTX-API-KEY"] = process.env.ALIENVAULT_API_KEY;

    try {
        const queryType = detectQueryType(query);
        let endpoint = "";

        if (queryType === "ip") endpoint = `https://otx.alienvault.com/api/v1/indicators/IPv4/${query}/general`;
        else if (queryType === "domain") endpoint = `https://otx.alienvault.com/api/v1/indicators/domain/${query}/general`;
        else if (queryType === "hash") endpoint = `https://otx.alienvault.com/api/v1/indicators/file/${query}/general`;
        else endpoint = `https://otx.alienvault.com/api/v1/indicators/url/${encodeURIComponent(query)}/general`;

        const response = await axios.get(endpoint, { headers });
        sendResponseWithQuota(res, response);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// Shodan
app.post('/api/shodan', async (req, res) => {
    const { query } = req.body;
    if (!process.env.SHODAN_API_KEY) return res.status(500).json({ error: "API Key missing" });

    const queryType = detectQueryType(query);
    if (queryType !== "ip") return res.json({ data: { "Status": "IP only" } });

    try {
        const response = await axios.get(`https://api.shodan.io/shodan/host/${query}?key=${process.env.SHODAN_API_KEY}`);
        sendResponseWithQuota(res, response);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// URLhaus
app.post('/api/urlhaus', async (req, res) => {
    const { query } = req.body;
    try {
        const response = await axios.post(`https://urlhaus-api.abuse.ch/v1/host/`,
            `host=${query}`,
            { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
        );
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});



// MalwareBazaar
app.post('/api/malwarebazaar', async (req, res) => {
    const { query } = req.body;
    const queryType = detectQueryType(query);
    if (queryType !== "hash") return res.json({ data: { "Status": "Hash only" } });

    try {
        const response = await axios.post(`https://mb-api.abuse.ch/api/v1/`,
            `query=get_info&hash=${query}`,
            { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
        );
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});



// PhishTank
app.post('/api/phishtank', async (req, res) => {
    const { query } = req.body;
    try {
        const body = `url=${encodeURIComponent(query)}&format=json${process.env.PHISHTANK_API_KEY ? `&app_key=${process.env.PHISHTANK_API_KEY}` : ""}`;
        const response = await axios.post(`https://checkurl.phishtank.com/checkurl/`, body, {
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "phishtank/threatsumm4ry"
            }
        });
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// Pulsedive
app.post('/api/pulsedive', async (req, res) => {
    const { query } = req.body;
    const key = process.env.PULSEDIVE_API_KEY || "free";
    try {
        const response = await axios.get(`https://pulsedive.com/api/info.php?indicator=${query}&key=${key}`);
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});











// Hybrid Analysis
app.post('/api/hybridanalysis', async (req, res) => {
    const { query } = req.body;
    if (!process.env.HYBRID_ANALYSIS_API_KEY) return res.status(500).json({ error: "API Key missing" });

    const queryType = detectQueryType(query);
    if (queryType !== "hash") return res.json({ data: { "Status": "Hash only" } });

    try {
        const response = await axios.post(`https://www.hybrid-analysis.com/api/v2/search/hash`,
            `hash=${query}`,
            {
                headers: {
                    "api-key": process.env.HYBRID_ANALYSIS_API_KEY,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            }
        );
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// CIRCL hashlookup
app.post('/api/circl', async (req, res) => {
    const { query } = req.body;
    const queryType = detectQueryType(query);
    if (queryType !== "hash") return res.json({ data: { "Status": "Hash only" } });

    try {
        const response = await axios.get(`https://hashlookup.circl.lu/lookup/${queryType}/${query}`);
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// Criminal IP
app.post('/api/criminalip', async (req, res) => {
    const { query } = req.body;
    if (!process.env.CRIMINALIP_API_KEY) return res.status(500).json({ error: "API Key missing" });

    const queryType = detectQueryType(query);
    if (queryType !== "ip" && queryType !== "domain") return res.json({ data: { "Status": "IP/Domain only" } });

    try {
        const endpoint = queryType === "ip"
            ? `https://api.criminalip.io/v1/ip/data?ip=${query}`
            : `https://api.criminalip.io/v1/domain/reports?query=${query}`;

        const response = await axios.get(endpoint, {
            headers: { "x-api-key": process.env.CRIMINALIP_API_KEY },
        });
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// MetaDefender
app.post('/api/metadefender', async (req, res) => {
    const { query } = req.body;
    if (!process.env.METADEFENDER_API_KEY) return res.status(500).json({ error: "API Key missing" });

    const queryType = detectQueryType(query);
    if (queryType !== "hash" && queryType !== "ip") return res.json({ data: { "Status": "Hash/IP only" } });

    try {
        const endpoint = queryType === "hash"
            ? `https://api.metadefender.com/v4/hash/${query}`
            : `https://api.metadefender.com/v4/ip/${query}`;

        const response = await axios.get(endpoint, {
            headers: { "apikey": process.env.METADEFENDER_API_KEY },
        });
        sendResponseWithQuota(res, response);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// PhishStats
app.post('/api/phishstats', async (req, res) => {
    const { query } = req.body;
    const queryType = detectQueryType(query);
    if (queryType !== "url" && queryType !== "domain") return res.json({ data: { "Status": "URL/Domain only" } });

    try {
        const searchTerm = queryType === "url" ? query : query;
        const response = await axios.get(`https://phishstats.info:2096/api/phishing?_where=(url,like,${encodeURIComponent(searchTerm)})&_sort=-date&_size=5`);
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// Ransomware.live
app.post('/api/ransomwarelive', async (req, res) => {
    const { query } = req.body;
    try {
        const response = await axios.get(`https://api.ransomware.live/recentvictims`);
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// WHOIS
app.post('/api/whois', async (req, res) => {
    const { query } = req.body;
    const queryType = detectQueryType(query);
    if (queryType !== "domain") return res.json({ data: { "Status": "Domain only" } });

    try {
        const response = await axios.get(`https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${process.env.WHOIS_API_KEY}&domainName=${query}&outputFormat=JSON`);
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// IP Geolocation
app.post('/api/ipgeo', async (req, res) => {
    const { query } = req.body;
    const queryType = detectQueryType(query);
    if (queryType !== "ip") return res.json({ data: { "Status": "IP only" } });

    try {
        const response = await axios.get(`http://ip-api.com/json/${query}?fields=status,country,countryCode,regionName,city,isp,org,as,proxy,hosting`);
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});



// Generic DNSBL Endpoint
app.post('/api/dnsbl', async (req, res) => {
    const { query, provider } = req.body;
    const queryType = detectQueryType(query);

    if (queryType !== "ip") {
        return res.json({ listed: false, status: "IP only" });
    }

    if (!provider) {
        return res.status(400).json({ error: "Provider required" });
    }

    try {
        const reversed = query.split('.').reverse().join('.');
        const dnsQuery = `${reversed}.${provider}`;

        const dns = await import('dns');
        dns.promises.resolve4(dnsQuery)
            .then(addresses => {
                res.json({ listed: true, addresses, status: `Listed on ${provider}` });
            })
            .catch(() => {
                res.json({ listed: false, status: "Not listed" });
            });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});



// OpenPhish
app.post('/api/openphish', async (req, res) => {
    const { query } = req.body;
    const queryType = detectQueryType(query);
    if (queryType !== "url" && queryType !== "domain") return res.json({ data: { "Status": "URL/Domain only" } });

    try {
        // OpenPhish provides a feed, we'll check if the URL is in it
        const response = await axios.get('https://openphish.com/feed.txt');
        const urls = response.data.split('\n');
        const found = urls.some(url => url.includes(query));

        res.json({
            listed: found,
            status: found ? "Listed as phishing" : "Not found in OpenPhish feed"
        });
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// DShield (SANS ISC)
app.post('/api/dshield', async (req, res) => {
    const { query } = req.body;
    const queryType = detectQueryType(query);
    if (queryType !== "ip") return res.json({ data: { "Status": "IP only" } });

    try {
        const response = await axios.get(`https://isc.sans.edu/api/ip/${query}?json`);
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// Team Cymru
app.post('/api/teamcymru', async (req, res) => {
    const { query } = req.body;
    const queryType = detectQueryType(query);

    try {
        if (queryType === "ip") {
            // Use Team Cymru's IP to ASN service
            const reversed = query.split('.').reverse().join('.');
            const dnsQuery = `${reversed}.origin.asn.cymru.com`;

            const dns = await import('dns');
            dns.promises.resolveTxt(dnsQuery)
                .then(records => {
                    // Parse response: "ASN | IP | BGP Prefix | CC | Registry | Allocated"
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
            // Team Cymru MHR (Malware Hash Registry)
            const dnsQuery = `${query}.malware.hash.cymru.com`;
            const dns = await import('dns');
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
        res.status(500).json({ error: error.message });
    }
});








// Serve frontend in production
if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.join(__dirname, '../dist')));
    app.get('*', (req, res) => {
        res.sendFile(path.join(__dirname, '../dist/index.html'));
    });
}

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
