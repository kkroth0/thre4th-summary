import net from 'net';

const MAX_LIMIT = 100;
const DEFAULT_LIMIT = 50;
const MAX_TEXT = 512;
const TCP_TIMEOUT_MS = 3000;
const TCP_CONCURRENCY = 5;
const CONTROL_CHARS = /[\x00-\x1F\x7F]/;
const SAFE_DOMAIN_REGEX = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const SAFE_CIDR_REGEX = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

const CRITICAL_PORTS = new Map([
  [23, 'Telnet exposed'],
  [445, 'SMB exposed'],
  [3389, 'RDP exposed'],
]);

const HIGH_PORTS = new Map([
  [21, 'FTP exposed'],
  [22, 'SSH exposed'],
  [1433, 'MSSQL exposed'],
  [3306, 'MySQL exposed'],
  [5900, 'VNC exposed'],
]);

const MEDIUM_PORTS = new Map([
  [25, 'SMTP exposed'],
  [8000, 'Alternative HTTP port exposed'],
  [8080, 'Alternative HTTP port exposed'],
  [8443, 'Alternative HTTPS port exposed'],
]);

const STANDARD_WEB_PORTS = new Set([80, 443]);
const ADMIN_PATTERN = /(admin|login|management|router|camera|printer|dashboard)/i;
const RISK_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

const createPublicError = (status, publicMessage) => {
  const error = new Error(publicMessage);
  error.status = status;
  error.publicMessage = publicMessage;
  return error;
};

export const clampLimit = (value) => {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_LIMIT;
  return Math.min(parsed, MAX_LIMIT);
};

const cleanText = (value, max = MAX_TEXT) => {
  if (value === undefined || value === null) return '';
  return String(value).replace(CONTROL_CHARS, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
};

const cleanNullable = (value, max = MAX_TEXT) => {
  const cleaned = cleanText(value, max);
  return cleaned || null;
};

const validateTextQuery = (value, label, max = MAX_TEXT) => {
  const cleaned = cleanText(value, max);
  if (!cleaned) throw createPublicError(400, `${label} is required`);
  if (CONTROL_CHARS.test(String(value))) throw createPublicError(400, `${label} contains invalid characters`);
  if (String(value).trim().length > max) throw createPublicError(400, `${label} is too long`);
  return cleaned;
};

const isValidIPv4 = (ip) => {
  if (typeof ip !== 'string' || net.isIP(ip) !== 4) return false;
  return ip.split('.').every((octet) => {
    const value = Number(octet);
    return Number.isInteger(value) && value >= 0 && value <= 255;
  });
};

export const isPublicIPv4 = (ip) => {
  if (!isValidIPv4(ip)) return false;
  const [a, b, c] = ip.split('.').map(Number);
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;
  if (a === 192 && b === 88 && c === 99) return false;
  if (a === 192 && b === 168) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  if (a >= 224) return false;
  return true;
};

const validateCidr = (cidr) => {
  const value = validateTextQuery(cidr, 'CIDR', 64);
  if (!SAFE_CIDR_REGEX.test(value)) throw createPublicError(400, 'Invalid CIDR format');
  const [ip, maskValue] = value.split('/');
  const mask = Number(maskValue);
  if (!isValidIPv4(ip) || !Number.isInteger(mask) || mask < 0 || mask > 32) {
    throw createPublicError(400, 'Invalid CIDR format');
  }
  return value;
};

const validateDomain = (domain) => {
  const value = validateTextQuery(domain, 'Domain', 253).toLowerCase();
  if (!SAFE_DOMAIN_REGEX.test(value)) throw createPublicError(400, 'Invalid domain format');
  return value;
};

const shodanQuoted = (value) => validateTextQuery(value, 'Target', 160).replace(/\\/g, '\\\\').replace(/"/g, '\\"');

export const buildAttackSurfaceQuery = (input = {}) => {
  const limit = clampLimit(input.limit);
  const mode = cleanText(input.mode, 16);
  if (mode !== 'guided' && mode !== 'advanced') throw createPublicError(400, 'Invalid mode');

  if (mode === 'advanced') {
    const query = validateTextQuery(input.advancedQuery, 'Advanced query', MAX_TEXT);
    return { kind: 'search', query, limit };
  }

  const targetType = input.targetType;
  const target = input.target;

  switch (targetType) {
    case 'ip': {
      const ip = validateTextQuery(target, 'IP', 64);
      if (!isValidIPv4(ip)) throw createPublicError(400, 'Invalid IP format');
      return { kind: 'host', ip, limit };
    }
    case 'cidr':
      return { kind: 'search', query: `net:"${validateCidr(target)}"`, limit };
    case 'domain':
      return { kind: 'search', query: `hostname:"${validateDomain(target)}"`, limit };
    case 'org':
      return { kind: 'search', query: `org:"${shodanQuoted(target)}"`, limit };
    default:
      throw createPublicError(400, 'Invalid guided target type');
  }
};

const uniqueStrings = (values) => Array.from(new Set((values || []).filter(Boolean).map(String)));

const vulnsToList = (...sources) => uniqueStrings(
  sources.flatMap((source) => {
    if (!source) return [];
    if (Array.isArray(source)) return source;
    if (typeof source === 'object') return Object.keys(source);
    return [];
  }),
);

const riskResult = (risk, riskScore, riskReasons) => ({ risk, riskScore, riskReasons });

export const assessExposureRisk = (service = {}) => {
  const port = Number(service.port);
  const transport = cleanText(service.transport || 'tcp', 12).toLowerCase();
  const cves = uniqueStrings(service.cves);
  const reasons = [];

  if (cves.length > 0) {
    reasons.push(`Known vulnerabilities reported: ${cves.slice(0, 5).join(', ')}`);
    return riskResult('critical', 95, reasons);
  }

  if (transport === 'tcp' && CRITICAL_PORTS.has(port)) {
    reasons.push(CRITICAL_PORTS.get(port));
    return riskResult('critical', 90, reasons);
  }

  const haystack = [
    service.product,
    service.service,
    service.httpTitle,
    service.httpServer,
    service.bannerSnippet,
    ...(Array.isArray(service.tags) ? service.tags : []),
  ].filter(Boolean).join(' ');

  if (transport === 'tcp' && HIGH_PORTS.has(port)) {
    reasons.push(HIGH_PORTS.get(port));
    return riskResult('high', 75, reasons);
  }

  if (transport === 'tcp' && ADMIN_PATTERN.test(haystack)) {
    reasons.push('Admin-like web service exposed');
    return riskResult('high', 72, reasons);
  }

  if (transport === 'tcp' && MEDIUM_PORTS.has(port)) {
    reasons.push(MEDIUM_PORTS.get(port));
    return riskResult('medium', 50, reasons);
  }

  if (transport === 'tcp' && STANDARD_WEB_PORTS.has(port)) {
    reasons.push('Standard web service exposed');
    return riskResult('low', 25, reasons);
  }

  reasons.push('Service has no high-risk rule match');
  return riskResult('low', 20, reasons);
};

const parseDate = (value) => {
  if (!value) return null;
  const text = String(value);
  const normalized = text.includes('T') ? text : `${text}T00:00:00Z`;
  const date = new Date(normalized.endsWith('Z') ? normalized : normalized.replace(/\.(\d{3})\d+/, '.$1'));
  if (Number.isNaN(date.getTime())) return text;
  return date.toISOString();
};

const bannerSnippet = (value) => {
  const cleaned = cleanText(value, 260);
  return cleaned || null;
};

const serviceName = (entry) => cleanNullable(entry.product || entry._shodan?.module || entry.transport || null, 120);

const baseFindingFromEntry = (host, entry, index) => {
  const ip = cleanText(entry.ip_str || host.ip_str || host.ip || '');
  const port = Number(entry.port || host.port || 0);
  const transport = cleanText(entry.transport || host.transport || 'tcp', 12).toLowerCase() === 'udp' ? 'udp' : 'tcp';
  const cves = vulnsToList(entry.vulns, host.vulns);
  const tags = uniqueStrings([...(entry.tags || []), ...(host.tags || [])]);
  const hostnames = uniqueStrings([...(entry.hostnames || []), ...(host.hostnames || [])]).slice(0, 10);
  const product = cleanNullable(entry.product || entry._shodan?.module || null, 120);
  const service = serviceName(entry);
  const version = cleanNullable(entry.version, 80);
  const httpTitle = cleanNullable(entry.http?.title, 160);
  const httpServer = cleanNullable(entry.http?.server, 120);
  const banner = bannerSnippet(entry.data || host.data);
  const risk = assessExposureRisk({
    port,
    transport,
    cves,
    tags,
    product,
    service,
    version,
    httpTitle,
    httpServer,
    bannerSnippet: banner,
  });

  return {
    id: `${ip}:${port}/${transport}:${index}`,
    ip,
    port,
    transport,
    ...risk,
    service,
    product,
    version,
    organization: cleanNullable(entry.org || host.org, 160),
    asn: cleanNullable(entry.asn || host.asn, 80),
    hostnames,
    country: cleanNullable(entry.location?.country_name || entry.country_name || host.location?.country_name || host.country_name, 120),
    city: cleanNullable(entry.location?.city || entry.city || host.location?.city || host.city, 120),
    source: { shodan: true, censys: false },
    observedAt: parseDate(entry.timestamp || host.last_update || host.timestamp),
    cves,
    tags,
    bannerSnippet: banner,
    validation: {
      attempted: false,
      status: 'not_requested',
      detail: null,
    },
  };
};

export const normalizeShodanHost = (host = {}) => {
  const entries = Array.isArray(host.data) && host.data.some((entry) => entry && entry.port)
    ? host.data
    : [host];

  return entries
    .map((entry, index) => baseFindingFromEntry(host, entry || {}, index))
    .filter((finding) => finding.ip && finding.port > 0);
};

const mergeCensysResource = (findings, ip, resource) => {
  const services = Array.isArray(resource?.services) ? resource.services : [];
  if (services.length === 0) return findings;

  const serviceMap = new Map(services.map((service) => [`${Number(service.port)}/${String(service.transport || 'tcp').toLowerCase()}`, service]));

  return findings.map((finding) => {
    if (finding.ip !== ip) return finding;
    const service = serviceMap.get(`${finding.port}/${finding.transport}`);
    if (!service) return finding;

    const cves = uniqueStrings([...finding.cves, ...(Array.isArray(service.vulnerabilities) ? service.vulnerabilities : [])]);
    const tags = uniqueStrings([...finding.tags, ...(Array.isArray(service.labels) ? service.labels : [])]);
    const merged = {
      ...finding,
      source: { ...finding.source, censys: true },
      product: finding.product || cleanNullable(service.software, 120),
      version: finding.version || cleanNullable(service.software_version, 80),
      service: finding.service || cleanNullable(service.protocol || service.transport, 120),
      cves,
      tags,
      bannerSnippet: finding.bannerSnippet || bannerSnippet(service.http_title || service.http_server),
    };
    const risk = assessExposureRisk({
      port: merged.port,
      transport: merged.transport,
      cves: merged.cves,
      tags: merged.tags,
      product: merged.product,
      service: merged.service,
      httpTitle: service.http_title,
      httpServer: service.http_server,
      bannerSnippet: merged.bannerSnippet,
    });
    return { ...merged, ...risk };
  });
};

const defaultTcpConnect = (ip, port, timeoutMs = TCP_TIMEOUT_MS) => new Promise((resolve) => {
  const socket = new net.Socket();
  let settled = false;

  const finish = (status, detail) => {
    if (settled) return;
    settled = true;
    socket.destroy();
    resolve({ status, detail });
  };

  socket.setTimeout(timeoutMs);
  socket.once('connect', () => finish('open', 'TCP connection accepted'));
  socket.once('timeout', () => finish('timeout', 'TCP connection timed out'));
  socket.once('error', (error) => {
    const code = error?.code || 'ERROR';
    if (code === 'ECONNREFUSED') finish('closed', 'TCP connection refused');
    else if (code === 'ETIMEDOUT') finish('timeout', 'TCP connection timed out');
    else finish('error', `TCP validation failed: ${code}`);
  });
  socket.connect(port, ip);
});

const mapWithConcurrency = async (items, limit, worker) => {
  const output = new Array(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      output[index] = await worker(items[index], index);
    }
  });
  await Promise.all(workers);
  return output;
};

const applyActiveValidation = async (findings, tcpConnect = defaultTcpConnect) => mapWithConcurrency(
  findings,
  TCP_CONCURRENCY,
  async (finding) => {
    if (finding.transport !== 'tcp') {
      return {
        ...finding,
        validation: { attempted: false, status: 'udp_not_supported', detail: 'UDP service - TCP validation not supported' },
      };
    }
    if (!isPublicIPv4(finding.ip)) {
      return {
        ...finding,
        validation: { attempted: false, status: 'error', detail: 'Active validation requires a public IPv4 address' },
      };
    }

    try {
      const result = await tcpConnect(finding.ip, finding.port, TCP_TIMEOUT_MS);
      return {
        ...finding,
        validation: {
          attempted: true,
          status: result.status || 'error',
          detail: result.detail || null,
        },
      };
    } catch (error) {
      return {
        ...finding,
        validation: {
          attempted: true,
          status: 'error',
          detail: error?.message || 'TCP validation failed',
        },
      };
    }
  },
);

const summarize = (findings, warnings, providers, totalObserved) => {
  const assetSet = new Set(findings.map((finding) => finding.ip));
  const byRisk = findings.reduce((acc, finding) => {
    acc[finding.risk] = (acc[finding.risk] || 0) + 1;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0 });

  return {
    totalAssets: assetSet.size,
    totalServices: findings.length,
    criticalHighFindings: byRisk.critical + byRisk.high,
    activelyConfirmedOpen: findings.filter((finding) => finding.validation.status === 'open').length,
    byRisk,
    providers,
    warnings,
    totalObserved,
  };
};

const sortFindings = (findings) => [...findings].sort((a, b) => {
  const riskDelta = RISK_ORDER[b.risk] - RISK_ORDER[a.risk];
  if (riskDelta !== 0) return riskDelta;
  const scoreDelta = b.riskScore - a.riskScore;
  if (scoreDelta !== 0) return scoreDelta;
  const ipDelta = a.ip.localeCompare(b.ip);
  if (ipDelta !== 0) return ipDelta;
  return a.port - b.port;
});

export const runAttackSurfaceScan = async (input = {}, deps = {}) => {
  const {
    axiosClient,
    shodanApiKey,
    censysApiKey,
    tcpConnect,
  } = deps;

  if (!axiosClient?.get) throw createPublicError(500, 'HTTP client unavailable');
  if (!shodanApiKey) throw createPublicError(503, 'Shodan API key missing');

  const queryPlan = buildAttackSurfaceQuery(input);
  let shodanResponse;

  if (queryPlan.kind === 'host') {
    shodanResponse = await axiosClient.get(`https://api.shodan.io/shodan/host/${queryPlan.ip}`, {
      params: { key: shodanApiKey },
      timeout: 15000,
    });
  } else {
    shodanResponse = await axiosClient.get('https://api.shodan.io/shodan/host/search', {
      params: { key: shodanApiKey, query: queryPlan.query, limit: queryPlan.limit },
      timeout: 15000,
    });
  }

  const shodanData = shodanResponse?.data || {};
  let findings = queryPlan.kind === 'host'
    ? normalizeShodanHost(shodanData)
    : (Array.isArray(shodanData.matches) ? shodanData.matches.flatMap((match) => normalizeShodanHost(match)) : []);
  findings = findings.slice(0, queryPlan.limit);

  const warnings = [];
  const providers = { shodan: true, censys: false };

  if (censysApiKey && findings.length > 0) {
    const ips = Array.from(new Set(findings.map((finding) => finding.ip).filter(isPublicIPv4))).slice(0, 25);
    await Promise.all(ips.map(async (ip) => {
      try {
        const response = await axiosClient.get(`https://api.platform.censys.io/v3/global/asset/host/${ip}`, {
          headers: {
            Authorization: `Bearer ${censysApiKey}`,
            Accept: 'application/json',
          },
          timeout: 10000,
        });
        const resource = response?.data?.result?.resource;
        if (resource) {
          providers.censys = true;
          findings = mergeCensysResource(findings, ip, resource);
        }
      } catch (error) {
        warnings.push(`Censys enrichment failed for ${ip}: ${error?.message || 'request failed'}`);
      }
    }));
  }

  if (input.activeValidation === true) {
    findings = await applyActiveValidation(findings, tcpConnect || defaultTcpConnect);
  }

  findings = sortFindings(findings).map((finding, index) => ({
    ...finding,
    id: `${finding.ip}:${finding.port}/${finding.transport}:${index}`,
  }));

  return {
    generatedAt: new Date().toISOString(),
    query: queryPlan.kind === 'host' ? queryPlan.ip : queryPlan.query,
    queryKind: queryPlan.kind,
    limit: queryPlan.limit,
    activeValidation: input.activeValidation === true,
    summary: summarize(findings, warnings, providers, shodanData.total ?? findings.length),
    findings,
    warnings,
  };
};
