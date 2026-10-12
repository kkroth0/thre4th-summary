import { extractIocsFromText, isPublicIpv4, isSupportedAnalyzerQuery } from './iocExtract';
import type { VendorData } from '@/types/threat-intelligence';
import type { AttackSurfaceFinding } from '@/services/threatApi';
import type { AbuseBlock } from '@/services/networkInvestigation';

export const ipv4Number = (ip: string) => ip.split('.').reduce((value, octet) => value * 256 + Number(octet), 0);
export const ipv4Address = (value: number) => [24, 16, 8, 0].map(shift => Math.floor(value / 2 ** shift) % 256).join('.');
export interface CidrRange { cidr: string; prefix: number; start: number; end: number; first: string; last: string; size: number }

export function parsePublicCidr(value: string): CidrRange | null {
  const match = value.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (!match || !isPublicIpv4(match[1]) || Number(match[2]) > 32) return null;
  const prefix = Number(match[2]); const size = 2 ** (32 - prefix);
  const start = Math.floor(ipv4Number(match[1]) / size) * size; const end = start + size - 1;
  const reserved = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/3'];
  if (reserved.some(block => {
    const [ip, bits] = block.split('/'); const lower = ipv4Number(ip); const upper = lower + 2 ** (32 - Number(bits)) - 1;
    return start <= upper && end >= lower;
  }) && !(size === 1 && ['192.0.0.9', '192.0.0.10'].includes(ipv4Address(start)))) return null;
  return { cidr: `${ipv4Address(start)}/${prefix}`, prefix, start, end, first: ipv4Address(start), last: ipv4Address(end), size };
}

export const isEnrichmentTarget = (value: string) => Boolean(parsePublicCidr(value)) || isSupportedAnalyzerQuery(value);

export function extractEnrichmentTargets(text: string): string[] {
  const urls = (text.match(/https?:\/\/[^\s"'<>]+/gi) || []).map(value => value.replace(/[),.;\]]+$/g, ''));
  const blocks: string[] = [];
  const remaining = text.replace(/https?:\/\/[^\s"'<>]+/gi, ' ').replace(/(?<![\w:/])\d{1,3}(?:\.\d{1,3}){3}\/[a-zA-Z0-9]+(?![\w/])/g, block => {
    blocks.push(parsePublicCidr(block)?.cidr || block); return ' ';
  });
  return [...new Set([...blocks, ...extractIocsFromText(remaining), ...urls])];
}

export interface NetworkObservation {
  ip: string; ports: number[]; hostnames: string[]; cves: string[]; sources: string[];
  organizations: string[]; asns: string[]; country: string; lastSeen: string | null;
  abuseScore: number | null; reports: number | null;
}

export function networkObservations(range: CidrRange, findings: AttackSurfaceFinding[] = [], abuse?: AbuseBlock): NetworkObservation[] {
  const rows = new Map<string, NetworkObservation>();
  const get = (ip: string) => {
    const value = ipv4Number(ip);
    if (!isPublicIpv4(ip) || value < range.start || value > range.end) return null;
    if (!rows.has(ip)) rows.set(ip, { ip, ports: [], hostnames: [], cves: [], sources: [], organizations: [], asns: [], country: '', lastSeen: null, abuseScore: null, reports: null });
    return rows.get(ip)!;
  };
  const add = (items: string[], values: string[]) => values.filter(Boolean).forEach(value => { if (!items.includes(value)) items.push(value); });
  const date = (row: NetworkObservation, value?: string | null) => { if (value && Number.isFinite(Date.parse(value)) && (!row.lastSeen || Date.parse(value) > Date.parse(row.lastSeen))) row.lastSeen = value; };
  for (const finding of findings) {
    const row = get(finding.ip); if (!row) continue;
    if (!row.ports.includes(finding.port)) row.ports.push(finding.port);
    add(row.hostnames, finding.hostnames || []); add(row.cves, finding.cves || []);
    add(row.organizations, finding.organization ? [finding.organization] : []); add(row.asns, finding.asn ? [finding.asn] : []);
    add(row.sources, ['Shodan']); row.country ||= finding.country || ''; date(row, finding.observedAt);
  }
  for (const finding of abuse?.reportedAddress || []) {
    const row = get(finding.ipAddress); if (!row) continue;
    row.abuseScore = Number.isFinite(finding.abuseConfidenceScore) ? finding.abuseConfidenceScore! : null;
    row.reports = Number.isFinite(finding.numReports) ? finding.numReports! : null;
    row.country ||= finding.countryCode || ''; add(row.sources, ['AbuseIPDB']); date(row, finding.mostRecentReport);
  }
  return [...rows.values()].sort((a, b) => ipv4Number(a.ip) - ipv4Number(b.ip));
}

export function cidrTilePage(range: CidrRange, observations: NetworkObservation[], page: number, size: number, observedOnly: boolean) {
  const prefix = Math.max(24, range.prefix); const step = 2 ** (32 - prefix);
  const observed = new Map<number, NetworkObservation[]>();
  for (const row of observations) {
    const address = ipv4Number(row.ip); if (!isPublicIpv4(row.ip) || address < range.start || address > range.end) continue;
    const index = Math.floor((address - range.start) / step);
    observed.set(index, [...(observed.get(index) || []), row]);
  }
  const indexes = [...observed.keys()].sort((a, b) => a - b);
  const total = observedOnly ? indexes.length : range.size / step;
  const current = Math.min(page, Math.max(1, Math.ceil(total / size)));
  const offset = (current - 1) * size;
  const tiles = Array.from({ length: Math.max(0, Math.min(size, total - offset)) }, (_, i) => {
    const index = observedOnly ? indexes[offset + i] : offset + i;
    const rows = observed.get(index) || [];
    return { cidr: `${ipv4Address(range.start + index * step)}/${prefix}`, rows, size: step,
      reported: rows.filter(row => (row.reports || 0) > 0).length,
      vulnerable: rows.filter(row => row.cves.length > 0).length };
  });
  return { tiles, total, current, observedBlocks: indexes.length };
}

export interface DomainHost { hostname: string; addresses: string[]; sources: string[]; lastSeen: string | null }
export function domainHosts(domain: string, vendors: VendorData[], records?: Record<string, string[]>): DomainHost[] {
  const rows = new Map<string, DomainHost>(); const root = domain.toLowerCase();
  const add = (name: string, address: string | null, source: string, lastSeen: string | null = null) => {
    name = name.toLowerCase();
    const hostname = name === '@' || !name ? root : name.endsWith(`.${root}`) || name === root ? name : `${name}.${root}`;
    if (!isSupportedAnalyzerQuery(hostname) || !(hostname === root || hostname.endsWith(`.${root}`))) return;
    const row = rows.get(hostname) || { hostname, addresses: [], sources: [], lastSeen: null };
    if (address && !row.addresses.includes(address)) row.addresses.push(address);
    if (!row.sources.includes(source)) row.sources.push(source);
    if (lastSeen && Number.isFinite(Date.parse(lastSeen)) && (!row.lastSeen || Date.parse(lastSeen) > Date.parse(row.lastSeen))) row.lastSeen = lastSeen;
    rows.set(hostname, row);
  };
  for (const address of [...(records?.A || []), ...(records?.AAAA || [])]) add(root, address, 'DNS');
  for (const vendor of vendors.filter(item => !item.error && !item.isLoading)) {
    if (vendor.name !== 'Shodan') continue;
    const names = vendor.data['Subdomain List'];
    if (Array.isArray(names)) names.forEach(name => { if (typeof name === 'string') add(name, null, 'Shodan'); });
    const dns = vendor.data['DNS Records'];
    if (Array.isArray(dns)) dns.forEach(record => {
      if (record && typeof record.subdomain === 'string') add(record.subdomain, ['A', 'AAAA'].includes(record.type) ? String(record.value) : null, 'Shodan', record.last_seen || null);
    });
  }
  return [...rows.values()].sort((a, b) => a.hostname.localeCompare(b.hostname));
}
