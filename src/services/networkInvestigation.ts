import type { AttackSurfaceResponse, DnsLookupResult } from './threatApi';

async function request(path: string, body: object, signal: AbortSignal): Promise<unknown> {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  if (signal.aborted) cancel(); else signal.addEventListener('abort', cancel, { once: true });
  const timer = setTimeout(cancel, 25_000);
  try {
    const response = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: controller.signal });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } finally { clearTimeout(timer); signal.removeEventListener('abort', cancel); }
}

export async function lookupDomain(domain: string, signal: AbortSignal): Promise<DnsLookupResult> {
  const data = await request('/api/dns/lookup', { query: domain }, signal) as DnsLookupResult;
  if (!data?.records || !Array.isArray(data.records.A)) throw new Error('Invalid DNS response');
  return data;
}

export async function lookupCidrShodan(cidr: string, signal: AbortSignal): Promise<AttackSurfaceResponse> {
  const data = await request('/api/attack-surface', { mode: 'guided', targetType: 'cidr', target: cidr, limit: 100, activeValidation: false }, signal) as AttackSurfaceResponse;
  if (!Array.isArray(data?.findings) || !data.summary) throw new Error('Invalid Shodan response');
  return data;
}

export interface AbuseBlock {
  reportedAddress: { ipAddress: string; abuseConfidenceScore?: number; numReports?: number; mostRecentReport?: string; countryCode?: string }[];
  numReports?: number;
}
export async function lookupCidrAbuse(cidr: string, signal: AbortSignal): Promise<AbuseBlock> {
  const raw = await request('/api/abuseipdb/check-block', { query: cidr }, signal) as { data?: { data?: AbuseBlock } & Partial<AbuseBlock> };
  const data = raw?.data?.data || raw?.data;
  if (!Array.isArray(data?.reportedAddress)) throw new Error('Invalid AbuseIPDB response');
  return data as AbuseBlock;
}
