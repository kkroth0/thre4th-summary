export interface DomainSource { status: 'available' | 'unavailable'; source: string; error?: string; fetchedAt?: string; truncated?: boolean; total?: number }
export interface PassiveHost { hostname: string; firstSeen: string | null; source: string }
export interface SubdomainResult extends DomainSource { hostname: string; apex: string; hosts: PassiveHost[] }
export interface Certificate { id: string; names: string[]; issuer: string; commonName: string; notBefore: string | null; notAfter: string | null; loggedAt: string | null; serial: string; source: string }
export interface CertificateResult extends DomainSource { certificates: Certificate[] }
export interface DnsChange { hostname: string; firstSeen: string | null; lastSeen: string | null; current: boolean; provider: string; records: Record<string, string[]>; source: string }
export interface DnsHistoryResult extends DomainSource { changes: DnsChange[]; local: DnsChange[]; nextCursor?: string | null; snapshotTime?: string | null; externalUrl: string }
export interface DomainMention { storyId: string; title: string; source: string; link: string; pubDate: string; actors: string[]; matched: string[]; iocs: { ips: string[]; domains: string[]; hashes: string[] } }

export async function domainRequest<T>(path: string, signal: AbortSignal, body?: object): Promise<T> {
  const controller = new AbortController(); const cancel = () => controller.abort();
  if (signal.aborted) cancel(); else signal.addEventListener('abort', cancel, { once: true });
  const timer = setTimeout(cancel, 22_000);
  try {
    const response = await fetch(path, { signal: controller.signal, ...(body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {}) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json() as T;
  } finally { clearTimeout(timer); signal.removeEventListener('abort', cancel); }
}
export async function fetchSubdomains(domain: string, signal: AbortSignal) {
  const data = await domainRequest<SubdomainResult>('/api/domain/subdomains', signal, { query: domain });
  if (!Array.isArray(data.hosts) || !['available', 'unavailable'].includes(data.status)) throw new Error('Invalid subdomain response');
  return data;
}
export async function fetchCertificates(domain: string, signal: AbortSignal) {
  const data = await domainRequest<CertificateResult>('/api/domain/certificates', signal, { query: domain });
  if (!Array.isArray(data.certificates) || !['available', 'unavailable'].includes(data.status)) throw new Error('Invalid certificate response');
  return data;
}
export async function fetchDnsHistory(domain: string, cursor: string, signal: AbortSignal) {
  const data = await domainRequest<DnsHistoryResult>('/api/domain/history', signal, { query: domain, cursor });
  if (!Array.isArray(data.changes) || !Array.isArray(data.local) || !['available', 'unavailable'].includes(data.status)) throw new Error('Invalid history response');
  return data;
}
export async function fetchDomainMentions(domain: string, signal: AbortSignal) {
  const data = await domainRequest<{ mentions: DomainMention[] }>(`/api/news/domain-mentions?domain=${encodeURIComponent(domain)}`, signal);
  if (!Array.isArray(data.mentions)) throw new Error('Invalid mentions response');
  return data.mentions;
}
