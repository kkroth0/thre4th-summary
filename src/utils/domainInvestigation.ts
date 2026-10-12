import { detectAnalyzerQueryType } from './iocExtract';
import type { DomainHost } from './networkInvestigation';
import type { PassiveHost } from '@/services/domainIntelligence';

export function investigationDomain(query: string): string | null {
  if (detectAnalyzerQueryType(query) === 'domain') return query.toLowerCase().replace(/\.$/, '');
  if (detectAnalyzerQueryType(query) !== 'url') return null;
  try { const host = new URL(query).hostname.toLowerCase(); return detectAnalyzerQueryType(host) === 'domain' ? host : null; } catch { return null; }
}
export interface ObservedDomainHost extends DomainHost { firstSeen: string | null }
export function mergeDomainHosts(domain: string, observed: DomainHost[], passive: PassiveHost[]): ObservedDomainHost[] {
  const rows = new Map<string, ObservedDomainHost>(observed.map(row => [row.hostname, { ...row, sources: [...row.sources], firstSeen: null }]));
  for (const host of passive) {
    if (host.hostname !== domain && !host.hostname.endsWith(`.${domain}`)) continue;
    const row = rows.get(host.hostname) || { hostname: host.hostname, addresses: [], sources: [], firstSeen: null, lastSeen: null };
    if (!row.sources.includes(host.source)) row.sources.push(host.source);
    if (host.firstSeen && Number.isFinite(Date.parse(host.firstSeen)) && (!row.firstSeen || host.firstSeen < row.firstSeen)) row.firstSeen = host.firstSeen;
    rows.set(host.hostname, row);
  }
  return [...rows.values()].sort((a, b) => a.hostname.localeCompare(b.hostname));
}
export const domainDate = (date: string | null | undefined, pt: boolean) => date && Number.isFinite(Date.parse(date)) ? new Date(date).toLocaleDateString(pt ? 'pt-BR' : 'en-US', { timeZone: 'UTC' }) : '—';
