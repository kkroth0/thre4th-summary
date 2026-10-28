import { detectAnalyzerQueryType, extractIocsFromText, isPublicIpv4, isPublicIpv6 } from './iocExtract';
import { refang } from './defang';
import type { ThreatIntelligenceResult } from '../types/threat-intelligence';
import type { BulkContext } from '../services/bulkContext';

export const BULK_MAX_BYTES = 3_800_000;
export type BulkState = 'queued' | 'running' | 'complete' | 'partial' | 'error' | 'unsupported' | 'stopped';
export interface BulkRow {
  serverOrdinal?: number;
  serverVersion?: number;
  query: string;
  state: BulkState;
  result?: ThreatIntelligenceResult;
  error?: string;
  completedAt?: string;
  context?: BulkContext;
  contextLoading?: boolean;
}

export function prepareBulkInput(raw: string) {
  let text = refang(raw);
  const urls = extractIocsFromText(text).filter(value => detectAnalyzerQueryType(value) === 'url');
  // Keep URL paths intact before masking email addresses and CIDR blocks.
  text = text.replace(/https?:\/\/[^\s"'<>]+/gi, ' ');
  const excluded = { emails: 0, cidrs: 0, nonPublicIps: 0 };
  const unique = (values: string[]) => new Set(values.map(value => value.toLowerCase())).size;
  const email = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
  const cidr = /(?:\b\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]*:[a-fA-F0-9:]+)\/\d{1,3}\b/g;
  excluded.emails = unique(text.match(email) || []);
  text = text.replace(email, ' ');
  excluded.cidrs = unique(text.match(cidr) || []);
  text = text.replace(cidr, ' ');
  const ipv4 = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || [];
  const ipv6 = text.split(/[\s,"'()\[\]{}|<>]+/).filter(value => /^[a-fA-F0-9:]+$/.test(value) && value.includes(':'));
  excluded.nonPublicIps = unique([
    ...ipv4.filter(value => value.split('.').every(part => Number(part) <= 255) && !isPublicIpv4(value)),
    ...ipv6.filter(value => { try { new URL(`http://[${value}]/`); return !isPublicIpv6(value); } catch { return false; } }),
  ]);
  const indicators = [...new Set([...urls, ...extractIocsFromText(text)].map(value => {
    const type = detectAnalyzerQueryType(value);
    if (type === 'domain' || type === 'hash') return value.toLowerCase();
    if (type === 'ip' && value.includes(':')) return new URL(`http://[${value}]/`).hostname.slice(1, -1);
    return value;
  }))];
  return { indicators, excluded };
}

/** Stops scheduling new requests; in-flight provider lookups are allowed to settle. */
export async function runBulkQueue<T>(items: T[], lookup: (item: T) => Promise<void>, stopped: () => boolean, concurrency = 3) {
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(items.length, Math.max(1, concurrency)) }, async () => {
    while (!stopped() && next < items.length) {
      const item = items[next++];
      await lookup(item);
    }
  }));
}

export function bulkResultState(result: ThreatIntelligenceResult): BulkState {
  if (!result.vendorData.length) return 'unsupported';
  const errors = result.vendorData.filter(vendor => vendor.error).length;
  return errors === result.vendorData.length ? 'error' : errors ? 'partial' : 'complete';
}

export function bulkField(row: BulkRow, keys: string[]) {
  for (const vendor of row.result?.vendorData || []) {
    if (vendor.error || vendor.isLoading) continue;
    for (const key of keys) {
      const value = vendor.data[key];
      if ((typeof value === 'string' || typeof value === 'number') && !['', 'unknown', 'n/a'].includes(String(value).toLowerCase())) return { value: String(value), source: vendor.name };
    }
  }
  return { value: '—', source: '' };
}

const csvCell = (value: unknown) => {
  let text = String(value ?? '');
  if (/^[\s]*[=+@-]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
};
export function bulkCsv(rows: BulkRow[]) {
  const vendors = [...new Set(rows.flatMap(row => row.result?.vendorData.map(vendor => vendor.name) || []))];
  const columns = ['indicator', 'type', 'status', 'verdict', 'detections', 'country', 'asn', 'organization', 'sources', 'failed_sources', 'completed_at', 'publications_json', 'correlated_evidence_json', 'context_errors_json', 'result_json', ...vendors.flatMap(name => [`${name}_status`, `${name}_data_json`, `${name}_raw_json`, `${name}_reference`, `${name}_timeline_json`, `${name}_quota_json`])];
  return [columns, ...rows.map(row => [row.query, detectAnalyzerQueryType(row.query), row.state, row.result?.threatLevel || 'unknown', row.result?.detections ?? '', bulkField(row, ['Country']).value, bulkField(row, ['ASN', 'AS']).value, bulkField(row, ['Organization', 'ISP']).value, row.result?.vendorData.map(vendor => vendor.name).join('; ') || '', row.result?.vendorData.filter(vendor => vendor.error).map(vendor => vendor.name).join('; ') || '', row.completedAt || '', JSON.stringify(row.context?.publications || []), JSON.stringify(row.context?.evidence || []), JSON.stringify(row.context?.errors || []), JSON.stringify(row.result || null), ...vendors.flatMap(name => {
    const vendor = row.result?.vendorData.find(item => item.name === name);
    return vendor ? [vendor.error || (vendor.isLoading ? 'pending' : 'ok'), JSON.stringify(vendor.data), JSON.stringify(vendor.rawPayload ?? null), vendor.link || '', JSON.stringify(vendor.timeline || []), JSON.stringify(vendor.quota || null)] : ['not_queried', '', '', '', '', ''];
  })])].map(row => row.map(csvCell).join(',')).join('\r\n');
}
