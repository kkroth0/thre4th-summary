import type { ThreatIntelligenceResult } from '../types/threat-intelligence';
/** Retry only transient source failures; permanent authentication failures need settings. */
export function bulkRetryAt(result: ThreatIntelligenceResult, attempts: Map<string, number>, now = Date.now()) {
  const pending: number[] = [];
  for (const vendor of result.vendorData) {
    const key = JSON.stringify([result.query, vendor.name]);
    if (!vendor.error) { attempts.delete(key); continue; }
    if (vendor.errorCode === 'PROVIDER_AUTH_FAILED') continue;
    if (vendor.httpStatus === 429) { pending.push(Math.max(now + 1000, vendor.retryAt || now + 60000)); continue; }
    if (vendor.httpStatus === 0 || [502, 503, 504].includes(vendor.httpStatus)) {
      const count = (attempts.get(key) || 0) + 1; attempts.set(key, count);
      if (count < 3) pending.push(Math.max(vendor.retryAt || 0, now + 30000 * count));
    }
  }
  return pending.length ? Math.min(...pending) : null;
}
