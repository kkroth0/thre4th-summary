import { domainTarget } from './domainIntelligence.js';
import { normalizeBrandTerm } from './phishingWatch.js';
import { similarDomainCandidates } from './similarDomains.js';

export function candidateBrandMatch(hostname, brands) {
  let target; try { target = domainTarget(hostname).hostname; } catch { return false; }
  return brands.some(brand => {
    const term = normalizeBrandTerm(brand); if (!term) return false;
    if (target.includes(term)) return true;
    try { return similarDomainCandidates(brand).candidates.some(row => row.domain === target); } catch { return false; }
  });
}
const utc = value => { const text = String(value || ''); const at = Date.parse(text && !/(Z|[+-]\d\d:\d\d)$/.test(text) ? text + 'Z' : text); return Number.isFinite(at) ? at : null; };

// Offline evaluation: certificate observation is an opportunity, not proof of
// maliciousness or the date a campaign started. No issued-date fallback.
export function evaluateCtBacktest(samples, { brands = [] } = {}) {
  const seen = new Set(), results = [];
  for (const sample of samples) {
    let hostname; try { hostname = domainTarget(sample.hostname).hostname; } catch { continue; }
    const key = `${sample.cohort}:${hostname}`; if (seen.has(key)) continue; seen.add(key);
    const reference = utc(sample.firstSeen), matched = candidateBrandMatch(hostname, brands);
    const certificates = (Array.isArray(sample.certificates) ? sample.certificates : []).filter(cert =>
      String(cert.name_value || '').toLowerCase().split(/\s+/).includes(hostname) && utc(cert.entry_timestamp) !== null && reference !== null && utc(cert.entry_timestamp) <= reference
    ).sort((a, b) => utc(b.entry_timestamp) - utc(a.entry_timestamp));
    const certificate = certificates[0];
    results.push({ hostname, cohort: sample.cohort, label: sample.label, matched, certificateId: certificate?.id || null,
      observedAt: certificate ? new Date(utc(certificate.entry_timestamp)).toISOString() : null,
      opportunityHours: matched && certificate ? (reference - utc(certificate.entry_timestamp)) / 3600000 : null,
      status: sample.lookupFailed ? 'lookup_failed' : reference === null ? 'missing_reference' : certificate ? 'observation_proxy' : 'no_prior_exact_certificate' });
  }
  const positive = results.filter(row => row.label === 'malicious'), negative = results.filter(row => row.label === 'legitimate');
  const tp = positive.filter(row => row.matched).length, fp = negative.filter(row => row.matched).length;
  return { mode: 'retrospective-opportunity', sampleCount: results.length, maliciousSamples: positive.length, legitimateSamples: negative.length,
    candidateRecall: positive.length ? tp / positive.length : null, falsePositiveRate: negative.length ? fp / negative.length : null,
    // A curated case/control sample does not estimate deployment precision.
    precision: null, prospectiveValidationRequired: true, results };
}
