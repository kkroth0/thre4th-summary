import { contentHash } from './articleCollector.js';
import { publishNewsSnapshot } from './publishNewsSnapshot.js';

// Each source keeps its own indicators and actor mentions. Never assign the
// union from a multi-source response to every source's actor profile.
export async function persistNewsEvidence(rows, { archive, stories, articleCache, originalFor = () => null, now = new Date() }) {
  for (const row of rows) {
    const old = articleCache.get(row.link);
    const original = originalFor(row);
    const fingerprint = contentHash(row.title + '\n' + (original?.text || original?.description || row.description || ''));
    const text = row.text || '';
    articleCache.set(row.link, { ...old, version: 2, link: row.link, fingerprint, text,
      contentHash: contentHash(text), artifactLinks: row.artifactLinks || [], supplementalIocs: row.iocs,
      attemptedAt: now.toISOString(), collectedAt: now.toISOString(), error: null });
  }
  const correlation = await publishNewsSnapshot(rows, { archive, stories, now });
  return correlation.items;
}
