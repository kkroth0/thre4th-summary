import { createHash } from 'node:crypto';
import { compareNewsSources, STORY_ACTIVE_DAYS } from './newsStories.js';

export const semanticTextHash = row => createHash('sha256').update([row.title, row.description || row.text].filter(Boolean).join('\n').slice(0, 16000)).digest('hex');
const values = rows => (rows || []).map(row => typeof row === 'string' ? row : row?.id).filter(Boolean);
const shared = (a, b) => [...new Set(values(a))].filter(value => values(b).includes(value));
const metrics = rows => {
  const tp = rows.filter(row => row.actual && row.expected).length, fp = rows.filter(row => row.actual && !row.expected).length;
  const fn = rows.filter(row => !row.actual && row.expected).length, tn = rows.length - tp - fp - fn;
  return { pairs: rows.length, truePositive: tp, falsePositive: fp, falseNegative: fn, trueNegative: tn, precision: tp + fp ? tp / (tp + fp) : null, recall: tp + fn ? tp / (tp + fn) : null };
};

// Offline only. Vectors must be produced separately with a pinned local model;
// there is no network/model download and no production merge hook here.
export function auditSemanticCorrelation(items, embeddings, { threshold = 0.9, model } = {}) {
  if (!Array.isArray(items) || items.length > 500) throw Error('Provide at most 500 reviewed publications');
  if (!model?.id || !model.revision || !Number.isInteger(model.dimensions) || model.dimensions < 8 || model.dimensions > 4096) throw Error('A pinned model id, revision and dimensions are required');
  if (!(threshold > 0 && threshold <= 1)) throw Error('Invalid cosine threshold');
  const labelled = items.filter(row => typeof row.expectedEvent === 'string' && row.expectedEvent);
  if (new Set(labelled.map(row => row.link)).size !== labelled.length || labelled.some(row => !row.link)) throw Error('Reviewed publication URLs must be unique');
  const embeddingsByLink = new Map((embeddings || []).map(row => [row.link, row]));
  const prepare = row => {
    const embedding = embeddingsByLink.get(row.link);
    if (embedding?.model !== model.id || embedding.revision !== model.revision || embedding.textHash !== semanticTextHash(row) || !Array.isArray(embedding.vector) || embedding.vector.length !== model.dimensions || !embedding.vector.every(Number.isFinite) || !embedding.vector.some(value => value !== 0)) return null;
    const norm = Math.hypot(...embedding.vector);
    return Number.isFinite(norm) && norm > 0 ? embedding.vector.map(value => value / norm) : null;
  };
  const prepared = new Map(labelled.map(row => [row, prepare(row)]));
  const valid = row => prepared.get(row);
  const results = [];
  for (let i = 0; i < labelled.length; i++) for (let j = i + 1; j < labelled.length; j++) {
    const left = labelled[i], right = labelled[j], baseline = compareNewsSources(left, right).sameEvent;
    const a = valid(left), b = valid(right);
    const languageKnown = ['pt', 'en'].includes(left.language) && ['pt', 'en'].includes(right.language);
    const crossLanguage = languageKnown && left.language !== right.language;
    const gap = Math.abs(Date.parse(left.pubDate) - Date.parse(right.pubDate));
    const hashes = shared(left.iocs?.hashes, right.iocs?.hashes);
    const campaigns = shared(left.campaigns, right.campaigns);
    const assets = shared((left.assets || []).map(row => `${row.vendor || ''}:${row.product || ''}`), (right.assets || []).map(row => `${row.vendor || ''}:${row.product || ''}`)).filter(value => value !== ':');
    const anchors = hashes.length > 0 || campaigns.length > 0 || shared(left.cves, right.cves).length > 0 && assets.length > 0;
    const roundup = /\b(?:roundup|digest|weekly|monthly|semanal|mensal|boletim|top \d+)\b/i.test(left.title + '\n' + right.title);
    let cosine = null;
    if (a && b) {
      const dot = a.reduce((sum, value, index) => sum + value * b[index], 0);
      cosine = dot;
      if (!Number.isFinite(cosine)) cosine = null;
    }
    const candidate = !!(crossLanguage && !roundup && anchors && Number.isFinite(gap) && gap <= STORY_ACTIVE_DAYS * 86400000 && cosine !== null && cosine >= threshold);
    results.push({ links: [left.link, right.link], expected: left.expectedEvent === right.expectedEvent, baseline, candidate, cosine, languageKnown, crossLanguage, validEmbeddings: !!(a && b), hasIndependentAnchors: anchors });
  }
  const crossLanguage = results.filter(row => row.crossLanguage);
  return { mode: 'offline-evaluation', automaticMergingEnabled: false, model, threshold,
    labelledPublications: labelled.length, publicationsWithoutLanguage: labelled.filter(row => !['pt', 'en'].includes(row.language)).length,
    publicationsWithValidEmbedding: labelled.filter(row => valid(row)).length,
    baseline: metrics(results.map(row => ({expected: row.expected, actual: row.baseline}))),
    proposed: metrics(results.map(row => ({expected: row.expected, actual: row.baseline || row.candidate}))),
    crossLanguage: { baseline: metrics(crossLanguage.map(row => ({expected: row.expected, actual: row.baseline}))), proposed: metrics(crossLanguage.map(row => ({expected: row.expected, actual: row.baseline || row.candidate}))) },
    introducedFalseUnions: results.filter(row => row.candidate && !row.baseline && !row.expected).length,
    decision: 'review-labelled-pt-en-sample-and-model-before-production', results,
  };
}
