// Compare JSON evidence by value. SQLite stores canonical object keys, while
// extractors construct the same objects in insertion order. Object order and
// omitted undefined properties are irrelevant; array order remains meaningful.
export function equalJsonEvidence(left, right) {
  if (left === right) return true;
  if (left == null || right == null) return left == null && right == null;
  if (typeof left !== 'object' || typeof right !== 'object') return false;
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
    for (let index = 0; index < left.length; index++) if (!equalJsonEvidence(left[index], right[index])) return false;
    return true;
  }
  const keys = Object.keys(left).filter(key => left[key] !== undefined);
  return keys.length === Object.keys(right).filter(key => right[key] !== undefined).length
    && keys.every(key => Object.hasOwn(right, key) && right[key] !== undefined && equalJsonEvidence(left[key], right[key]));
}

export const canonicalJsonEvidence = value => JSON.stringify(value, (_, item) => item && typeof item === 'object' && !Array.isArray(item)
  ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item);
