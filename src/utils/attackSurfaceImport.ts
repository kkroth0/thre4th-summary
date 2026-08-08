export type AttackSurfaceImportedKind = "ip" | "cidr" | "domain" | "asn" | "shodan_query";

export interface AttackSurfaceImportedTarget {
  kind: AttackSurfaceImportedKind;
  value: string;
  raw: string;
  line: number;
  label: string;
}

export interface AttackSurfaceImportResult {
  targets: AttackSurfaceImportedTarget[];
  ignored: number;
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const CIDR = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/([0-9]|[1-2][0-9]|3[0-2])$/;
const DOMAIN = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
const ASN = /^(?:AS)?(\d{1,10})$/i;
const QUERY_PREFIX = /^(?:shodan|query)\s*:\s*(.+)$/i;

const withoutControlChars = (value: string) => Array.from(value, (char) => {
  const code = char.charCodeAt(0);
  return code <= 31 || code === 127 ? " " : char;
}).join("");

const clean = (value: string) => withoutControlChars(value).replace(/\s+/g, " ").trim();

const normalizeLine = (line: string) => clean(line.replace(/^\uFEFF/, ""));

const hostnameFromUrl = (value: string) => {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:" ? url.hostname : value;
  } catch {
    return value;
  }
};

const parsedTarget = (
  kind: AttackSurfaceImportedKind,
  value: string,
  raw: string,
  line: number,
): AttackSurfaceImportedTarget => ({
  kind,
  value,
  raw,
  line,
  label: kind === "shodan_query" ? "Shodan query" : value,
});

const classify = (raw: string, line: number): AttackSurfaceImportedTarget | null => {
  const query = raw.match(QUERY_PREFIX);
  if (query?.[1]?.trim()) return parsedTarget("shodan_query", clean(query[1]), raw, line);
  if (CIDR.test(raw)) return parsedTarget("cidr", raw, raw, line);
  if (IPV4.test(raw)) return parsedTarget("ip", raw, raw, line);
  const asn = raw.match(ASN);
  if (asn) return parsedTarget("asn", `AS${asn[1]}`, raw, line);
  if (DOMAIN.test(raw)) return parsedTarget("domain", raw.toLowerCase(), raw, line);
  return null;
};

// Shared collector: classify each entry, dedupe by kind+value, and count the
// ones that carry content but match nothing (`counts`) as ignored. Blank lines
// pass `counts:false` so they stay silent.
const collect = (
  entries: Array<{ raw: string; line: number; counts: boolean }>,
): AttackSurfaceImportResult => {
  const targets: AttackSurfaceImportedTarget[] = [];
  const seen = new Set<string>();
  let ignored = 0;

  for (const { raw, line, counts } of entries) {
    const value = hostnameFromUrl(raw);
    if (!value) {
      if (counts) ignored += 1;
      continue;
    }
    const target = classify(value, line);
    if (!target) {
      ignored += 1;
      continue;
    }
    const key = `${target.kind}:${target.value.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    targets.push(target);
  }

  return { targets, ignored };
};

const parseLines = (text: string): AttackSurfaceImportResult =>
  collect(
    text.split(/\r?\n/).map((sourceLine, index) => {
      const raw = normalizeLine(sourceLine);
      const isComment = raw.startsWith("#");
      return { raw: isComment ? "" : raw, line: index + 1, counts: isComment };
    }),
  );

const STRING_FIELDS = ["value", "target", "ip", "host", "cidr", "domain", "asn"] as const;

// Pull a single target string out of a JSON object. A `query` field is tagged
// with the `query:` prefix so it classifies as a Shodan query.
const pickString = (item: Record<string, unknown>): string => {
  const query = item.query;
  if (typeof query === "string" && query.trim()) return `query: ${query}`;
  for (const field of STRING_FIELDS) {
    const candidate = item[field];
    if (typeof candidate === "string" && candidate.trim()) return candidate;
  }
  return "";
};

const toTokenStrings = (data: unknown): string[] => {
  let items: unknown[] = [];
  if (Array.isArray(data)) {
    items = data;
  } else if (data && typeof data === "object") {
    for (const key of ["targets", "ips", "assets", "hosts", "items"]) {
      const value = (data as Record<string, unknown>)[key];
      if (Array.isArray(value)) {
        items = value;
        break;
      }
    }
    if (items.length === 0) items = [data];
  }
  return items.map((item) => {
    if (typeof item === "string") return item;
    if (item && typeof item === "object") return pickString(item as Record<string, unknown>);
    return "";
  });
};

const parseJson = (data: unknown): AttackSurfaceImportResult =>
  collect(
    toTokenStrings(data).map((token, index) => ({
      raw: clean(token),
      line: index + 1,
      counts: true,
    })),
  );

// Accepts both line-delimited text (IP/CIDR/domain/ASN/`shodan:` query, `#`
// comments) and JSON (array of strings, array of objects with a value/target/
// ip/query field, or an object exposing a targets/ips/assets array). Malformed
// JSON falls back to line parsing so a mislabeled file still works.
export const parseAttackSurfaceTargets = (text: string): AttackSurfaceImportResult => {
  const trimmed = text.replace(/^\uFEFF/, "").trim();
  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    try {
      return parseJson(JSON.parse(trimmed));
    } catch {
      // Not valid JSON — fall through to line-based parsing.
    }
  }
  return parseLines(text);
};

export const targetToMonitorDraft = (target: AttackSurfaceImportedTarget) => ({
  type: target.kind,
  value: target.value,
  label: target.label,
});
