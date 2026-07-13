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

const clean = (value: string) => value.replace(/[\x00-\x1F\x7F]/g, " ").replace(/\s+/g, " ").trim();

const normalizeLine = (line: string) => clean(line.replace(/^\uFEFF/, ""));

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

export const parseAttackSurfaceTargets = (text: string): AttackSurfaceImportResult => {
  const targets: AttackSurfaceImportedTarget[] = [];
  const seen = new Set<string>();
  let ignored = 0;

  text.split(/\r?\n/).forEach((sourceLine, index) => {
    const raw = normalizeLine(sourceLine);
    if (!raw || raw.startsWith("#")) {
      ignored += raw ? 1 : 0;
      return;
    }

    let target: AttackSurfaceImportedTarget | null = null;
    const query = raw.match(QUERY_PREFIX);
    if (query?.[1]?.trim()) {
      target = parsedTarget("shodan_query", clean(query[1]), raw, index + 1);
    } else if (CIDR.test(raw)) {
      target = parsedTarget("cidr", raw, raw, index + 1);
    } else if (IPV4.test(raw)) {
      target = parsedTarget("ip", raw, raw, index + 1);
    } else {
      const asn = raw.match(ASN);
      if (asn) {
        target = parsedTarget("asn", `AS${asn[1]}`, raw, index + 1);
      } else if (DOMAIN.test(raw)) {
        target = parsedTarget("domain", raw.toLowerCase(), raw, index + 1);
      }
    }

    if (!target) {
      ignored += 1;
      return;
    }

    const key = `${target.kind}:${target.value.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    targets.push(target);
  });

  return { targets, ignored };
};

export const targetToMonitorDraft = (target: AttackSurfaceImportedTarget) => ({
  type: target.kind,
  value: target.value,
  label: target.label,
});
