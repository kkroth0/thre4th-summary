#!/usr/bin/env node
/**
 * Build the threat-actor catalog served at /api/actors, plus the ATT&CK
 * taxonomy that attackIndex.js uses as the coverage denominator.
 *
 * Sources (both free, no auth):
 *   - MITRE ATT&CK Groups: the `intrusion-set` objects in the enterprise ATT&CK
 *     STIX bundle (same bundle the engine's tools/fetch_attack.py uses). Gives
 *     name, aliases, description, the Gxxxx id, and — via `relationship`
 *     (relationship_type "uses") — the techniques and software the group uses.
 *   - MISP galaxy `threat-actor.json`: enriches with country, motivation and
 *     extra synonyms, and adds actors that aren't in ATT&CK.
 *
 * The same STIX bundle also carries every `attack-pattern` and `x-mitre-tactic`,
 * so we emit server/data/attack.json here instead of downloading 35 MB twice
 * from a second script. actors.json only sees the ~490 techniques some group
 * uses; the matrix needs all of them, with their tactic.
 *
 * Writes server/data/actors.json and server/data/attack.json. Run manually:
 *     node server/scripts/build-actors.mjs
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_PATH = join(__dirname, "..", "data", "actors.json");
const ATTACK_OUT_PATH = join(__dirname, "..", "data", "attack.json");

const ATTACK_URL =
  "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/" +
  "enterprise-attack/enterprise-attack.json";
const MISP_URL =
  "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json";

// 2-letter country code -> display name (common APT sponsors; fallback = raw value).
const COUNTRY_NAMES = {
  RU: "Russia", CN: "China", KP: "North Korea", IR: "Iran", US: "United States",
  IL: "Israel", IN: "India", PK: "Pakistan", VN: "Vietnam", KR: "South Korea",
  TR: "Turkey", SY: "Syria", LB: "Lebanon", AE: "United Arab Emirates",
  GB: "United Kingdom", FR: "France", UA: "Ukraine", BY: "Belarus", NG: "Nigeria",
};

const CITATION_RE = /\(Citation:[^)]*\)/g;
const MD_LINK_RE = /\[([^\]]+)\]\([^)]+\)/g; // [text](url) -> text
const WS_RE = /\s+/g;

function cleanDesc(text, cap = 1600) {
  if (!text) return "";
  let t = text.replace(CITATION_RE, "");
  t = t.replace(MD_LINK_RE, "$1");
  t = t.replace(/\*\*/g, "").replace(/`/g, "");
  t = t.replace(WS_RE, " ").trim();
  return t.length > cap ? t.slice(0, cap).trim() + "…" : t;
}

/** Normalized key for matching actor names/aliases across sources. */
function norm(s) {
  return (s || "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

/** MISP meta fields are sometimes arrays; coerce to a trimmed string. */
function asText(v) {
  if (Array.isArray(v)) return v.filter(Boolean).map((x) => String(x).trim()).join(", ");
  return (v || "").toString().trim();
}

/** Clean an alias list: drop the actor's own name, dups, ATT&CK ID tokens
 * (e.g. "G0032" — a group id, not an alias), and cap the count. */
function cleanAliases(arr, self, cap = 15) {
  const seen = new Set([norm(self)]);
  const out = [];
  for (const a of arr || []) {
    const k = norm(a);
    if (!k || seen.has(k) || /^[gst]\d{3,4}$/.test(k)) continue;
    seen.add(k);
    out.push(String(a).trim());
    if (out.length >= cap) break;
  }
  return out;
}

async function fetchJson(url, label) {
  process.stderr.write(`Downloading ${label} …\n`);
  const res = await fetch(url, { headers: { "User-Agent": "threatsumm4ry-actors/1.0" } });
  if (!res.ok) throw new Error(`${label}: HTTP ${res.status}`);
  return res.json();
}

function attackId(obj) {
  const ref = (obj.external_references || []).find((r) => r.source_name === "mitre-attack");
  return ref ? { id: ref.external_id || "", url: ref.url || "" } : { id: "", url: "" };
}

function techniqueUrl(tid) {
  // T1059 -> /techniques/T1059/ ; T1059.001 -> /techniques/T1059/001/
  return `https://attack.mitre.org/techniques/${(tid || "").replace(".", "/")}/`;
}

async function buildAttack() {
  const bundle = await fetchJson(ATTACK_URL, "enterprise ATT&CK STIX (~35 MB)");
  const objects = bundle.objects || [];

  // Index objects by STIX id so relationships can be resolved.
  const byId = new Map();
  for (const o of objects) byId.set(o.id, o);

  // Group STIX-id -> group record (only live intrusion-sets).
  const groups = new Map();
  for (const o of objects) {
    if (o.type !== "intrusion-set" || o.revoked || o.x_mitre_deprecated) continue;
    const { id: gid, url } = attackId(o);
    const aliases = (o.aliases || []).filter((a) => a && a !== o.name);
    groups.set(o.id, {
      stixId: o.id,
      name: o.name || "",
      aliases,
      description: cleanDesc(o.description),
      attack_id: gid,
      attack_url: url,
      techniques: [],
      software: [],
    });
  }

  // Wire "uses" relationships: intrusion-set -> attack-pattern | malware/tool.
  for (const o of objects) {
    if (o.type !== "relationship" || o.relationship_type !== "uses") continue;
    const g = groups.get(o.source_ref);
    if (!g) continue;
    const target = byId.get(o.target_ref);
    if (!target || target.revoked || target.x_mitre_deprecated) continue;
    if (target.type === "attack-pattern") {
      const { id, url } = attackId(target);
      if (id) g.techniques.push({ id, name: target.name || "", url: url || techniqueUrl(id) });
    } else if (target.type === "malware" || target.type === "tool") {
      const { id, url } = attackId(target);
      g.software.push({ id, name: target.name || "", url });
    }
  }

  // Sort techniques by id, dedupe software by name.
  for (const g of groups.values()) {
    g.techniques.sort((a, b) => a.id.localeCompare(b.id));
    const seen = new Set();
    g.software = g.software.filter((s) => {
      const k = norm(s.name);
      if (!k || seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }
  return { groups: [...groups.values()], taxonomy: buildTaxonomy(objects) };
}

/**
 * The full ATT&CK matrix from the same STIX objects: every live attack-pattern
 * with the tactics it belongs to. `parent` and "is a sub-technique" are both
 * derivable from the id ("T1566.002" -> "T1566"), so we don't store them.
 */
function buildTaxonomy(objects) {
  const tacticByStixId = new Map();
  const techniques = [];
  for (const o of objects) {
    if (o.revoked || o.x_mitre_deprecated) continue;
    const { id } = attackId(o);
    if (!id) continue;
    if (o.type === "x-mitre-tactic") {
      tacticByStixId.set(o.id, { id, name: o.name || "", shortname: o.x_mitre_shortname || "" });
    } else if (o.type === "attack-pattern") {
      techniques.push({
        id,
        name: o.name || "",
        tactics: (o.kill_chain_phases || [])
          .filter((p) => p.kill_chain_name === "mitre-attack")
          .map((p) => p.phase_name),
      });
    }
  }
  techniques.sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }));

  // The matrix object carries the canonical left-to-right tactic order
  // (Reconnaissance … Impact). Bundle order is arbitrary, so use tactic_refs and
  // fall back to whatever is left over if the matrix ever drops one.
  const matrix = objects.find((o) => o.type === "x-mitre-matrix" && !o.revoked);
  const ordered = (matrix?.tactic_refs || []).map((ref) => tacticByStixId.get(ref)).filter(Boolean);
  const seen = new Set(ordered.map((t) => t.id));
  const tactics = [...ordered, ...[...tacticByStixId.values()].filter((t) => !seen.has(t.id))];
  return { tactics, techniques };
}

async function buildMisp() {
  const cluster = await fetchJson(MISP_URL, "MISP galaxy threat-actor");
  const out = [];
  for (const v of cluster.values || []) {
    const meta = v.meta || {};
    const name = (v.value || "").trim();
    const country =
      asText(meta["cfr-suspected-state-sponsor"]) ||
      COUNTRY_NAMES[(asText(meta.country)).toUpperCase()] ||
      asText(meta.country);
    out.push({
      name,
      aliases: (meta.synonyms || []).map((s) => (s || "").trim()).filter((s) => s && s !== name),
      country,
      motivation: asText(meta["cfr-type-of-incident"]),
      description: cleanDesc(v.description),
      refs: (meta.refs || []).slice(0, 8),
      uuid: v.uuid || "",
    });
  }
  return out;
}

function mergedKey(names) {
  return names.map(norm).filter(Boolean);
}

async function main() {
  const [{ groups: attack, taxonomy }, misp] = await Promise.all([buildAttack(), buildMisp()]);

  // Index MISP actors by every normalized name/alias for enrichment lookup.
  const mispByKey = new Map();
  for (const m of misp) {
    for (const k of mergedKey([m.name, ...m.aliases])) {
      if (!mispByKey.has(k)) mispByKey.set(k, m);
    }
  }

  const actors = [];
  const usedMisp = new Set();

  // 1) ATT&CK groups are authoritative; enrich each with its MISP match.
  for (const g of attack) {
    let match = null;
    for (const k of mergedKey([g.name, ...g.aliases])) {
      if (mispByKey.has(k)) { match = mispByKey.get(k); break; }
    }
    if (match) usedMisp.add(match.uuid);
    actors.push({
      id: g.attack_id || `mitre-${norm(g.name)}`,
      name: g.name,
      // ATT&CK aliases only — authoritative and clean. MISP synonyms are broad
      // "family" groupings (they'd merge Lazarus/APT38/AppleJeus into one), so we
      // take only country/motivation/refs from the MISP match, not its aliases.
      aliases: cleanAliases(g.aliases, g.name),
      country: match ? match.country : "",
      motivation: match ? match.motivation : "",
      description: g.description || (match ? match.description : ""),
      attack_id: g.attack_id,
      attack_url: g.attack_url,
      techniques: g.techniques,
      software: g.software,
      refs: match ? match.refs : [],
      source: match ? "attack+misp" : "attack",
    });
  }

  // 2) MISP-only actors (not matched to any ATT&CK group) as extra entries.
  for (const m of misp) {
    if (usedMisp.has(m.uuid)) continue;
    if (!m.name || !m.description) continue; // skip empty stubs
    actors.push({
      id: `misp-${m.uuid.slice(0, 8) || norm(m.name)}`,
      name: m.name,
      aliases: cleanAliases(m.aliases, m.name),
      country: m.country,
      motivation: m.motivation,
      description: m.description,
      attack_id: "",
      attack_url: "",
      techniques: [],
      software: [],
      refs: m.refs,
      source: "misp",
    });
  }

  actors.sort((a, b) => a.name.localeCompare(b.name));

  const generated_at = new Date().toISOString();
  mkdirSync(dirname(OUT_PATH), { recursive: true });
  writeFileSync(OUT_PATH, JSON.stringify({ generated_at, actors }, null, 0), "utf8");
  writeFileSync(ATTACK_OUT_PATH, JSON.stringify({ generated_at, ...taxonomy }, null, 0), "utf8");

  const withAttack = actors.filter((a) => a.attack_id).length;
  process.stderr.write(
    `Wrote ${actors.length} actors (${withAttack} from ATT&CK, ` +
    `${actors.length - withAttack} MISP-only) to ${OUT_PATH}\n`,
  );
  process.stderr.write(
    `Wrote ${taxonomy.tactics.length} tactics / ${taxonomy.techniques.length} techniques ` +
    `to ${ATTACK_OUT_PATH}\n`,
  );
}

main().catch((e) => {
  console.error("build-actors failed:", e);
  process.exit(1);
});
