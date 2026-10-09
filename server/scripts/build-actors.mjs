#!/usr/bin/env node
/**
 * Build the threat-actor catalog served at /api/actors, the malware-family
 * catalog malwareMatch.js indexes, the named-campaign catalog
 * campaignMatch.js indexes, plus the ATT&CK taxonomy that attackIndex.js
 * uses as the coverage denominator.
 *
 * Sources (all free, no auth):
 *   - MITRE ATT&CK Groups: the `intrusion-set` objects in the enterprise ATT&CK
 *     STIX bundle (same bundle the engine's tools/fetch_attack.py uses). Gives
 *     name, aliases, description, the Gxxxx id, and — via `relationship`
 *     (relationship_type "uses") — the techniques and software the group uses.
 *   - MISP galaxy `threat-actor.json`: enriches with country, motivation and
 *     extra synonyms, and adds actors that aren't in ATT&CK.
 *   - ransomware.live `/v2/groups`: the extortion brands. ATT&CK and MISP track
 *     nation-state intrusion sets and barely name ransomware gangs — LockBit,
 *     Cl0p, ALPHV, Qilin and ~300 others were simply absent, so news about them
 *     matched no actor at all.
 *   - The same STIX bundle's `malware`/`tool` objects: each carries its own
 *     `x_mitre_aliases` (confirmed populated on 724/730 live malware objects as
 *     of 2026-10, including "Lumma Stealer" -> ["LummaStealer"]) independent of
 *     which group's "uses" relationship points at it.
 *   - MISP galaxy `malpedia.json`: malpedia's synonym lists are broader than
 *     ATT&CK's own aliases — it's where "Lumma Stealer" picks up the synonym
 *     "LummaC2 Stealer" that ATT&CK doesn't list.
 *   - The same STIX bundle's `campaign` objects (named operations like
 *     "Operation Dream Job"): these use a plain `aliases` field (not
 *     `x_mitre_aliases`) and carry `attributed-to`/`uses` relationships to the
 *     intrusion-set and malware/tool behind them. Only 56 live as of 2026-10 —
 *     MITRE's campaign tracking is new and curated tightly.
 *   - MISP galaxy `tidal-campaigns.json` (Tidal Cyber): every one of its 157
 *     entries already carries a `campaign_attack_id`, but more of those ids
 *     exist than the official STIX bundle currently lists live — Tidal tracks
 *     ~100 campaigns ATT&CK hasn't (yet) published as first-class objects.
 *     Confirmed empty of its own aliases (0/157 `meta.synonyms`), so it only
 *     adds campaign coverage, never alias coverage.
 *
 * The same STIX bundle also carries every `attack-pattern` and `x-mitre-tactic`,
 * so we emit server/data/attack.json here instead of downloading 35 MB twice
 * from a second script. actors.json only sees the ~490 techniques some group
 * uses; the matrix needs all of them, with their tactic.
 *
 * Writes server/data/actors.json, server/data/malware.json,
 * server/data/campaigns.json and server/data/attack.json. Run manually:
 *     node server/scripts/build-actors.mjs
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_PATH = join(__dirname, "..", "data", "actors.json");
const MALWARE_OUT_PATH = join(__dirname, "..", "data", "malware.json");
const CAMPAIGN_OUT_PATH = join(__dirname, "..", "data", "campaigns.json");
const ATTACK_OUT_PATH = join(__dirname, "..", "data", "attack.json");

const TIDAL_CAMPAIGNS_URL =
  "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/tidal-campaigns.json";

const ATTACK_URL =
  "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/" +
  "enterprise-attack/enterprise-attack.json";
const MISP_URL =
  "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json";
const MALPEDIA_URL =
  "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/malpedia.json";
const RANSOMWARE_URL = "https://api.ransomware.live/v2/groups";

// 2-letter country code -> display name (common APT sponsors; fallback = raw value).
const COUNTRY_NAMES = {
  RU: "Russia", CN: "China", KP: "North Korea", IR: "Iran", US: "United States",
  IL: "Israel", IN: "India", PK: "Pakistan", VN: "Vietnam", KR: "South Korea",
  TR: "Turkey", SY: "Syria", LB: "Lebanon", AE: "United Arab Emirates",
  GB: "United Kingdom", FR: "France", UA: "Ukraine", BY: "Belarus", NG: "Nigeria",
};

const CITATION_RE = /\(Citation:[^)]*\)/g;
const MD_LINK_RE = /\[([^\]]+)\]\([^)]+\)/g; // [text](url) -> text
// Tidal Cyber's descriptions embed raw citation markup ATT&CK's own prose
// doesn't have, e.g. "<sup>[ClearSky Dream Job November 12 2024]</sup>".
const HTML_TAG_RE = /<\/?[a-z][^>]*>/gi;
const WS_RE = /\s+/g;

function cleanDesc(text, cap = 1600) {
  if (!text) return "";
  let t = text.replace(CITATION_RE, "");
  t = t.replace(MD_LINK_RE, "$1");
  t = t.replace(HTML_TAG_RE, "");
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

  // Malware/tool SDOs carry their own x_mitre_aliases regardless of which
  // group's "uses" relationship points at them, so this is a separate pass
  // over the same objects — not reusing the groups loop above, which
  // `continue`s past anything that isn't an intrusion-set.
  const malware = [];
  for (const o of objects) {
    if ((o.type !== "malware" && o.type !== "tool") || o.revoked || o.x_mitre_deprecated) continue;
    const { id, url } = attackId(o);
    malware.push({
      name: o.name || "",
      aliases: (o.x_mitre_aliases || []).filter((a) => a && a !== o.name),
      description: cleanDesc(o.description),
      platforms: o.x_mitre_platforms || [],
      attack_id: id,
      attack_url: url,
    });
  }

  // Campaigns: their own pass too, same reason as malware/tool above — a
  // separate STIX type the groups loop skips past entirely.
  const campaigns = [];
  for (const o of objects) {
    if (o.type !== "campaign" || o.revoked || o.x_mitre_deprecated) continue;
    const { id, url } = attackId(o);
    campaigns.push({
      stixId: o.id,
      name: o.name || "",
      // Plain `aliases`, not `x_mitre_aliases` — campaigns use the same field
      // intrusion-sets do, not the malware/tool convention.
      aliases: (o.aliases || []).filter((a) => a && a !== o.name),
      description: cleanDesc(o.description),
      first_seen: o.first_seen || "",
      last_seen: o.last_seen || "",
      attack_id: id,
      attack_url: url,
      techniques: [],
      malware: [],
      attributed_actor_id: "",
    });
  }
  const campaignByStixId = new Map(campaigns.map((c) => [c.stixId, c]));

  // "uses" from a campaign source behaves exactly like "uses" from a group
  // above; "attributed-to" is campaign-only and points at the intrusion-set
  // actually running it — the one relationship actors.json doesn't carry the
  // other direction (a group's record never lists "campaigns it ran").
  for (const o of objects) {
    if (o.type !== "relationship") continue;
    const c = campaignByStixId.get(o.source_ref);
    if (!c) continue;
    if (o.relationship_type === "uses") {
      const target = byId.get(o.target_ref);
      if (!target || target.revoked || target.x_mitre_deprecated) continue;
      if (target.type === "attack-pattern") {
        const { id, url } = attackId(target);
        if (id) c.techniques.push({ id, name: target.name || "", url: url || techniqueUrl(id) });
      } else if (target.type === "malware" || target.type === "tool") {
        const { id, url } = attackId(target);
        if (id) c.malware.push({ id, name: target.name || "", url });
      }
    } else if (o.relationship_type === "attributed-to") {
      const actor = groups.get(o.target_ref);
      if (actor?.attack_id) c.attributed_actor_id = actor.attack_id;
    }
  }
  for (const c of campaigns) {
    c.techniques.sort((a, b) => a.id.localeCompare(b.id));
    const seen = new Set();
    c.malware = c.malware.filter((m) => {
      const k = norm(m.name);
      if (!k || seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }

  return { groups: [...groups.values()], taxonomy: buildTaxonomy(objects), malware, campaigns };
}

/** MISP galaxy tidal-campaigns: broader campaign coverage, zero alias data. */
async function buildTidalCampaigns() {
  const cluster = await fetchJson(TIDAL_CAMPAIGNS_URL, "MISP galaxy tidal-campaigns");
  const out = [];
  for (const v of cluster.values || []) {
    const name = (v.value || "").trim();
    const attackId = (v.meta?.campaign_attack_id || "").trim();
    if (!name || !attackId) continue;
    out.push({
      name,
      attack_id: attackId,
      description: cleanDesc(v.description),
      first_seen: v.meta?.first_seen || "",
      last_seen: v.meta?.last_seen || "",
      uuid: v.uuid || "",
    });
  }
  return out;
}

// "Lumma Stealer" is cited in prose as bare "Lumma" at least as often as with
// the type suffix, but malpedia/ATT&CK alias lists rarely include that bare
// form on their own (malpedia's own synonym for it is "LummaC2 Stealer", still
// carrying "Stealer") — so derive it by stripping a trailing generic-type word.
// cleanAliases() downstream already drops anything too short/duplicate, so no
// extra validation is needed here.
const MALWARE_TYPE_SUFFIX = new RegExp(
  "^(.+?)\\s+(?:stealer|rat|trojan|loader|backdoor|wiper|worm|botnet|ransomware|" +
  "malware|miner|rootkit|keylogger|dropper|clipper|downloader|implant)$",
  "i",
);
function deriveBareBrand(name) {
  const m = MALWARE_TYPE_SUFFIX.exec(String(name || "").trim());
  return m ? m[1].trim() : null;
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

/** MISP galaxy malpedia: the broadest public malware-family synonym catalog. */
async function buildMalpedia() {
  const cluster = await fetchJson(MALPEDIA_URL, "MISP galaxy malpedia");
  const out = [];
  for (const v of cluster.values || []) {
    const meta = v.meta || {};
    const name = (v.value || "").trim();
    if (!name) continue;
    out.push({
      name,
      aliases: (meta.synonyms || []).map((s) => (s || "").trim()).filter((s) => s && s !== name),
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

/**
 * ransomware.live keys groups by slug ("lockbit", "alphv", "cl0p"), but the
 * description carries the branded casing. The catalog shows the name and the
 * news feed prints it back to the analyst, so recover the branding when the
 * prose has it — pick the variant with the most capitals ("LockBit" over a
 * sentence-initial "Lockbit").
 *
 * The slug also swallows the spaces ("blackbasta"), so each character may be
 * followed by one in the prose. That half matters more than the casing: a
 * two-word brand lands in the distinctive tier of the news matcher, where it
 * needs no CTI context term to be attributed.
 */
function brandedName(name, description) {
  if (!name || name !== name.toLowerCase()) return name;
  const chars = [...name].map((c) => c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const re = new RegExp(`(?<![A-Za-z0-9])${chars.join("[ -]?")}(?![A-Za-z0-9])`, "gi");
  const caps = (s) => (s.match(/[A-Z]/g) || []).length;
  let best = name;
  for (const [hit] of String(description || "").matchAll(re)) {
    if (caps(hit) > caps(best) || (caps(hit) === caps(best) && hit.length > best.length)) {
      best = hit;
    }
  }
  return best;
}

async function buildRansomware() {
  const groups = await fetchJson(RANSOMWARE_URL, "ransomware.live groups");
  const out = [];
  for (const g of Array.isArray(groups) ? groups : []) {
    const name = brandedName(String(g.name || "").trim(), g.description);
    if (!name) continue;
    // A technique can hang off two tactics; the actor record wants it once.
    const techniques = new Map();
    for (const tactic of g.ttps || []) {
      for (const t of tactic.techniques || []) {
        if (!t.technique_id || techniques.has(t.technique_id)) continue;
        techniques.set(t.technique_id, {
          id: t.technique_id,
          name: t.technique_name || "",
          url: techniqueUrl(t.technique_id),
        });
      }
    }
    out.push({
      name,
      aliases: cleanAliases([g.altname], name),
      description: cleanDesc(g.description),
      techniques: [...techniques.values()].sort((a, b) => a.id.localeCompare(b.id)),
      // `g.locations` holds live DLS onions — deliberately not carried into refs.
      url: g.url || "",
    });
  }
  return out;
}

async function main() {
  const [{ groups: attack, taxonomy, malware: attackMalware, campaigns: attackCampaigns }, misp, ransomware, malpedia, tidalCampaigns] = await Promise.all([
    buildAttack(),
    buildMisp(),
    buildRansomware(),
    buildMalpedia(),
    buildTidalCampaigns(),
  ]);

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

  // 3) Ransomware brands neither source names. ATT&CK/MISP win on any overlap:
  // their Akira/Play/RansomHub entries carry techniques and references.
  const known = new Set(actors.flatMap((a) => mergedKey([a.name, ...a.aliases])));
  for (const r of ransomware) {
    const keys = mergedKey([r.name, ...r.aliases]);
    if (!keys.length || keys.some((k) => known.has(k))) continue;
    for (const k of keys) known.add(k);
    actors.push({
      id: `rl-${norm(r.name)}`,
      name: r.name,
      aliases: r.aliases,
      country: "",
      motivation: "Extortion",
      description: r.description,
      attack_id: "",
      attack_url: "",
      techniques: r.techniques,
      software: [],
      refs: r.url ? [r.url] : [],
      source: "ransomware.live",
    });
  }

  actors.sort((a, b) => a.name.localeCompare(b.name));

  // Index malpedia entries by every normalized name/alias for enrichment lookup.
  const malpediaByKey = new Map();
  for (const m of malpedia) {
    for (const k of mergedKey([m.name, ...m.aliases])) {
      if (!malpediaByKey.has(k)) malpediaByKey.set(k, m);
    }
  }

  const malware = [];
  const usedMalpedia = new Set();

  // 1) ATT&CK malware/tool objects are authoritative for id/platform/
  // description; malpedia only contributes extra alias coverage (and refs/
  // description for malpedia-only families below).
  for (const w of attackMalware) {
    let match = null;
    for (const k of mergedKey([w.name, ...w.aliases])) {
      if (malpediaByKey.has(k)) { match = malpediaByKey.get(k); break; }
    }
    if (match) usedMalpedia.add(match.uuid);
    // Derive from every candidate (name + each alias), not just the primary
    // name: malpedia's own synonym is often ITSELF still type-suffixed (Lumma
    // Stealer's synonym is "LummaC2 Stealer", not bare "LummaC2") — the bare
    // form a headline actually uses hides inside the alias, not the name.
    const combined = [w.name, ...w.aliases, ...(match ? match.aliases : [])];
    const bareBrands = combined.map(deriveBareBrand).filter(Boolean);
    const rawAliases = [...w.aliases, ...(match ? match.aliases : []), ...bareBrands];
    malware.push({
      id: w.attack_id || `mitre-${norm(w.name)}`,
      name: w.name,
      aliases: cleanAliases(rawAliases, w.name, 20),
      platforms: w.platforms,
      description: w.description || (match ? match.description : ""),
      attack_id: w.attack_id,
      attack_url: w.attack_url,
      refs: match ? match.refs : [],
      source: match ? "attack+malpedia" : "attack",
    });
  }

  // 2) malpedia-only families (not matched to any ATT&CK malware/tool object)
  // — this is the bulk of the catalog: ATT&CK only tracks software used by a
  // tracked intrusion-set, so most commodity malware (stealers, loaders sold
  // as MaaS with no attributed group) only exists here.
  for (const m of malpedia) {
    if (usedMalpedia.has(m.uuid)) continue;
    const bareBrands = [m.name, ...m.aliases].map(deriveBareBrand).filter(Boolean);
    const rawAliases = [...m.aliases, ...bareBrands];
    malware.push({
      id: `malpedia-${m.uuid.slice(0, 8) || norm(m.name)}`,
      name: m.name,
      aliases: cleanAliases(rawAliases, m.name, 20),
      platforms: [],
      description: m.description,
      attack_id: "",
      attack_url: "",
      refs: m.refs,
      source: "malpedia",
    });
  }

  malware.sort((a, b) => a.name.localeCompare(b.name));

  // No bare-brand derivation here, unlike malware's deriveBareBrand(): ~23%
  // of campaign names end in a generic suffix ("SolarWinds Compromise",
  // "Quantum Ransomware Compromise"), but they don't follow malware's clean
  // "Brand + Type" convention — stripping the suffix off "Microsoft Midnight
  // Blizzard Breach" yields "Microsoft Midnight Blizzard," which reads as
  // Microsoft being part of the campaign's own name. The risk of a wrong
  // derived alias outweighs catching the few genuinely clean cases.
  //
  // Campaigns: STIX objects are authoritative (id/dates/aliases/techniques/
  // malware/attributed actor); Tidal only ever contributes a bare extra entry
  // when ATT&CK's own live campaign list doesn't have that id yet.
  const campaigns = attackCampaigns.map((c) => ({
    id: c.attack_id || `mitre-${norm(c.name)}`,
    name: c.name,
    aliases: cleanAliases(c.aliases, c.name, 20),
    description: c.description,
    first_seen: c.first_seen,
    last_seen: c.last_seen,
    attributed_actor_id: c.attributed_actor_id,
    techniques: c.techniques,
    malware: c.malware,
    attack_id: c.attack_id,
    attack_url: c.attack_url,
    source: "attack",
  }));
  const knownCampaignIds = new Set(campaigns.map((c) => c.attack_id).filter(Boolean));
  for (const t of tidalCampaigns) {
    if (knownCampaignIds.has(t.attack_id)) continue;
    knownCampaignIds.add(t.attack_id);
    campaigns.push({
      id: t.attack_id,
      name: t.name,
      aliases: [],
      description: t.description,
      first_seen: t.first_seen,
      last_seen: t.last_seen,
      attributed_actor_id: "",
      techniques: [],
      malware: [],
      attack_id: t.attack_id,
      attack_url: "",
      source: "tidal",
    });
  }
  campaigns.sort((a, b) => a.name.localeCompare(b.name));

  const generated_at = new Date().toISOString();
  mkdirSync(dirname(OUT_PATH), { recursive: true });
  writeFileSync(OUT_PATH, JSON.stringify({ generated_at, actors }, null, 0), "utf8");
  writeFileSync(MALWARE_OUT_PATH, JSON.stringify({ generated_at, malware }, null, 0), "utf8");
  writeFileSync(CAMPAIGN_OUT_PATH, JSON.stringify({ generated_at, campaigns }, null, 0), "utf8");
  writeFileSync(ATTACK_OUT_PATH, JSON.stringify({ generated_at, ...taxonomy }, null, 0), "utf8");

  const withAttack = actors.filter((a) => a.attack_id).length;
  const ransom = actors.filter((a) => a.source === "ransomware.live").length;
  process.stderr.write(
    `Wrote ${actors.length} actors (${withAttack} from ATT&CK, ` +
    `${actors.length - withAttack - ransom} MISP-only, ` +
    `${ransom} ransomware.live) to ${OUT_PATH}\n`,
  );
  const malwareWithAttack = malware.filter((m) => m.attack_id).length;
  process.stderr.write(
    `Wrote ${malware.length} malware families (${malwareWithAttack} from ATT&CK, ` +
    `${malware.length - malwareWithAttack} malpedia-only) to ${MALWARE_OUT_PATH}\n`,
  );
  const campaignsFromAttack = campaigns.filter((c) => c.source === "attack").length;
  process.stderr.write(
    `Wrote ${campaigns.length} campaigns (${campaignsFromAttack} from ATT&CK, ` +
    `${campaigns.length - campaignsFromAttack} tidal-only) to ${CAMPAIGN_OUT_PATH}\n`,
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
