// Structured exports of scan results for ingestion by SIEM/TIP/SOAR platforms.
// Siblings to the PDF report: machine-readable JSON, line-delimited NDJSON, and
// a STIX 2.1 bundle of indicators.
import type { ThreatIntelligenceResult } from "@/types/threat-intelligence";
import { detectIOCType } from "@/services/threatApi";

const triggerDownload = (content: string, filename: string, type: string) => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
};

const stamp = () => new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");

const uuid = () =>
    typeof crypto !== "undefined" && "randomUUID" in crypto
        ? crypto.randomUUID()
        : "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
              const r = (Math.random() * 16) | 0;
              return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
          });

// Full structured dump: one JSON document with every result.
export const exportResultsJSON = (results: ThreatIntelligenceResult[]) => {
    const payload = {
        generated_at: new Date().toISOString(),
        tool: "ThreatSumm4ry",
        count: results.length,
        results,
    };
    triggerDownload(JSON.stringify(payload, null, 2), `threatsumm4ry-${stamp()}.json`, "application/json");
};

// One JSON object per line — convenient for Splunk HEC / Elasticsearch bulk import.
export const exportResultsNDJSON = (results: ThreatIntelligenceResult[]) => {
    const lines = results
        .map((r) =>
            JSON.stringify({
                query: r.query,
                ioc_type: detectIOCType(r.query),
                threat_level: r.threatLevel,
                score: r.overallScore,
                detections: r.detections,
                total_vendors: r.totalVendors,
            })
        )
        .join("\n");
    triggerDownload(lines, `threatsumm4ry-${stamp()}.ndjson`, "application/x-ndjson");
};

// Build a STIX 2.1 comparison pattern for an indicator from its IOC type.
const stixPattern = (query: string): string => {
    switch (detectIOCType(query)) {
        case "ip":
            return query.includes(":")
                ? `[ipv6-addr:value = '${query}']`
                : `[ipv4-addr:value = '${query}']`;
        case "domain":
            return `[domain-name:value = '${query}']`;
        case "url":
            return `[url:value = '${query.replace(/'/g, "\\'")}']`;
        case "hash": {
            const algo = query.length === 32 ? "MD5" : query.length === 40 ? "SHA-1" : "SHA-256";
            return `[file:hashes.'${algo}' = '${query}']`;
        }
    }
};

const indicatorTypes = (level: ThreatIntelligenceResult["threatLevel"]): string[] => {
    if (level === "malicious") return ["malicious-activity"];
    if (level === "suspicious") return ["anomalous-activity"];
    return ["benign"];
};

// STIX 2.1 bundle: a producer identity plus one indicator SDO per scanned IOC.
export const exportResultsSTIX = (results: ThreatIntelligenceResult[]) => {
    const now = new Date().toISOString();
    const identityId = `identity--${uuid()}`;

    const identity = {
        type: "identity",
        spec_version: "2.1",
        id: identityId,
        created: now,
        modified: now,
        name: "ThreatSumm4ry",
        identity_class: "system",
    };

    const indicators = results.map((r) => ({
        type: "indicator",
        spec_version: "2.1",
        id: `indicator--${uuid()}`,
        created: now,
        modified: now,
        created_by_ref: identityId,
        name: r.query,
        indicator_types: indicatorTypes(r.threatLevel),
        pattern: stixPattern(r.query),
        pattern_type: "stix",
        valid_from: now,
        confidence: r.overallScore,
    }));

    const bundle = {
        type: "bundle",
        id: `bundle--${uuid()}`,
        objects: [identity, ...indicators],
    };

    triggerDownload(JSON.stringify(bundle, null, 2), `threatsumm4ry-stix-${stamp()}.json`, "application/json");
};
