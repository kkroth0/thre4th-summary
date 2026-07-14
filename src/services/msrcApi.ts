// Microsoft Patch Tuesday (MSRC CVRF v3.0) client service.
// Data is fetched through the backend proxy at /api/patch-tuesday/* which
// normalizes the raw CVRF document into the compact shapes below.

export interface PatchTuesdayMonth {
    id: string; // e.g. "2026-Jun"
    title: string; // e.g. "June 2026 Security Updates"
    initialReleaseDate: string;
    currentReleaseDate: string;
}

export interface PatchTuesdayTotals {
    // Microsoft's own patch set. Chromium restatements are excluded from every
    // field here and counted in `chromium` instead, so these are the numbers
    // that describe what Microsoft actually shipped this month.
    total: number;
    critical: number;
    important: number;
    moderate: number;
    low: number;
    unknown: number;
    exploited: number;
    disclosed: number;
    exploitMoreLikely: number;
    chromium: number;
}

export interface NamedCount {
    name: string;
    count: number;
}

export interface PatchVulnerability {
    cve: string;
    title: string;
    description: string;
    cwe: string;
    severity: string; // Critical | Important | Moderate | Low | Unknown
    impact: string; // Remote Code Execution, Elevation of Privilege, ...
    cvss: number | null;
    vector: string;
    exploited: boolean;
    publiclyDisclosed: boolean;
    exploitability: string; // Exploitation More Likely / Less Likely / Unlikely / N/A
    chromium: boolean; // Google Chrome CVE restated by Microsoft, not a Microsoft bug
    family: string;
    productCount: number;
    kbs: { kb: string; url: string }[];
    releaseDate: string | null;
}

export interface PatchTuesdaySummary {
    id: string;
    title: string;
    initialReleaseDate: string | null;
    currentReleaseDate: string | null;
    totals: PatchTuesdayTotals;
    byImpact: NamedCount[];
    byFamily: NamedCount[];
    topCves: PatchVulnerability[];
    vulnerabilities: PatchVulnerability[];
}

const handle = async <T>(res: Response): Promise<T> => {
    if (!res.ok) {
        let detail = '';
        try {
            detail = (await res.json())?.error || '';
        } catch {
            /* ignore */
        }
        throw new Error(detail || `Request failed (${res.status})`);
    }
    return res.json() as Promise<T>;
};

export const fetchPatchTuesdayMonths = async (): Promise<PatchTuesdayMonth[]> => {
    const res = await fetch('/api/patch-tuesday/months');
    return handle<PatchTuesdayMonth[]>(res);
};

export const fetchPatchTuesdaySummary = async (id: string): Promise<PatchTuesdaySummary> => {
    const res = await fetch(`/api/patch-tuesday/${encodeURIComponent(id)}`);
    return handle<PatchTuesdaySummary>(res);
};
