// SAP Security Patch Day client service.
// Data is scraped + normalized by the backend at /api/sap-patch (the SAP
// Security Notes page has no API/feed). One request = the latest patch month.

export interface SapNote {
    note: string; // SAP note number, e.g. "3747367"
    noteUrl: string; // me.sap.com/notes/<note>
    title: string;
    cves: string[]; // CVE ids referenced by the note
    priority: string; // Hot News/Critical | High | Medium | Low
    cvss: number | null;
    cvssVector: string | null;
    isUpdate: boolean; // re-release of a prior month's note
}

export interface SapPatchSummary {
    url: string;
    stale?: boolean;
    releaseDate: string | null; // YYYY-MM-DD (SAP Patch Day)
    notes: SapNote[];
    summary: {
        total: number;
        byPriority: Record<string, number>;
        hotNews: number; // Hot News + Critical
        high: number;
        maxCvss: number;
        cveCount: number;
    };
}

export const fetchSapPatch = async (month?: string, signal?: AbortSignal): Promise<SapPatchSummary> => {
    const res = await fetch('/api/sap-patch' + (month ? '?' + new URLSearchParams({ month }) : ''), { signal });
    if (!res.ok) {
        let detail = '';
        try { detail = (await res.json())?.error || ''; } catch { /* ignore */ }
        throw new Error(detail || `Request failed (${res.status})`);
    }
    return res.json() as Promise<SapPatchSummary>;
};
