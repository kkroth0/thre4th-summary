// A single dated observation a vendor reported about an IOC (first/last seen,
// last analysis, an abuse report, etc.), normalized to ISO 8601 so events from
// every feed can be merged into one chronological timeline.
export interface TimelineEvent {
    vendor: string;
    label: string;
    date: string; // ISO 8601
    kind: "first_seen" | "last_seen" | "analysis" | "report" | "other";
}

export interface VendorData {
    rawDeferred?: boolean;
    name: string;
    data: Record<string, any>;
    error?: string;
    httpStatus?: number;
    errorCode?: string;
    retryAt?: number;
    isLoading?: boolean;
    quota?: {
        remaining?: string | number;
        limit?: string | number;
        reset?: string | number;
        daily_remaining?: string | number;
    };
    link?: string;
    timeline?: TimelineEvent[];
    /** Complete provider response, retained by bulk enrichment exports. */
    rawPayload?: unknown;
}

export interface ThreatIntelligenceResult {
    query: string;
    overallScore: number;
    threatLevel: "safe" | "suspicious" | "malicious" | "unknown";
    totalVendors: number;
    detections: number;
    vendorData: VendorData[];
    // Additive verdict metadata (does not affect threatLevel/overallScore):
    // confidence = agreement among vendors that returned a definitive signal;
    // disagreement = a meaningful malicious/clean split worth analyst attention;
    // reportingVendors = how many vendors actually weighed in.
    confidence?: number;
    disagreement?: boolean;
    reportingVendors?: number;
}

export interface ApiConfig {
    apiKey: string;
    baseUrl: string;
}
