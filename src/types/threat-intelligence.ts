export interface VendorData {
    name: string;
    data: Record<string, any>;
    error?: string;
    isLoading?: boolean;
    quota?: {
        remaining?: string | number;
        limit?: string | number;
        reset?: string | number;
        daily_remaining?: string | number;
    };
    link?: string;
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
