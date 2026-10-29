import type { ThreatIntelligenceResult, VendorData, VerdictSignal } from '../types/threat-intelligence';

export const THREAT_VERDICT_VERSION = '2026-10-29-signals-v4-query-coverage';
const IMPORTANT_AV_VENDORS = ['Microsoft','Kaspersky','Bitdefender','ESET-NOD32','Avira','Sophos','McAfee','Symantec','TrendMicro','F-Secure','Fortinet','Palo Alto Networks','CrowdStrike'];
const numeric = (value: unknown): number | null => {
    if (value == null || value === '') return null;
    const result = Number.parseFloat(String(value));
    return Number.isFinite(result) && result >= 0 ? result : null;
};

/** Absence is an abstention. A minority finding survives other sources' empty responses. */
export function scoreThreatResults(query: string, results: VendorData[]): ThreatIntelligenceResult {
    const signals: VerdictSignal[] = [];
    let positiveVotes = 0, cleanVotes = 0, strong = false;
    for (const vendor of results) {
        if (vendor.error || vendor.isLoading || vendor.unsupported || !vendor.data) continue;
        const data = vendor.data, status = String(data.Status || '').toLowerCase();
        const signal = (reason: string, kind: VerdictSignal['kind'], confirmed = false) => {
            positiveVotes++; strong ||= confirmed; signals.push({ source: vendor.name, reason, kind });
        };
        if (vendor.name === 'VirusTotal') {
            const malicious = numeric(data.Malicious), suspicious = numeric(data.Suspicious);
            const important = Array.isArray(data['All Vendors']) && data['All Vendors'].some((v: any) =>
                v.category === 'malicious' && IMPORTANT_AV_VENDORS.some(av => String(v.engine || '').toLowerCase().includes(av.toLowerCase())));
            if ((malicious || 0) > 0 || status === 'malicious') signal(`${malicious ?? 1} detecção(ões) de malware`, 'detection', (malicious || 0) > 3 || important);
            else if ((suspicious || 0) > 0 || status.includes('suspicious')) signal(`${suspicious ?? 1} detecção(ões) suspeita(s)`, 'detection');
            else if (malicious != null || suspicious != null || status === 'clean') cleanVotes++;
            continue;
        }
        if (vendor.name === 'AbuseIPDB') {
            const score = numeric(data['Abuse Confidence Score']), reports = numeric(data['Total Reports']);
            if ((score || 0) > 0 || (reports || 0) > 0) signal(`${reports ?? 'Não informado'} relato(s) de abuso; confiança da fonte: ${score == null ? 'não informada' : score + '%'}`, 'abuse', score === 100);
            else if (score != null) cleanVotes++;
            continue;
        }
        if (vendor.name === 'AlienVault OTX') {
            const pulses = numeric(data['Pulse Count']) ?? (Array.isArray(data['Pulse Details']) ? data['Pulse Details'].length : 0);
            if (pulses > 0 || status.includes('suspicious')) signal(`${pulses} pulse(s) associado(s); contexto para revisão, sem confirmar autoria`, 'context');
            continue;
        }
        if (vendor.name === 'Axur') {
            if ((numeric(data['Registros Axur']) || 0) > 0) signal('Registro exato na Axur; relações do relatório são contexto para revisão', 'context');
            continue;
        }
        if (vendor.name === 'WHOIS' || vendor.name === 'DNS / Team Cymru' || vendor.name === 'abuse.ch Hunting') continue;
        if (vendor.name === 'MalwareBazaar' && status === 'sample found') { signal('Amostra encontrada na base de malware', 'detection', true); continue; }
        if (vendor.name === 'URLhaus' && (status.includes('malware payload') || (numeric(data['URL Count']) || 0) > 0)) { signal('URL ou payload associado a malware', 'detection', true); continue; }
        if (/malicious|unsafe|phishing/.test(status) && !/unknown|unverified|not found|no data/.test(status)) { signal('Registro positivo informado pela fonte', 'detection', true); continue; }
        if (status === 'clean') cleanVotes++;
        // No data / No samples found / Unknown never become clean votes.
    }
    const checked = positiveVotes + cleanVotes, incomplete = results.some(v => v.error || v.isLoading);
    let threatLevel: ThreatIntelligenceResult['threatLevel'] = 'unknown', overallScore = 0;
    if (strong) { threatLevel = 'malicious'; overallScore = Math.max(75, Math.round(positiveVotes / Math.max(1, checked) * 100)); }
    else if (positiveVotes > 0) { threatLevel = 'suspicious'; overallScore = Math.max(35, Math.min(69, Math.round(positiveVotes / checked * 100))); }
    else if (cleanVotes > 0 && !incomplete) threatLevel = 'safe';
    const minority = Math.min(positiveVotes, cleanVotes);
    return { query, overallScore, threatLevel, totalVendors: results.filter(v=>!v.unsupported).length, detections: positiveVotes, vendorData: results,
        signals, reportingVendors: checked, confidence: checked ? Math.max(strong ? 80 : 0, Math.round(Math.max(positiveVotes, cleanVotes) / checked * 100)) : 0,
        disagreement: positiveVotes > 0 && cleanVotes > 0 && minority / checked >= 0.2 };
}
