export interface OtPatchRow {
  categories?: string[];
  id: string; title: string; source: string; url: string; references: string[]; vendors: string[];
  published: string; updated: string; revision: string; summary: string; cves: string[]; cvss: number | null;
  patch: 'available' | 'mitigation' | 'unconfirmed'; kev: boolean; revised: boolean; stale: boolean;
  products: { id: string; name: string; vendor: string; status: string; modelNumbers?: string[] }[];
  remediations: { category: string; details: string; url: string; products: string[]; cve: string }[];
  matches: { vendor: string; level: 'model' | 'family' | 'vendor'; models: string[]; families?: string[] }[];
  cveSignals: { id: string; kev: boolean | null; epss: number | null; cvss: number | null }[];
  alsoReportedBy?: string[];
  partialFix?: boolean;
}
export interface OtEquipmentType { id: string; name: string; nameEn: string; description: string; descriptionEn: string; patchContext: string }
export interface OtProductRecord {
  id: string; vendor: string; name: string; family: string; platform: string;
  version: string; versionLabel: string; versionKind: string; versionOrigin: string; versionType: string;
  modelNumbers: string[]; modelPatterns: string[]; equipmentTypes: string[]; statuses: string[];
  affectedCves: string[]; fixedCves: string[];
  evidence: { id: string; source: string; url: string; published: string; updated: string; status: string }[];
}
export interface OtProductBase { rows: OtProductRecord[]; truncated: boolean; summary: { products: number; vendors: number; versioned: number; firmware: number; fixed: number } }
export interface OtPatchData {
  month: string; rows: OtPatchRow[];
  catalog: { vendor: string; aliases: string[]; models: string[]; review: string[]; description?: string; descriptionEn?: string; url?: string; observedModels?: string[]; observedFamilies?: string[]; evidenceProducts?: number; category?: string; families?: string[]; equipmentTypes?: string[] }[];
  productBase?: OtProductBase;
  equipmentTypes?: OtEquipmentType[];
  equipmentReference?: string;
  categories?: string[];
  coverage?: { catalogTools: number; githubAdvisories: number; historicalImportPending: boolean; truncated: boolean; policy: string };
  sources: { id: string; name: string; url: string; coverage: string; status?: string; lastSuccess?: string; checkedAt?: string; error?: string }[];
  status: { catalogPending?: number; catalogFailed?: number; running: boolean; pending: number; failed: number; initialized: boolean; cadenceHours: number; persistenceError: boolean; failedDocuments?: { id: string; source: string; reason: string; retryAt: string }[] };
  summary: { advisories: number; patches: number; mitigations: number; kev: number; matched: number };
}
export function otCurrentMonth(date = new Date()) {
  const parts = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Fortaleza', year: 'numeric', month: '2-digit' }).formatToParts(date);
  return `${parts.find(p => p.type === 'year')!.value}-${parts.find(p => p.type === 'month')!.value}`;
}
export function shiftPatchMonth(month: string, delta: number) {
  const date = new Date(Date.UTC(Number(month.slice(0, 4)), Number(month.slice(5, 7)) - 1 + delta, 1));
  return date.toISOString().slice(0, 7);
}
export function msrcPatchMonth(id: string) {
  const match = /^(20\d{2})-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$/i.exec(id);
  if (!match) return '';
  return `${match[1]}-${String(['jan','feb','mar','apr','may','jun','jul','aug','sep','oct','nov','dec'].indexOf(match[2].toLowerCase()) + 1).padStart(2, '0')}`;
}
export async function fetchOtPatch(month: string, signal?: AbortSignal, domain: 'ot' | 'ai' = 'ot'): Promise<OtPatchData> {
  const response = await fetch(`/api/${domain === 'ai' ? 'ai' : 'ot'}-patch-day?` + new URLSearchParams({ month }), { signal });
  if (!response.ok) throw Error(response.status === 400 ? 'Período inválido.' : 'Não foi possível carregar o Patch Day.');
  return response.json();
}
