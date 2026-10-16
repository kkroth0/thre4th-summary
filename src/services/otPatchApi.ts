export interface OtPatchRow {
  categories?: string[];
  id: string; title: string; source: string; url: string; references: string[]; vendors: string[];
  published: string; updated: string; revision: string; summary: string; cves: string[]; cvss: number | null;
  patch: 'available' | 'mitigation' | 'unconfirmed'; kev: boolean; revised: boolean; stale: boolean;
  products: { id: string; name: string; vendor: string; status: string; modelNumbers?: string[] }[];
  remediations: { category: string; details: string; url: string; products: string[]; cve: string }[];
  matches: { vendor: string; level: 'model' | 'vendor'; models: string[] }[];
  cveSignals: { id: string; kev: boolean | null; epss: number | null; cvss: number | null }[];
  alsoReportedBy?: string[];
}
export interface OtPatchData {
  month: string; rows: OtPatchRow[];
  catalog: { vendor: string; aliases: string[]; models: string[]; review: string[]; category?: string }[];
  categories?: string[];
  coverage?: { catalogTools: number; githubAdvisories: number; historicalImportPending: boolean; truncated: boolean; policy: string };
  sources: { id: string; name: string; url: string; coverage: string; status?: string; lastSuccess?: string; checkedAt?: string; error?: string }[];
  status: { running: boolean; pending: number; failed: number; initialized: boolean; cadenceHours: number; persistenceError: boolean };
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
export async function fetchOtPatch(month: string, signal?: AbortSignal, domain: 'ot' | 'ai' = 'ot'): Promise<OtPatchData> {
  const response = await fetch(`/api/${domain === 'ai' ? 'ai' : 'ot'}-patch-day?` + new URLSearchParams({ month }), { signal });
  if (!response.ok) throw Error(response.status === 400 ? 'Período inválido.' : 'Não foi possível carregar o Patch Day.');
  return response.json();
}
