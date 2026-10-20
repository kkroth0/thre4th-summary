export type HuntingPeriod = 'day' | 'week' | 'month';
export type HuntingTechnique = { id: string; name: string; tactics: string[]; url: string };
export type HuntingQuery = { id: string; title: string; description: string; query: string; platform: 'sentinel' | 'defender' | 'unknown'; tables: string[]; techniques: string[]; cves: string[]; provenance: { repo: string; path?: string; revision?: string; license: string; url: string }[] };
export type HuntingHypothesis = {
  id: string; queryId: string; title: string; hypothesis: string; reason: string; matchKind: string; matchTerms: string[];
  techniques: HuntingTechnique[]; query: HuntingQuery; aiUsed: boolean; feedback: 'yes' | 'no' | null;
  sources: { id: string; title: string; url: string; publishedAt: string; source: string; storyId?: string; kind: string }[];
  actors: { id: string; name: string }[]; malware: { id: string; name: string }[]; cves: string[];
  signals: { kev: boolean; epss: number | null; cvss: number | null };
};
export type HuntingOverview = {
  period: HuntingPeriod; window: { from: string; to: string }; generatedAt: string; aiStatus: 'processing' | 'ready' | 'unavailable' | 'limited' | 'disabled';
  publications: number; hypotheses: HuntingHypothesis[]; evaluated: number; techniques: HuntingTechnique[];
  library: { updatedAt: string | null; queries: number; sources: { repo: string; revision: string; license: string }[] };
};
export async function fetchHunting(period: HuntingPeriod, signal?: AbortSignal): Promise<HuntingOverview> {
  const response = await fetch('/api/hunting/overview?period=' + period, { signal, cache: 'no-store' });
  if (!response.ok) throw new Error('Não foi possível carregar as caças.');
  return response.json();
}
export async function sendHuntingFeedback(queryId: string, vote: 'yes' | 'no') {
  const response = await fetch('/api/hunting/feedback', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ queryId, vote }) });
  if (!response.ok) throw new Error('Não foi possível salvar seu retorno.');
  return response.json();
}
