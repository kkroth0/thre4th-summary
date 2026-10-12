import { domainRequest } from './domainIntelligence';
export interface ActorActivity { ips: number; domains: number; hashes: number; posts: number; latest: string | null }
export interface ActorIndicator { value: string; type: 'ips' | 'domains' | 'hashes'; evidence: { title: string; source: string; link: string; pubDate: string; actors: string[]; malware: string[] }[] }
export interface ActorEvidence { actorId: string; days: number; counts: ActorActivity; latest: string | null; indicators: ActorIndicator[]; publications: { title: string; source: string; link: string; pubDate: string; storyId: string | null }[] }
export async function fetchActorActivity(signal: AbortSignal) {
  const data = await domainRequest<{ activity: Record<string, ActorActivity> }>('/api/actors/activity', signal);
  if (!data.activity || typeof data.activity !== 'object') throw new Error('Invalid activity response'); return data.activity;
}
export async function fetchActorEvidence(id: string, days: number, signal: AbortSignal) {
  const data = await domainRequest<ActorEvidence>(`/api/actors/${encodeURIComponent(id)}/evidence?days=${days}`, signal);
  if (!data.counts || !Array.isArray(data.indicators) || !Array.isArray(data.publications)) throw new Error('Invalid evidence response'); return data;
}
