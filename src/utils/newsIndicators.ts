import type { StoryCard, StorySource } from '@/pages/newsletterView';
import { isPublicIpv4, isPublicIpv6 } from './iocExtract';

export interface NewsIndicator {
  value: string; kind: 'ip' | 'domain'; lastSeen: string;
  evidence: { storyId: string; source: StorySource; actors: { id: string; name: string }[]; malware: { id: string; name: string }[] }[];
}
export function collectNewsIndicators<T extends StorySource>(stories: StoryCard<T>[]): NewsIndicator[] {
  const result = new Map<string, NewsIndicator>();
  for (const story of stories) for (const source of story.sources) {
    for (const kind of ['ip', 'domain'] as const) {
      const values = kind === 'ip' ? source.iocs?.ips : source.iocs?.domains;
      for (const raw of values || []) {
        if (typeof raw !== 'string') continue;
        const value = raw.trim().toLowerCase();
        if (kind === 'ip' ? !isPublicIpv4(value) && !isPublicIpv6(value) : !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(value)) continue;
        const key = `${kind}:${value}`; const row = result.get(key) || { value, kind, lastSeen: source.pubDate, evidence: [] };
        if (!row.evidence.some(item => item.source.link === source.link)) row.evidence.push({ storyId: story.storyId, source, actors: source.actors || [], malware: source.malware || [] });
        if (Number.isFinite(Date.parse(source.pubDate)) && (!Number.isFinite(Date.parse(row.lastSeen)) || Date.parse(source.pubDate) > Date.parse(row.lastSeen))) row.lastSeen = source.pubDate;
        result.set(key, row);
      }
    }
  }
  return [...result.values()].sort((a, b) => String(b.lastSeen).localeCompare(String(a.lastSeen)) || a.value.localeCompare(b.value));
}
