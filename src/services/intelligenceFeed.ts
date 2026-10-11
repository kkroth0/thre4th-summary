import type { StorySource } from '@/pages/newsletterView';
export interface IntelligenceFeedRow extends StorySource {
  description: string; severity?: string; kev?: boolean; ttps?: string[];
}
export async function fetchIntelligenceFeed(signal?: AbortSignal): Promise<IntelligenceFeedRow[]> {
  const response = await fetch('/api/newsletter', { signal, cache: 'no-store' });
  if (!response.ok) throw new Error(`Intelligence feed unavailable: ${response.status}`);
  const data = await response.json();
  if (!Array.isArray(data)) throw new Error('Invalid intelligence feed');
  return data;
}
