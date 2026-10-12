import assert from 'node:assert/strict';
import test from 'node:test';
import { collectNewsIndicators } from './newsIndicators';
import type { StoryCard, StorySource } from '@/pages/newsletterView';

test('news IOC evidence stays with its own publication instead of inheriting story attribution', () => {
  const sources: StorySource[] = [
    { title: 'First', source: 'Research', link: 'https://example.com/first', pubDate: '2026-10-01', actors: [{ id: 'G1', name: 'Actor' }], malware: [{ id: 'M1', name: 'Family' }], iocs: { ips: ['8.8.8.8', '8.8.8.8', '127.0.0.1'], domains: ['EXAMPLE.NET'] } },
    { title: 'Second', source: 'News', link: 'https://example.com/second', pubDate: '2026-10-02', iocs: { ips: ['8.8.8.8'], domains: ['bad domain', 'example.net'] } },
  ];
  const story = { storyId: 'event', actors: [{ id: 'G1', name: 'Actor' }], sources } as StoryCard;
  const rows = collectNewsIndicators([story]); assert.equal(rows.length, 2);
  const ip = rows.find(row => row.kind === 'ip')!; assert.equal(ip.evidence.length, 2); assert.equal(ip.lastSeen, '2026-10-02');
  assert.equal(ip.evidence[0].actors.length, 1); assert.equal(ip.evidence[1].actors.length, 0); assert.equal(ip.evidence[1].malware.length, 0);
  assert.equal(rows.find(row => row.kind === 'domain')?.value, 'example.net');
});
