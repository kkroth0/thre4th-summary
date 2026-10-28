import type { NewsMention } from './threatApi';

export interface BulkEvidence {
  provider: string; source?: string; title: string; link: string; published: string;
  collectedAt: string; confidence: number | null;
  reputation: Record<string, unknown> | null;
  entities: { kind: 'actor' | 'malware' | 'cve'; id: string; name: string; relation: string }[];
}
export interface BulkContext {
  publications: NewsMention[];
  evidence: BulkEvidence[];
  errors: string[];
  localSnapshot?: { asOf: string; axurImportStatus: string; axurImportAt: string | null; axurRecordsTraversed: number; axurEvidence: number };
}

/** Read existing evidence only; no article extraction or extra provider calls. */
export async function fetchBulkContext(query: string): Promise<BulkContext> {
  const result: BulkContext = { publications: [], evidence: [], errors: [] };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000);
  const read = async (path: string) => {
    const response = await fetch(path, { signal: controller.signal, credentials: 'same-origin' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
  };
  try {
    await Promise.all([
      (async () => {
        try { result.publications = (await read(`/api/news/mentions?ioc=${encodeURIComponent(query)}`)).mentions || []; }
        catch { result.errors.push('Publicações: consulta indisponível ou tempo limite atingido.'); }
      })(),
      (async () => {
        try {
          let offset = 0;
          while (true) {
            const response = await fetch(`/api/intelligence/ioc?${new URLSearchParams({ value: query, offset: String(offset), size: '100' })}`, { signal: controller.signal, credentials: 'same-origin' });
            if (response.status === 404 && offset === 0) break;
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const page = await response.json();
            result.evidence.push(...page.evidence);
            offset += page.evidence.length;
            if (offset >= page.total) break;
            if (!page.evidence.length) throw new Error('Incomplete evidence page');
          }
        } catch { result.errors.push('Base correlacionada: consulta incompleta ou indisponível.'); }
      })(),
    ]);
    const known = new Set(result.publications.map(item => item.link));
    for (const item of result.evidence) if (item.provider === 'news' && item.link && !known.has(item.link)) {
      known.add(item.link);
      result.publications.push({ storyId: '', title: item.title, source: item.source || 'Notícias', link: item.link, pubDate: item.published, actors: item.entities.filter(entity => entity.kind === 'actor').map(entity => entity.name), categories: [] });
    }
    return result;
  } finally { clearTimeout(timer); }
}
