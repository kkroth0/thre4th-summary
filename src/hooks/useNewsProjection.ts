import { useEffect, useRef, useState } from 'react';
import { projectNews, type ProjectionItem, type NewsProjectionOptions } from '../utils/newsProjection';
import type { StoryCard } from '../pages/newsletterView';

export function useNewsProjection<T extends ProjectionItem>(items: T[], options: NewsProjectionOptions, scope: string | null) {
  const worker = useRef<Worker | null>(null), previous = useRef<T[] | null>(null), serial = useRef(0);
  const [result, setResult] = useState<{ scope: string | null; id: number; cards: StoryCard<T>[]; counts: Record<string, number> }>({ scope, id: 0, cards: [], counts: {} });
  const [pending, setPending] = useState(false);
  useEffect(() => {
    let current: Worker;
    try { current = new Worker(new URL('../workers/newsProjection.worker.ts', import.meta.url), { type: 'module' }); }
    catch { return; }
    worker.current = current;
    return () => { worker.current = null; previous.current = null; current.terminate(); };
  }, []);
  useEffect(() => {
    const current = worker.current;
    if (!current) { setResult({ ...projectNews(items, options), scope, id: ++serial.current }); return; }
    const id = ++serial.current;
    setPending(true);
    const fallback = () => {
      if (id !== serial.current) return;
      setResult({ ...projectNews(items, options), scope, id }); setPending(false);
    };
    current.onmessage = ({ data }) => {
      if (data.id !== serial.current) return;
      if (data.error) { fallback(); return; }
      setResult({ ...data.data, scope, id }); setPending(false);
    };
    current.onerror = fallback;
    try {
      if (previous.current !== items) { current.postMessage({ type: 'snapshot', items }); previous.current = items; }
      current.postMessage({ type: 'project', id, options });
    } catch { fallback(); }
  }, [items, options, scope]);
  return { cards: result.scope === scope ? result.cards : [], counts: result.scope === scope ? result.counts : {}, pending };
}
