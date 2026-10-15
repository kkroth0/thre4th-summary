import { useEffect, useState } from 'react';
import { ExternalLink, Loader2, Plus, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useLanguage } from '@/contexts/LanguageContext';
import { fetchWatchSuggestions, reviewWatchSuggestion, type WatchTermSuggestion } from '@/services/threatApi';
import { toast } from 'sonner';

export function WatchSuggestions({ profileId, onAccepted }: { profileId: string; onAccepted: () => Promise<unknown> }) {
  const { language } = useLanguage();
  const pt = language === 'pt';
  const [items, setItems] = useState<WatchTermSuggestion[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const [reviewing, setReviewing] = useState('');
  useEffect(() => {
    let active = true;
    setItems([]); setError(false); setLoading(!!profileId);
    if (profileId) fetchWatchSuggestions(profileId).then(data => { if (active) setItems(data.suggestions); }).catch(() => { if (active) setError(true); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [profileId]);
  if (!profileId) return null;
  const review = async (item: WatchTermSuggestion, decision: 'accepted' | 'dismissed') => {
    setReviewing(item.id);
    try {
      await reviewWatchSuggestion(profileId, item.id, decision);
      if (decision === 'accepted') await onAccepted();
      setItems(current => current.filter(row => row.id !== item.id));
      toast.success(decision === 'accepted' ? (pt ? 'Marca adicionada à vigilância do perfil' : 'Brand added to profile monitoring') : (pt ? 'Sugestão dispensada' : 'Suggestion dismissed'));
    } catch (cause) { toast.error(cause instanceof Error ? cause.message : (pt ? 'Falha ao revisar sugestão' : 'Could not review suggestion')); }
    finally { setReviewing(''); }
  };
  return <section className="intel-panel space-y-3 p-4" aria-label={pt ? 'Sugestões de vigilância das notícias' : 'Monitoring suggestions from news'}>
    <h3 className="text-sm font-semibold">{pt ? 'Sugestões das notícias' : 'Suggestions from news'}</h3>
    <p className="text-xs text-muted-foreground">{pt ? 'Marcas citadas em notícias de phishing relacionadas ao contexto do perfil nos últimos 90 dias. Revise as evidências antes de adicionar à vigilância. Aceitar usa o limite de oito marcas do perfil.' : 'Brands mentioned in phishing news related to this profile over the last 90 days. Review the evidence before monitoring. Acceptance uses the profile’s eight-brand allowance.'}</p>
    {loading && <Loader2 className="h-4 w-4 animate-spin" aria-label={pt ? 'Carregando sugestões' : 'Loading suggestions'} />}
    {error && <p role="alert" className="text-xs text-destructive">{pt ? 'Não foi possível carregar as sugestões. Atualize a página para tentar novamente.' : 'Could not load suggestions. Refresh the page to retry.'}</p>}
    {!loading && !error && !items.length && <p className="text-xs text-muted-foreground">{pt ? 'Nenhuma sugestão nova com evidência para este perfil.' : 'No new evidenced suggestions for this profile.'}</p>}
    <div className="grid gap-3 lg:grid-cols-2">{items.map(item => <article key={item.id} className="min-w-0 space-y-2 rounded-lg border border-border p-3">
      <div className="flex flex-wrap items-center justify-between gap-2"><span className="font-mono text-sm font-semibold">{item.term}</span><span className="text-[11px] text-muted-foreground">{item.events} {pt ? 'eventos' : 'events'} · {item.sources} {pt ? 'fontes' : 'sources'}</span></div>
      <p className="text-xs text-muted-foreground">{item.reasons.join(' · ')}</p>
      <details className="text-xs"><summary className="cursor-pointer">{pt ? 'Ver publicações e padrões observados' : 'View publications and observed patterns'}</summary><ul className="mt-2 space-y-2">{item.publications.map(row => <li key={row.link} className="space-y-1"><a href={row.link} target="_blank" rel="noopener noreferrer" className="inline-flex gap-1 text-primary hover:underline">{row.title}<ExternalLink className="h-3 w-3 shrink-0" /></a><p className="text-muted-foreground">{row.techniques.join(' · ')}{row.campaign ? ` · ${row.campaign}` : ''}</p>{row.patterns.map(pattern => <p key={pattern.hostname + pattern.path} className="break-all font-mono text-[11px] text-muted-foreground">{pattern.hostname.replace(/\./g, '[.]')}{pattern.path}</p>)}</li>)}</ul></details>
      <div className="flex gap-2"><Button size="sm" className="h-7 gap-1 text-xs" disabled={!!reviewing} onClick={() => review(item, 'accepted')}><Plus className="h-3 w-3" />{pt ? 'Adicionar à vigilância' : 'Add to monitoring'}</Button><Button variant="ghost" size="sm" className="h-7 gap-1 text-xs" disabled={!!reviewing} onClick={() => review(item, 'dismissed')}><X className="h-3 w-3" />{pt ? 'Dispensar sugestão' : 'Dismiss suggestion'}</Button></div>
    </article>)}</div>
  </section>;
}
