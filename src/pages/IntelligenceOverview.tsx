import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ArrowUpRight, RefreshCw, Activity, Layers, Radio, ShieldAlert } from 'lucide-react';
import { PageLayout } from '@/components/PageLayout';
import { PageHeader } from '@/components/PageHeader';
import { Button } from '@/components/ui/button';
import { useLanguage } from '@/contexts/LanguageContext';
import { useAuth } from '@/contexts/AuthContext';
import { useNewsMonitoring } from '@/hooks/useNewsMonitoring';
import { newsMonitoringCacheKey } from '@/utils/newsVendorSelection';
import { fetchIntelligenceFeed } from '@/services/intelligenceFeed';
import { groupAdvisoriesIntoStories, countByCategory } from './newsletterView';

export default function IntelligenceOverview() {
  const { language } = useLanguage(); const pt = language === 'pt';
  const { auth } = useAuth();
  const monitoring = useNewsMonitoring();
  const selection = monitoring.data ? newsMonitoringCacheKey(auth.login || '', monitoring.data.preferences) : null;
  const feed = useQuery({ queryKey: ['intelligence-overview', selection], queryFn: ({ signal }) => fetchIntelligenceFeed(signal), enabled: Boolean(selection) && !monitoring.isError, staleTime: 0 });
  const failed = monitoring.isError || feed.isError;
  const waiting = !failed && (monitoring.isPending || feed.isPending);
  const rows = useMemo(() => feed.data || [], [feed.data]);
  const stories = useMemo(() => groupAdvisoriesIntoStories(rows, { pt }), [rows, pt]);
  const categories = useMemo(() => Object.entries(countByCategory(stories)).sort((a, b) => b[1] - a[1]), [stories]);
  const sources = new Set(rows.map(row => row.source)).size;
  const days = Array.from({ length: 7 }, (_, index) => {
    const date = new Date(); date.setHours(0, 0, 0, 0); date.setDate(date.getDate() - 6 + index);
    const end = new Date(date); end.setDate(end.getDate() + 1);
    return { label: date.toLocaleDateString(pt ? 'pt-BR' : 'en-US', { day: '2-digit', month: 'short' }), count: rows.filter(row => { const time = Date.parse(row.pubDate); return time >= date.getTime() && time < end.getTime(); }).length };
  });
  const max = Math.max(1, ...days.map(day => day.count));
  return <PageLayout width="max-w-[1600px]">
    <PageHeader title={pt ? 'Visão geral' : 'Overview'} subtitle={pt ? 'Acompanhe eventos, cobertura das fontes e prioridades do seu monitoramento.' : 'Track events, source coverage and priorities in your monitoring.'} actions={<Button variant="outline" size="sm" disabled={feed.isFetching || monitoring.isPending} onClick={async () => { await monitoring.refetch(); await feed.refetch(); }}><RefreshCw className={`mr-2 h-3.5 w-3.5 ${feed.isFetching ? 'animate-spin' : ''}`} />{pt ? 'Atualizar' : 'Refresh'}</Button>} />
    {waiting ? <p role="status" className="intel-panel p-10 text-center text-sm text-muted-foreground">{pt ? 'Carregando inteligência…' : 'Loading intelligence…'}</p> : failed ? <p role="alert" className="intel-panel p-6 text-sm text-destructive">{pt ? 'Não foi possível carregar o feed. Tente atualizar.' : 'Could not load the feed. Try refreshing.'}</p> : <div className="space-y-6">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">{[
        { label: pt ? 'Eventos no feed' : 'Events in feed', value: stories.length, icon: Activity, note: pt ? `${rows.length} publicações coletadas` : `${rows.length} collected publications` },
        { label: pt ? 'Cobertura correlacionada' : 'Correlated coverage', value: stories.filter(row => row.sources.length > 1).length, icon: Layers, note: pt ? 'Grupos com várias publicações' : 'Groups with multiple publications' },
        { label: pt ? 'Fontes no recorte' : 'Sources in selection', value: sources, icon: Radio, note: pt ? 'Veículos com publicações no feed' : 'Publishers represented in the feed' },
        { label: pt ? 'Eventos com KEV' : 'Events with KEV', value: stories.filter(row => row.sources.some(source => source.kev)).length, icon: ShieldAlert, note: pt ? 'Vulnerabilidades com exploração conhecida' : 'Known exploited vulnerabilities' },
      ].map(item => <div key={item.label} className="intel-panel p-5"><div className="flex items-center justify-between text-xs text-muted-foreground"><span>{item.label}</span><item.icon className="h-4 w-4" /></div><p className="my-3 text-3xl font-semibold tabular-nums">{item.value}</p><p className="text-xs text-muted-foreground">{item.note}</p></div>)}</div>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <section className="intel-panel p-5"><h2 className="text-base font-semibold">{pt ? 'Atividade recente' : 'Recent activity'}</h2><p className="mt-1 text-xs text-muted-foreground">{pt ? 'Publicações dos últimos 7 dias presentes no feed atual.' : 'Publications from the last 7 days present in the current feed.'}</p><div className="mt-6 flex h-40 items-end gap-3 sm:gap-6">{days.map(day => <div key={day.label} className="flex h-full min-w-0 flex-1 flex-col justify-end text-center"><span className="mb-2 text-[11px] tabular-nums text-muted-foreground">{day.count}</span><div className="mx-auto w-full max-w-16 rounded-t bg-primary/75" style={{ height: `${Math.max(2, day.count / max * 110)}px` }} aria-label={`${day.label}: ${day.count}`} /><span className="mt-3 truncate text-[10px] text-muted-foreground">{day.label}</span></div>)}</div></section>
        <section className="intel-panel p-5"><h2 className="text-base font-semibold">{pt ? 'Panorama de ameaças' : 'Threat landscape'}</h2><div className="mt-4 space-y-4">{categories.slice(0, 6).map(([name, value]) => <div key={name}><div className="mb-2 flex justify-between text-xs"><span>{name}</span><span className="tabular-nums text-muted-foreground">{value}</span></div><div className="h-1 rounded-full bg-muted"><div className="h-1 rounded-full bg-primary/70" style={{ width: `${value / Math.max(1, stories.length) * 100}%` }} /></div></div>)}{!categories.length && <p className="text-sm text-muted-foreground">{pt ? 'Sem publicações neste recorte.' : 'No publications in this selection.'}</p>}</div></section>
      </div>
      <section className="intel-panel overflow-hidden"><div className="flex items-center justify-between border-b px-5 py-4"><h2 className="text-base font-semibold">{pt ? 'Eventos recentes' : 'Recent events'}</h2><Link to="/newsletter" className="inline-flex items-center gap-1 text-xs text-primary">{pt ? 'Abrir feed' : 'Open feed'}<ArrowUpRight className="h-3.5 w-3.5" /></Link></div><div className="overflow-x-auto"><table className="intel-table min-w-[620px]"><thead><tr><th>{pt ? 'Evento' : 'Event'}</th><th>{pt ? 'Categoria' : 'Category'}</th><th>{pt ? 'Publicações' : 'Publications'}</th><th>{pt ? 'Atualizado' : 'Updated'}</th></tr></thead><tbody>{stories.slice(0, 8).map(row => <tr key={row.storyId}><td><Link to={`/newsletter?story=${encodeURIComponent(row.storyId)}`} className="font-medium hover:text-primary">{row.title}</Link></td><td className="whitespace-nowrap">{row.primaryCategory || '—'}</td><td className="tabular-nums">{row.sources.length}</td><td className="whitespace-nowrap text-xs">{Number.isFinite(Date.parse(row.lastSeen)) ? new Date(row.lastSeen).toLocaleDateString(pt ? 'pt-BR' : 'en-US') : '—'}</td></tr>)}</tbody></table>{!stories.length && <p className="p-8 text-center text-sm text-muted-foreground">{pt ? 'Escolha fornecedores nas configurações ou aguarde a próxima coleta.' : 'Choose vendors in settings or wait for the next collection.'}</p>}</div></section>
      <p className="text-xs text-muted-foreground">{pt ? 'Os números refletem o feed autorizado para sua conta e seleção de fornecedores.' : 'Counts reflect the feed authorized for your account and vendor selection.'}</p>
    </div>}
  </PageLayout>;
}
