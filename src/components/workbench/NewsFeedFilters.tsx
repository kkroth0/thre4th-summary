import { useState } from 'react';
import { ChevronDown, Filter } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { TIME_RANGES, type TimeRange } from '@/pages/newsletterView';
import { cn } from '@/lib/utils';

interface NewsFeedFiltersProps {
  pt: boolean;
  activeCount: number;
  severity: string;
  onSeverityChange: (value: string) => void;
  period: TimeRange;
  onPeriodChange: (value: TimeRange) => void;
  relevance: boolean;
  onRelevanceChange: (value: boolean) => void;
  source: string;
  sources: string[];
  onSourceChange: (value: string) => void;
  kevOnly: boolean;
  onKevChange: (value: boolean) => void;
  profiles: { id: string; name: string }[];
  profileId: string;
  onProfileChange: (value: string) => void;
  hasContext: boolean;
  orgOnly: boolean;
  onOrgOnlyChange: (value: boolean) => void;
  onClear: () => void;
}

export function NewsFeedFilters(props: NewsFeedFiltersProps) {
  const [open, setOpen] = useState(false);
  const { pt } = props;
  const l = (a: string, b: string) => pt ? a : b;
  const selectClass = 'h-10 w-full min-w-0 rounded-md border border-input bg-background px-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring';
  return <Popover open={open} onOpenChange={setOpen}>
    <PopoverTrigger asChild>
      <Button variant="outline" size="sm" className={cn('h-9 shrink-0 gap-2 px-3 text-xs', props.activeCount > 0 && 'border-primary/40 bg-primary/10 text-primary')}>
        <Filter className="h-4 w-4" aria-hidden="true" />{l('Filtros', 'Filters')}
        {props.activeCount > 0 && <Badge variant="secondary" className="h-4 min-w-4 px-1 text-[10px] tabular-nums">{props.activeCount}</Badge>}
      </Button>
    </PopoverTrigger>
    <PopoverContent align="end" sideOffset={8} aria-label={l('Filtros de notícias', 'News filters')} className="max-h-[var(--radix-popover-content-available-height)] w-[calc(100vw-2rem)] overflow-y-auto rounded-xl bg-card p-0 shadow-xl sm:w-[420px]">
      <div className="flex items-center justify-between border-b px-4 py-3">
        <h2 className="text-sm font-semibold">{l('Filtrar publicações', 'Filter publications')}</h2>
        <Button variant="ghost" size="sm" disabled={!props.activeCount} className="h-7 px-2 text-xs text-muted-foreground" onClick={props.onClear}>{l('Limpar', 'Clear')}</Button>
      </div>
      <div className="space-y-4 p-4">
        <div className="grid grid-cols-1 gap-3 min-[380px]:grid-cols-2">
          <div className="space-y-1.5"><Label htmlFor="news-filter-severity" className="text-xs text-muted-foreground">{l('Severidade', 'Severity')}</Label>
            <select id="news-filter-severity" className={selectClass} value={props.severity} onChange={e => props.onSeverityChange(e.target.value)}>
              {[['all', l('Todas', 'All')], ['Critical', l('Crítica', 'Critical')], ['High', l('Alta', 'High')], ['Medium', l('Média', 'Medium')], ['Low', l('Baixa', 'Low')]].map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </select></div>
          <div className="space-y-1.5"><Label htmlFor="news-filter-period" className="text-xs text-muted-foreground">{l('Período', 'Period')}</Label>
            <select id="news-filter-period" className={selectClass} value={props.period} onChange={e => props.onPeriodChange(e.target.value as TimeRange)}>
              {TIME_RANGES.map(value => <option key={value} value={value}>{({ all: l('Todo o período', 'All time'), '24h': l('Últimas 24h', 'Last 24h'), '7d': l('Últimos 7 dias', 'Last 7 days'), '30d': l('Últimos 30 dias', 'Last 30 days') })[value]}</option>)}
            </select></div>
          <div className="space-y-1.5"><Label htmlFor="news-filter-source" className="text-xs text-muted-foreground">{l('Fonte', 'Source')}</Label>
            <select id="news-filter-source" className={selectClass} value={props.source} onChange={e => props.onSourceChange(e.target.value)}><option value="all">{l('Todas as fontes', 'All sources')}</option>{props.sources.map(source => <option key={source}>{source}</option>)}</select></div>
          <div className="space-y-1.5"><Label htmlFor="news-filter-sort" className="text-xs text-muted-foreground">{l('Ordenar por', 'Sort by')}</Label>
            <select id="news-filter-sort" className={selectClass} value={props.relevance ? 'relevance' : 'recent'} onChange={e => props.onRelevanceChange(e.target.value === 'relevance')}><option value="recent">{l('Mais recentes', 'Most recent')}</option><option value="relevance">{l('Mais relevantes', 'Most relevant')}</option></select></div>
        </div>
        <div className="flex items-center justify-between gap-3 rounded-lg border bg-background/50 px-3 py-2.5"><Label htmlFor="news-filter-kev" className="cursor-pointer text-xs font-medium">{l('Exploração confirmada (KEV)', 'Confirmed exploitation (KEV)')}</Label><Switch id="news-filter-kev" checked={props.kevOnly} onCheckedChange={props.onKevChange} /></div>
        {props.profiles.length > 0 && <details className="group border-t pt-3" open={props.profileId ? true : undefined}>
          <summary className="flex cursor-pointer list-none items-center justify-between gap-2 text-xs font-medium [&::-webkit-details-marker]:hidden">{l('Contexto da organização', 'Organization context')}<ChevronDown className="h-3.5 w-3.5 text-muted-foreground transition-transform group-open:rotate-180" /></summary>
          <div className="mt-3 space-y-3"><Label htmlFor="news-filter-profile" className="sr-only">{l('Perfil da organização', 'Organization profile')}</Label><select id="news-filter-profile" className={selectClass} value={props.profileId} onChange={e => props.onProfileChange(e.target.value)}><option value="">{l('Sem contexto', 'No context')}</option>{props.profiles.map(profile => <option key={profile.id} value={profile.id}>{profile.name}</option>)}</select>
            <div className="flex items-center justify-between gap-3"><Label htmlFor="news-filter-org-only" className="text-xs text-muted-foreground">{l('Mostrar só meu contexto', 'Show my context only')}</Label><Switch id="news-filter-org-only" checked={props.orgOnly} disabled={!props.hasContext} onCheckedChange={props.onOrgOnlyChange} /></div></div>
        </details>}
      </div>
      <div className="flex items-center justify-between border-t px-4 py-3"><span className="text-xs text-muted-foreground">{l('Filtros aplicados automaticamente', 'Filters apply automatically')}</span><Button size="sm" className="h-8 px-3 text-xs" onClick={() => setOpen(false)}>{l('Concluir', 'Done')}</Button></div>
    </PopoverContent>
  </Popover>;
}
