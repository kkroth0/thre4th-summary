import type { ReactNode } from 'react';
import { ChevronLeft, ChevronRight, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { otCurrentMonth, shiftPatchMonth } from '@/services/otPatchApi';

export function PatchDayToolbar({ month, onMonthChange, onRefresh, loading, pt, actions, min = '2000-01', availableMonths, latest = otCurrentMonth() }: {
  month: string; onMonthChange: (month: string) => void; onRefresh: () => void; loading: boolean; pt: boolean; actions: ReactNode; min?: string; availableMonths?: string[]; latest?: string;
}) {
  const choices = availableMonths ? [...new Set(availableMonths)].sort() : null;
  const previous = choices ? choices.filter(m => m < month).at(-1) : month > min ? shiftPatchMonth(month, -1) : undefined;
  const next = choices ? choices.find(m => m > month) : month < latest ? shiftPatchMonth(month, 1) : undefined;
  const newest = choices?.at(-1) || latest;
  return <section className="mb-5 flex flex-col gap-4 rounded-xl border bg-card p-4 lg:flex-row lg:items-center lg:justify-between" aria-label={pt ? 'Controle mensal' : 'Monthly control'}>
    <div className="min-w-0"><span className="mb-2 block text-xs font-semibold uppercase tracking-wide text-muted-foreground">{pt ? 'Mês do relatório' : 'Report month'}</span>
      <div className="flex flex-wrap items-center gap-2"><Button size="icon" variant="outline" aria-label={pt ? 'Mês anterior' : 'Previous month'} disabled={!previous} onClick={() => previous && onMonthChange(previous)}><ChevronLeft className="h-4 w-4" /></Button>
        {choices ? <select className="flex h-10 w-[180px] rounded-md border border-input bg-background px-3 text-sm font-semibold" aria-label={pt ? 'Mês do Patch Day' : 'Patch Day month'} value={month} disabled={!choices.length} onChange={e => onMonthChange(e.target.value)}>{!choices.length && <option value="">{pt ? 'Carregando…' : 'Loading…'}</option>}{choices.map(m => <option key={m} value={m}>{new Date(m + '-15T12:00:00Z').toLocaleDateString(pt ? 'pt-BR' : 'en-US', { month: 'long', year: 'numeric', timeZone: 'UTC' })}</option>)}</select>
          : <Input className="w-[180px] font-semibold" aria-label={pt ? 'Mês do Patch Day' : 'Patch Day month'} type="month" min={min} max={latest} value={month} onChange={e => { if (/^20\d{2}-(0[1-9]|1[0-2])$/.test(e.target.value) && e.target.value >= min && e.target.value <= latest) onMonthChange(e.target.value); }} />}
        <Button size="icon" variant="outline" aria-label={pt ? 'Próximo mês' : 'Next month'} disabled={!next} onClick={() => next && onMonthChange(next)}><ChevronRight className="h-4 w-4" /></Button>
        <Button variant="ghost" size="sm" disabled={!month || month === newest} onClick={() => onMonthChange(newest)}>{pt ? 'Mês atual' : 'Current month'}</Button></div></div>
    <div className="flex flex-wrap items-center gap-2 lg:pt-5"><Button className="whitespace-nowrap" variant="outline" onClick={onRefresh} disabled={loading}><RefreshCw className="h-4 w-4" />{pt ? 'Atualizar dados' : 'Refresh data'}</Button>{actions}<span className="text-xs text-muted-foreground">{month && `${month.slice(5)}/${month.slice(0, 4)}`}</span></div>
  </section>;
}

export function PatchDayTabs({ value, onChange, tabs, label }: { value: string; onChange: (value: string) => void; tabs: { id: string; label: string }[]; label: string }) {
  return <div className="mb-4 flex flex-wrap gap-2 border-b pb-3" role="tablist" aria-label={label}>{tabs.map(tab => <Button key={tab.id} role="tab" aria-selected={value === tab.id} variant={value === tab.id ? 'default' : 'ghost'} size="sm" onClick={() => onChange(tab.id)}>{tab.label}</Button>)}</div>;
}
