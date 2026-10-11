import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from 'lucide-react';
import { Button } from '@/components/ui/button';

export function DataPager({ total, page, pageSize, onPage, onPageSize, pt, pageSizes = [20, 50, 100] }: {
  total: number; page: number; pageSize: number; onPage: (page: number) => void;
  onPageSize?: (size: number) => void; pt: boolean; pageSizes?: number[];
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const current = Math.min(page, pages);
  return <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 text-xs text-muted-foreground">
    <span className="tabular-nums">{total ? `${(current - 1) * pageSize + 1}–${Math.min(current * pageSize, total)}` : '0'} / {total} {pt ? 'resultados' : 'results'}</span>
    <div className="flex items-center gap-2">
      {onPageSize && <select aria-label={pt ? 'Resultados por página' : 'Results per page'} className="h-8 rounded-md border bg-background px-2" value={pageSize} onChange={event => onPageSize(Number(event.target.value))}>{pageSizes.map(size => <option key={size} value={size}>{size} / {pt ? 'página' : 'page'}</option>)}</select>}
      <span className="tabular-nums">{current} / {pages}</span>
      {[[ChevronsLeft, 1, current === 1, pt ? 'Primeira página' : 'First page'], [ChevronLeft, current - 1, current === 1, pt ? 'Página anterior' : 'Previous page'], [ChevronRight, current + 1, current === pages, pt ? 'Próxima página' : 'Next page'], [ChevronsRight, pages, current === pages, pt ? 'Última página' : 'Last page']].map(([Icon, target, disabled, label]) => {
        const Glyph = Icon as typeof ChevronLeft;
        return <Button key={String(label)} type="button" size="icon" variant="outline" className="h-8 w-8" disabled={Boolean(disabled)} aria-label={String(label)} onClick={() => onPage(Number(target))}><Glyph className="h-3.5 w-3.5" /></Button>;
      })}
    </div>
  </div>;
}
