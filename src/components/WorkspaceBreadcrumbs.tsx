import { Link } from 'react-router-dom';
import { ChevronRight } from 'lucide-react';

export interface WorkspaceBreadcrumbItem {
  label: string;
  to?: string;
}

export function WorkspaceBreadcrumbs({ items, pt }: { items: WorkspaceBreadcrumbItem[]; pt: boolean }) {
  return <nav aria-label={pt ? 'Trilha de navegação' : 'Breadcrumb'} className="min-w-0 flex-1">
    <ol className="flex min-w-0 items-center gap-2 text-sm font-normal sm:gap-3 sm:text-base">
      {items.map((item, index) => {
        const current = index === items.length - 1;
        return <li key={`${index}-${item.label}`} className={`flex min-w-0 items-center gap-2 sm:gap-3 ${current ? 'flex-1' : 'max-w-36 sm:max-w-64'}`}>
          {index > 0 && <ChevronRight aria-hidden="true" className="h-3.5 w-3.5 shrink-0 text-muted-foreground/70" />}
          {!current && item.to ? <Link to={item.to} className="truncate rounded-sm text-blue-700 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring dark:text-blue-300" title={item.label}>{item.label}</Link>
            : <span aria-current={current ? 'page' : undefined} className="truncate text-foreground/80" title={item.label}>{item.label}</span>}
        </li>;
      })}
    </ol>
  </nav>;
}
