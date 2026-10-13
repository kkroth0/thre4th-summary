import type { WeeklyNews } from '@/types/weekly-report';
import { NewsTimestamp } from './NewsTimestamp';

export function WeeklyNewsChoices({ items, selected, limit, onToggle, disabled, pt }: {
  items: WeeklyNews[]; selected: string[]; limit: number; onToggle: (id: string) => void; disabled: boolean; pt: boolean;
}) {
  return <section aria-label={pt ? 'Notícias sugeridas para a semana' : 'Suggested weekly news'}>
    <p className="mb-3 text-sm text-muted-foreground">{pt ? `Até 25 sugestões por relevância. Escolha no máximo ${limit}; suas escolhas ficam salvas durante as atualizações.` : `Up to 25 suggestions by relevance. Choose at most ${limit}; updates preserve your selections.`}</p>
    <div className="divide-y overflow-hidden rounded-lg border">{items.map((item, index) => {
      const checked = selected.includes(item.id);
      return <article key={item.id} className={checked ? 'bg-primary/5 p-4' : 'p-4'}>
        <label className="flex cursor-pointer items-start gap-3"><input type="checkbox" className="mt-1 h-4 w-4 accent-primary" checked={checked} disabled={disabled || (!checked && selected.length >= limit)} onChange={() => onToggle(item.id)} /><span className="min-w-0"><span className="font-mono text-xs text-muted-foreground">{String(index + 1).padStart(2, '0')} · {pt ? 'Relevância' : 'Relevance'} {item.score}</span><span className="mt-1 block text-sm font-semibold leading-6">{item.title}</span><NewsTimestamp item={{ ...item, pubDate: item.published }} pt={pt} className="mt-1 block text-xs text-muted-foreground" /></span></label>
        <details className="ml-7 mt-2 text-xs"><summary className="cursor-pointer text-primary">{pt ? 'Resumo e fontes' : 'Summary and sources'} · {item.sources.length}</summary><p className="mt-2 leading-6 text-muted-foreground">{item.summary}</p><div className="mt-2 space-y-1">{item.sources.map(source => <a key={source.link} href={source.link} target="_blank" rel="noreferrer" className="block text-primary hover:underline">{source.source}: {source.title}</a>)}</div></details>
      </article>;
    })}{!items.length && <p className="p-6 text-sm text-muted-foreground">{pt ? 'Nenhuma notícia disponível nesta semana.' : 'No news available this week.'}</p>}</div>
  </section>;
}
