import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ExternalLink, Search } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import type { RansomwareVictim } from '@/services/threatApi';
import { DataPager } from './DataPager';
import { RecordDrawer } from './RecordDrawer';

const victimDate = (iso: string | null | undefined, pt: boolean) => iso && Number.isFinite(Date.parse(iso))
  ? new Date(iso).toLocaleString(pt ? 'pt-BR' : 'en-US', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—';
const safeLink = (value: unknown): value is string => typeof value === 'string' && /^https?:\/\//i.test(value);
const options = (values: string[]) => [...new Set(values.filter(Boolean))].sort((a, b) => a.localeCompare(b));
const evidence = (victim: RansomwareVictim, pt: boolean) => [
  safeLink(victim.screenshot) && (pt ? 'Captura' : 'Screenshot'),
  victim.press?.length && (pt ? 'Imprensa' : 'Press'),
  victim.infostealer && 'Infostealer',
  safeLink(victim.permalink) && (pt ? 'Fonte' : 'Source'),
].filter(Boolean) as string[];
const pressLinks = (items?: unknown[]) => (items || []).flatMap(item => {
  if (safeLink(item)) return [{ url: item, title: item }];
  if (!item || typeof item !== 'object') return [];
  const record = item as Record<string, unknown>;
  const url = record.url || record.link || record.href;
  return safeLink(url) ? [{ url, title: typeof record.title === 'string' ? record.title : url }] : [];
});

export type RansomwareVictimFilters = { search: string; group: string; country: string; sector: string };
export function RansomwareVictimsTable({ victims, pt, filters, onFiltersChange }: {
  victims: RansomwareVictim[]; pt: boolean; filters: RansomwareVictimFilters; onFiltersChange: (next: RansomwareVictimFilters) => void;
}) {
  const { search, group, country, sector } = filters;
  const setSearch = (value: string) => onFiltersChange({ ...filters, search: value });
  const setGroup = (value: string) => onFiltersChange({ ...filters, group: value });
  const setCountry = (value: string) => onFiltersChange({ ...filters, country: value });
  const setSector = (value: string) => onFiltersChange({ ...filters, sector: value });
  const [page, setPage] = useState(1); const [size, setSize] = useState(20);
  const [selected, setSelected] = useState<RansomwareVictim | null>(null);
  const rows = useMemo(() => victims.filter(victim =>
    (!search.trim() || [victim.name, victim.group, victim.countryName, victim.country, victim.sector, victim.website, victim.source].some(value => value?.toLowerCase().includes(search.trim().toLowerCase())))
    && (group === 'all' || victim.group === group)
    && (country === 'all' || (victim.countryName || victim.country) === country)
    && (sector === 'all' || victim.sector === sector)), [victims, search, group, country, sector]);
  useEffect(() => { setPage(1); }, [search, group, country, sector, victims]);
  useEffect(() => { setSelected(null); }, [victims]);
  const current = Math.min(page, Math.max(1, Math.ceil(rows.length / size)));
  const active = Boolean(search || group !== 'all' || country !== 'all' || sector !== 'all');
  const clear = () => onFiltersChange({ search: '', group: 'all', country: 'all', sector: 'all' });
  const selects = [
    { label: pt ? 'Grupo' : 'Group', all: pt ? 'Todos os grupos' : 'All groups', value: group, onChange: setGroup, values: options(victims.map(victim => victim.group)) },
    { label: pt ? 'País' : 'Country', all: pt ? 'Todos os países' : 'All countries', value: country, onChange: setCountry, values: options(victims.map(victim => victim.countryName || victim.country)) },
    { label: pt ? 'Setor' : 'Sector', all: pt ? 'Todos os setores' : 'All sectors', value: sector, onChange: setSector, values: options(victims.map(victim => victim.sector)) },
  ];
  const articles = pressLinks(selected?.press);
  return <>
    <section className="intel-panel overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-3"><h2 className="text-sm font-semibold">{pt ? 'Vítimas reivindicadas' : 'Claimed victims'}</h2><span className="text-xs text-muted-foreground">{rows.length} / {victims.length} {pt ? 'registros no recorte' : 'records in selection'}</span></div>
      <div className="flex flex-wrap items-center gap-2 border-b p-4">
        <div className="relative w-full sm:min-w-56 sm:flex-1"><Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" /><Input aria-label={pt ? 'Buscar vítima' : 'Search victim'} placeholder={pt ? 'Vítima, domínio, grupo ou país…' : 'Victim, domain, group or country…'} value={search} onChange={event => setSearch(event.target.value)} className="pl-9" /></div>
        {selects.map(filter => <select key={filter.label} aria-label={filter.label} value={filter.value} onChange={event => filter.onChange(event.target.value)} className="h-9 min-w-[140px] max-w-full flex-1 rounded-md border bg-background px-3 text-xs sm:min-w-0 sm:max-w-44"><option value="all">{filter.all}</option>{options([...filter.values, ...(filter.value === 'all' ? [] : [filter.value])]).map(value => <option key={value} value={value}>{value}</option>)}</select>)}
        {active && <Button variant="ghost" size="sm" onClick={clear}>{pt ? 'Limpar filtros' : 'Clear filters'}</Button>}
      </div>
      <DataPager total={rows.length} page={current} pageSize={size} onPage={setPage} onPageSize={value => { setSize(value); setPage(1); }} pt={pt} />
      <div className="overflow-x-auto"><table className="intel-table min-w-[980px]">
        <thead><tr>{[pt ? 'Vítima / organização' : 'Victim / organization', pt ? 'Grupo' : 'Group', pt ? 'País' : 'Country', pt ? 'Setor' : 'Sector', pt ? 'Descoberta' : 'Discovered', pt ? 'Evidências' : 'Evidence', pt ? 'Fonte' : 'Source'].map(label => <th key={label}>{label}</th>)}</tr></thead>
        <tbody>{rows.slice((current - 1) * size, current * size).map((victim, index) => <tr key={`${victim.id || victim.name}-${victim.group}-${victim.discovered || victim.published}-${index}`}>
          <td className="max-w-72"><button type="button" className="break-words text-left font-medium hover:text-primary focus-visible:ring-2 focus-visible:ring-ring" onClick={() => setSelected(victim)}>{victim.name}</button><p className="mt-1 break-all text-xs text-muted-foreground">{victim.website || '—'}</p></td>
          <td className="max-w-40 break-words">{victim.actorId ? <Link className="text-primary hover:underline" to={'/atores?actor=' + encodeURIComponent(victim.actorId)}>{victim.group}</Link> : victim.group || '—'}</td><td>{victim.countryName || victim.country || '—'}</td><td className="max-w-44 text-muted-foreground">{victim.sector || '—'}</td>
          <td className="whitespace-nowrap text-xs text-muted-foreground">{victimDate(victim.discovered || victim.published, pt)}</td>
          <td><div className="flex max-w-48 flex-wrap gap-1">{evidence(victim, pt).length ? evidence(victim, pt).map(label => <span key={label} className="rounded border px-1.5 py-0.5 text-[10px] text-muted-foreground">{label}</span>) : <span className="text-muted-foreground">—</span>}</div></td>
          <td>{safeLink(victim.permalink) ? <a href={victim.permalink} target="_blank" rel="noopener noreferrer" aria-label={`${pt ? 'Abrir fonte de' : 'Open source for'} ${victim.name}`} className="inline-flex rounded p-1 text-muted-foreground hover:text-primary focus-visible:ring-2 focus-visible:ring-ring"><ExternalLink className="h-3.5 w-3.5" /></a> : <span className="text-muted-foreground">—</span>}</td>
        </tr>)}</tbody>
      </table>{!rows.length && <div className="p-8 text-center"><p className="text-sm text-muted-foreground">{pt ? 'Nenhuma vítima neste filtro.' : 'No victims match these filters.'}</p>{active && <Button variant="outline" size="sm" className="mt-3" onClick={clear}>{pt ? 'Limpar filtros' : 'Clear filters'}</Button>}</div>}</div>
      <DataPager total={rows.length} page={current} pageSize={size} onPage={setPage} pt={pt} />
    </section>
    <RecordDrawer open={Boolean(selected)} onClose={() => setSelected(null)} title={selected?.name || ''} description={pt ? 'Ransomware · reivindicação da fonte' : 'Ransomware · source claim'}>
      {selected && <>
        <dl className="grid grid-cols-2 gap-x-6 gap-y-4 text-sm">{[
          [pt ? 'Grupo' : 'Group', selected.group], [pt ? 'País' : 'Country', selected.countryName || selected.country],
          [pt ? 'Setor' : 'Sector', selected.sector], [pt ? 'Domínio' : 'Domain', selected.website],
          [pt ? 'Descoberta' : 'Discovered', victimDate(selected.discovered, pt)], [pt ? 'Publicação' : 'Published', victimDate(selected.published, pt)],
        ].map(([label, value]) => <div key={label} className="min-w-0"><dt className="intel-eyebrow">{label}</dt><dd className="mt-1 break-words">{value || '—'}</dd></div>)}</dl>
        <section><h3 className="intel-eyebrow">{pt ? 'Descrição da fonte' : 'Source description'}</h3><p className="mt-3 whitespace-pre-wrap break-words text-sm leading-6 text-muted-foreground">{selected.description || (pt ? 'A fonte não forneceu uma descrição.' : 'The source did not provide a description.')}</p></section>
        <section><h3 className="intel-eyebrow">{pt ? 'Evidências e referências' : 'Evidence and references'}</h3><p className="mt-2 text-xs text-muted-foreground">{selected.source || '—'}</p><div className="mt-3 flex flex-wrap gap-2">{[[selected.permalink, pt ? 'Registro da fonte' : 'Source record'], [selected.screenshot, pt ? 'Abrir captura' : 'Open screenshot'], [selected.ctiFyi?.permalink, 'CTI.fyi']].map(([url, label]) => safeLink(url) && <Button key={label} asChild variant="outline" size="sm"><a href={url} target="_blank" rel="noopener noreferrer">{label}<ExternalLink className="ml-2 h-3.5 w-3.5" /></a></Button>)}</div>
          {articles.length > 0 && <ul className="mt-4 space-y-2">{articles.map((article, index) => <li key={`${article.url}-${index}`}><a href={article.url} target="_blank" rel="noopener noreferrer" className="break-words text-sm text-primary hover:underline">{article.title}<ExternalLink className="ml-1 inline h-3 w-3" /></a></li>)}</ul>}
          {selected.press?.length && !articles.length ? <p className="mt-3 text-xs text-muted-foreground">{pt ? 'A fonte indica cobertura de imprensa, mas não forneceu links válidos.' : 'The source indicates press coverage but provided no valid links.'}</p> : null}
          {!safeLink(selected.permalink) && !safeLink(selected.screenshot) && !selected.press?.length && !selected.infostealer && <p className="mt-3 text-xs text-muted-foreground">{pt ? 'Sem referências adicionais neste registro.' : 'No additional references in this record.'}</p>}
        </section>
        {Boolean(selected.infostealer) && <section><h3 className="intel-eyebrow">{pt ? 'Infostealer · dados da fonte' : 'Infostealer · source data'}</h3><pre className="mt-3 max-h-48 overflow-auto rounded-md border p-3 text-xs">{JSON.stringify(selected.infostealer, null, 2)}</pre></section>}
        <p className="border-t pt-4 text-xs leading-5 text-muted-foreground">{pt ? 'Este registro é uma reivindicação divulgada pela fonte, não uma confirmação independente do incidente.' : 'This record is a source-reported claim, not independent confirmation of the incident.'}</p>
      </>}
    </RecordDrawer>
  </>;
}
