import { useEffect, useMemo, useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { Download, ExternalLink, Factory, RefreshCw, Search, ShieldCheck, Wrench } from 'lucide-react';
import { PageLayout } from '@/components/PageLayout';
import { MetricCard } from '@/components/MetricCard';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useLanguage } from '@/contexts/LanguageContext';
import { useToast } from '@/hooks/use-toast';
import { fetchOtPatch, otCurrentMonth, type OtPatchData, type OtPatchRow } from '@/services/otPatchApi';

const PAGE_SIZE = 25;
const dateLabel = (date: string, pt: boolean) => date ? new Date(date).toLocaleDateString(pt ? 'pt-BR' : 'en-US', { timeZone: 'UTC' }) : '—';
export default function OtPatchDay() {
  const { language } = useLanguage(), pt = language === 'pt', { toast } = useToast();
  const [params, setParams] = useSearchParams();
  const candidateMonth = params.get('month') || '';
  const month = /^20\d{2}-(0[1-9]|1[0-2])$/.test(candidateMonth) ? candidateMonth : otCurrentMonth();
  const [data, setData] = useState<OtPatchData | null>(null), [error, setError] = useState(''), [loading, setLoading] = useState(true);
  const [reload, setReload] = useState(0), [tab, setTab] = useState('advisories'), [vendor, setVendor] = useState('all'), [scope, setScope] = useState('all');
  const [search, setSearch] = useState(''), [patch, setPatch] = useState('all'), [page, setPage] = useState(1), [exporting, setExporting] = useState(false);
  const patchLabel = (value: string) => value === 'available' ? (pt ? 'Correção publicada' : 'Fix published') : value === 'mitigation' ? (pt ? 'Mitigação' : 'Mitigation') : (pt ? 'Correção não confirmada' : 'Fix unconfirmed');
  useEffect(() => {
    const controller = new AbortController(); let timer: ReturnType<typeof setTimeout>;
    setLoading(true); setData(null); setError('');
    const load = async () => {
      try {
        const next = await fetchOtPatch(month, controller.signal);
        if (controller.signal.aborted) return;
        setData(next); setError('');
        if (!next.status.initialized || next.status.running || next.status.pending > next.status.failed) timer = setTimeout(load, 12000);
      } catch (e) { if (!controller.signal.aborted) setError((e as Error).message); }
      finally { if (!controller.signal.aborted) setLoading(false); }
    };
    void load();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [month, reload]);
  useEffect(() => setPage(1), [month, vendor, scope, search, patch]);
  const vendors = useMemo(() => [...new Set([...(data?.catalog.map(v => v.vendor) || []), ...(data?.rows.flatMap(r => r.vendors) || [])])].sort(), [data]);
  const rows = useMemo(() => {
    const q = search.trim().toLowerCase();
    return (data?.rows || []).filter(row => (vendor === 'all' || row.vendors.includes(vendor))
      && (patch === 'all' || row.patch === patch)
      && (scope !== 'baseline' || row.matches.length > 0)
      && (scope !== 'models' || row.matches.some(m => m.level === 'model'))
      && (!q || `${row.id} ${row.title} ${row.cves.join(' ')} ${row.products.map(p => [p.name, ...(p.modelNumbers || [])].join(' ')).join(' ')}`.toLowerCase().includes(q)));
  }, [data, vendor, patch, scope, search]);
  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const visible = rows.slice((Math.min(page, pages) - 1) * PAGE_SIZE, Math.min(page, pages) * PAGE_SIZE);
  const busy = data && (!data.status.initialized || data.status.running || data.status.pending > data.status.failed);
  const exportExcel = async () => {
    if (!data || !rows.length) return;
    setExporting(true);
    try {
      const { exportNewsExcel } = await import('@/utils/iocExcelExport');
      const year = Number(month.slice(0, 4)), m = Number(month.slice(5));
      await exportNewsExcel({ dataset: 'ot-patches', range: { from: month + '-01', to: new Date(Date.UTC(year, m, 0)).toISOString().slice(0, 10) }, rows: rows.map(row => ({ ...row, sourceCoverage: data.sources, patchLabel: patchLabel(row.patch) })) }, `threatsumm4ry-ot-ics-patch-day-${month}.xlsx`);
    } catch (e) { toast({ title: pt ? 'Falha ao exportar' : 'Export failed', description: (e as Error).message, variant: 'destructive' }); }
    finally { setExporting(false); }
  };
  const details = (row: OtPatchRow) => <details className="group mt-3">
    <summary className="cursor-pointer text-xs font-medium text-primary">{pt ? 'Produtos, CVEs e orientações' : 'Products, CVEs and guidance'}</summary>
    <div className="mt-3 space-y-4 rounded-md border bg-background p-4 text-sm">
      {row.summary && <p className="text-muted-foreground">{row.summary}</p>}
      <div><h3 className="mb-2 font-semibold">{pt ? 'Produtos e versões informadas na fonte' : 'Products and versions reported by source'}</h3>
        <ul className="space-y-1 text-muted-foreground">{row.products.map((p, i) => <li key={i}>{p.name}{p.modelNumbers?.length ? ` (${p.modelNumbers.join(', ')})` : ''} <span className="text-xs">· {p.status === 'fixed' ? (pt ? 'corrigido' : 'fixed') : p.status === 'affected' ? (pt ? 'afetado na fonte' : 'affected in source') : (pt ? 'mencionado' : 'mentioned')}</span></li>)}</ul>
        {!row.products.length && <p className="text-muted-foreground">{pt ? 'Verifique os produtos no aviso original.' : 'Check products in the original advisory.'}</p>}</div>
      {row.matches.length > 0 && <p className="text-muted-foreground">{row.matches.some(m => m.models.length) ? `${pt ? 'Modelos citados do catálogo' : 'Catalog models mentioned'}: ${row.matches.flatMap(m => m.models).join(', ')}` : (pt ? 'Correspondência apenas de fabricante; modelo não confirmado.' : 'Manufacturer match only; model not confirmed.')}</p>}
      <div><h3 className="mb-2 font-semibold">{pt ? 'Correções e mitigações' : 'Fixes and mitigations'}</h3>
        <ul className="space-y-2 text-muted-foreground">{row.remediations.map((r, i) => <li key={i}><Badge variant="outline" className="mr-2 text-[10px]">{r.category}</Badge>{r.cve && <span className="mr-2 font-mono">{r.cve}</span>}{r.details} {r.products.length > 0 && <span>({r.products.join(', ')})</span>} {r.url && <a href={r.url} target="_blank" rel="noreferrer" className="text-primary underline">{pt ? 'Referência' : 'Reference'}</a>}</li>)}</ul>
        {!row.remediations.length && <p className="text-muted-foreground">{pt ? 'Sem correção estruturada informada. Consulte o fabricante.' : 'No structured fix provided. Consult the vendor.'}</p>}</div>
      <div className="flex flex-wrap gap-2">{row.cveSignals.map(v => <Link key={v.id} to={`/cves?cve=${encodeURIComponent(v.id)}`} className="rounded border px-2 py-1 font-mono text-xs text-primary">{v.id}{v.kev ? ' · KEV' : ''}{v.epss != null ? ` · EPSS ${(v.epss * 100).toFixed(2)}%` : ''}</Link>)}</div>
      <div className="flex flex-wrap gap-3">{row.references.map((url, i) => <a key={url} href={url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-primary underline">{pt ? 'Fonte' : 'Source'} {i + 1}<ExternalLink className="h-3 w-3" /></a>)}</div>
      <p className="text-xs text-muted-foreground">{pt ? 'A correspondência do catálogo não confirma a versão instalada nem substitui a validação e o planejamento de atualização em OT.' : 'Catalog matching does not confirm installed versions. Validate applicability and plan OT updates.'}</p>
    </div>
  </details>;
  return <PageLayout width="max-w-7xl">
    <div className="page-head"><div><h1 className="page-title">OT/ICS Patch Day</h1><p className="page-lede">{pt ? 'Correções e avisos industriais consolidados por mês. Novas publicações e revisões, com consulta diária às fontes.' : 'Monthly industrial fixes and advisories. New publications and revisions, with daily source checks.'}</p></div>
      <div className="flex flex-wrap items-center gap-2"><Button variant="outline" size="sm" onClick={() => setReload(r => r + 1)} disabled={loading}><RefreshCw className="h-4 w-4" />{pt ? 'Recarregar' : 'Reload'}</Button><Button size="sm" disabled={!rows.length || exporting} onClick={() => void exportExcel()}><Download className="h-4 w-4" />{exporting ? (pt ? 'Preparando…' : 'Preparing…') : 'Excel'}</Button></div>
    </div>
    <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-5">
      <MetricCard size="sm" label={pt ? 'Avisos no mês' : 'Monthly advisories'} value={data?.summary.advisories ?? '—'} icon={Factory} />
      <MetricCard size="sm" label={pt ? 'Correção publicada' : 'Fix published'} value={data?.summary.patches ?? '—'} icon={ShieldCheck} />
      <MetricCard size="sm" label={pt ? 'Somente mitigação' : 'Mitigation only'} value={data?.summary.mitigations ?? '—'} icon={Wrench} />
      <MetricCard size="sm" label="KEV" value={data?.summary.kev ?? '—'} tone={data?.summary.kev ? 'critical' : 'neutral'} />
      <MetricCard size="sm" label={pt ? 'Modelos do catálogo' : 'Catalog model matches'} value={data?.summary.matched ?? '—'} hint={pt ? 'Avisos com modelo explícito' : 'Advisories naming a model'} />
    </div>
    <div className="mb-4 flex flex-wrap gap-2 border-b pb-3" role="tablist" aria-label="OT/ICS">
      <Button role="tab" aria-selected={tab === 'advisories'} variant={tab === 'advisories' ? 'default' : 'ghost'} size="sm" onClick={() => setTab('advisories')}>{pt ? 'Avisos e correções' : 'Advisories and fixes'}</Button>
      <Button role="tab" aria-selected={tab === 'coverage'} variant={tab === 'coverage' ? 'default' : 'ghost'} size="sm" onClick={() => setTab('coverage')}>{pt ? 'Catálogo e cobertura' : 'Catalog and coverage'}</Button>
    </div>
    {error && <div role="alert" className="mb-4 rounded-lg border border-destructive/40 p-4 text-sm text-destructive">{error}</div>}
    {data?.status.persistenceError && <p role="alert" className="mb-4 rounded-lg border border-destructive/40 p-3 text-sm">{pt ? 'Os dados foram carregados, mas o cache não pôde ser salvo. A próxima atualização tentará novamente.' : 'Data loaded but cache could not be saved. The next update will retry.'}</p>}
    {!!data?.status.failed && <p className="mb-4 rounded-lg border border-amber-500/30 p-3 text-sm">{data.status.failed} {pt ? 'arquivos não puderam ser atualizados. Os dados anteriores foram preservados; haverá nova tentativa automática.' : 'files could not be updated. Previous data was retained; an automatic retry is scheduled.'}</p>}
    {busy && <p role="status" className="mb-4 flex items-center gap-2 text-sm text-muted-foreground"><RefreshCw className="h-4 w-4 animate-spin" />{pt ? 'Consolidando fontes em segundo plano…' : 'Consolidating sources in the background…'} {data.status.pending > 0 && `${data.status.pending} ${pt ? 'avisos pendentes' : 'advisories pending'}`}</p>}
    {data?.sources.some(s => s.status === 'error' || s.status === 'stale') && <p className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-sm">{pt ? 'Cobertura parcial: uma ou mais fontes estão indisponíveis. Consulte o estado em Catálogo e cobertura.' : 'Partial coverage: one or more sources are unavailable. See Catalog and coverage for source status.'}</p>}
    {tab === 'advisories' ? <>
      <div className="mb-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-[150px_minmax(180px,1fr)_200px_210px_minmax(200px,1fr)]">
        <Input aria-label={pt ? 'Mês do Patch Day' : 'Patch Day month'} type="month" value={month} onChange={e => { if (e.target.value) setParams({ month: e.target.value }); }} />
        <Select value={vendor} onValueChange={setVendor}><SelectTrigger aria-label={pt ? 'Fabricante' : 'Manufacturer'}><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">{pt ? 'Todos os fabricantes' : 'All manufacturers'}</SelectItem>{vendors.map(v => <SelectItem key={v} value={v}>{v}</SelectItem>)}</SelectContent></Select>
        <Select value={scope} onValueChange={setScope}><SelectTrigger aria-label={pt ? 'Correspondência' : 'Matching'}><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">{pt ? 'Todos os avisos OT/ICS' : 'All OT/ICS advisories'}</SelectItem><SelectItem value="baseline">{pt ? 'Fabricantes do catálogo' : 'Catalog manufacturers'}</SelectItem><SelectItem value="models">{pt ? 'Modelos explícitos' : 'Explicit models'}</SelectItem></SelectContent></Select>
        <Select value={patch} onValueChange={setPatch}><SelectTrigger aria-label={pt ? 'Situação da correção' : 'Remediation status'}><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">{pt ? 'Todas as situações' : 'All statuses'}</SelectItem>{['available', 'mitigation', 'unconfirmed'].map(v => <SelectItem key={v} value={v}>{patchLabel(v)}</SelectItem>)}</SelectContent></Select>
        <div className="relative"><Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" /><Input className="pl-9" aria-label={pt ? 'Buscar aviso, CVE ou produto' : 'Search advisory, CVE or product'} placeholder={pt ? 'Aviso, CVE ou produto…' : 'Advisory, CVE or product…'} value={search} onChange={e => setSearch(e.target.value)} /></div>
      </div>
      <p className="mb-3 text-xs text-muted-foreground">{rows.length} {pt ? 'avisos nos filtros · publicação inicial ou última revisão no mês · prioridade: KEV e CVSS' : 'filtered advisories · initial publication or latest revision in month · ranked by KEV and CVSS'}</p>
      <div className="overflow-x-auto rounded-lg border"><table className="w-full text-left text-sm"><thead className="bg-muted/40 text-xs text-muted-foreground"><tr><th className="p-4">{pt ? 'Aviso / produto' : 'Advisory / product'}</th><th className="p-4">{pt ? 'Fabricante' : 'Manufacturer'}</th><th className="p-4">CVSS / KEV</th><th className="p-4">{pt ? 'Correção' : 'Remediation'}</th><th className="p-4">{pt ? 'Datas' : 'Dates'}</th></tr></thead>
        <tbody className="divide-y">{visible.map(row => <tr key={row.source + row.id} className="align-top"><td className="min-w-[300px] max-w-xl p-4"><a className="font-medium text-primary hover:underline" href={row.url} target="_blank" rel="noreferrer">{row.title}</a><div className="mt-1 text-xs text-muted-foreground">{row.id} · {row.source}{row.alsoReportedBy?.length ? ' · CISA' : ''}{row.stale ? ` · ${pt ? 'cache anterior' : 'previous cache'}` : ''}</div><div className="mt-2 flex flex-wrap gap-1">{row.cves.slice(0, 3).map(cve => <Badge key={cve} variant="outline" className="font-mono text-[10px]">{cve}</Badge>)}{row.cves.length > 3 && <Badge variant="outline">+{row.cves.length - 3}</Badge>}</div>{details(row)}</td><td className="p-4 text-xs">{row.vendors.join(', ')}{row.matches.length > 0 && <Badge variant="outline" className="mt-2 block w-fit text-[10px]">{row.matches.some(m => m.level === 'model') ? (pt ? 'Modelo citado' : 'Model mentioned') : (pt ? 'Fabricante do catálogo' : 'Catalog manufacturer')}</Badge>}</td><td className="whitespace-nowrap p-4 font-mono">{row.cvss?.toFixed(1) ?? '—'}{row.kev && <Badge variant="destructive" className="ml-2">KEV</Badge>}</td><td className="p-4"><Badge variant="outline" className={row.patch === 'available' ? 'border-emerald-500/40 text-emerald-700 dark:text-emerald-400' : ''}>{patchLabel(row.patch)}</Badge></td><td className="whitespace-nowrap p-4 text-xs text-muted-foreground"><div>{pt ? 'Publicação' : 'Published'}: {dateLabel(row.published, pt)}</div><div className="mt-1">{pt ? 'Revisão' : 'Updated'}: {dateLabel(row.updated, pt)}</div></td></tr>)}</tbody></table>
        {!visible.length && <p className="p-10 text-center text-sm text-muted-foreground">{loading || busy ? (pt ? 'Carregando avisos…' : 'Loading advisories…') : (pt ? 'Nenhum aviso consolidado para estes filtros. Isso não confirma ausência de vulnerabilidades.' : 'No consolidated advisories for these filters. This does not confirm absence of vulnerabilities.')}</p>}</div>
      <div className="mt-4 flex items-center justify-end gap-3 text-sm"><Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>{pt ? 'Anterior' : 'Previous'}</Button><span>{Math.min(page, pages)} / {pages}</span><Button variant="outline" size="sm" disabled={page >= pages} onClick={() => setPage(p => p + 1)}>{pt ? 'Próxima' : 'Next'}</Button></div>
    </> : <div className="space-y-6">
      <section className="grid gap-3 md:grid-cols-2">{data?.sources.map(source => <div key={source.id} className="rounded-lg border bg-card p-4"><div className="flex items-center justify-between gap-2"><a href={source.url} target="_blank" rel="noreferrer" className="font-semibold text-primary hover:underline">{source.name}</a><Badge variant="outline">{source.status === 'ok' ? (pt ? 'Disponível' : 'Available') : source.status === 'stale' ? (pt ? 'Cache anterior' : 'Stale cache') : source.status === 'error' ? (pt ? 'Indisponível' : 'Unavailable') : (pt ? 'Aguardando' : 'Pending')}</Badge></div><p className="mt-2 text-sm text-muted-foreground">{source.coverage}</p><p className="mt-2 text-xs text-muted-foreground">{pt ? 'Último sucesso' : 'Last success'}: {source.lastSuccess ? new Date(source.lastSuccess).toLocaleString(pt ? 'pt-BR' : 'en-US') : '—'}{source.error ? ` · ${source.error}` : ''}</p></div>)}</section>
      <section><h2 className="text-lg font-semibold">{pt ? 'Catálogo de produtos monitorados' : 'Monitored product catalog'}</h2><p className="mb-4 mt-1 text-sm text-muted-foreground">{pt ? 'Fabricantes e modelos consolidados. A presença no catálogo não significa cobertura integral do fabricante; descrições ambíguas precisam de validação.' : 'Consolidated manufacturers and models. Catalog inclusion does not mean complete vendor coverage; ambiguous descriptions require validation.'}</p><div className="grid gap-3 md:grid-cols-2">{data?.catalog.map(v => <details key={v.vendor} className="rounded-lg border bg-card p-4"><summary className="cursor-pointer text-sm font-semibold">{v.vendor} <span className="ml-2 font-normal text-muted-foreground">{v.models.length} {pt ? 'modelos' : 'models'}{v.review.length ? ` · ${pt ? 'revisão pendente' : 'review needed'}` : ''}</span></summary><p className="mt-3 text-sm text-muted-foreground">{v.models.join(' · ') || (pt ? 'Modelo a confirmar.' : 'Model unconfirmed.')}</p>{v.review.length > 0 && <p className="mt-3 text-xs text-amber-700 dark:text-amber-400">{v.review.join(' · ')}</p>}</details>)}</div></section>
    </div>}
  </PageLayout>;
}
