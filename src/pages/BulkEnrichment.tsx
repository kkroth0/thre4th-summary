import { bulkRetryAt } from '@/utils/bulkRetry';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Download, ListFilter, Play, Square, Upload } from 'lucide-react';
import { PageLayout } from '@/components/PageLayout';
import { PageHeader } from '@/components/PageHeader';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { DataPager } from '@/components/workbench/DataPager';
import { RecordDrawer } from '@/components/workbench/RecordDrawer';
import { VendorContent } from '@/components/VendorContent';
import { BulkSourceCell } from '@/components/workbench/BulkSourceCell';
import { fetchBulkContext } from '@/services/bulkContext';
import { useLanguage } from '@/contexts/LanguageContext';
import { SUPPORTED_VENDORS } from '@/config/vendorCatalog';
import { detectIOCType, fetchThreatDataProgressive, resolveVendorsForQuery } from '@/services/threatApi';
import { BULK_MAX_BYTES, bulkCsv, bulkField, bulkResultState, prepareBulkInput, runBulkQueue, type BulkRow, type BulkState } from '@/utils/bulkEnrichment';

const download = (body: string, extension: string, mime: string) => {
  const url = URL.createObjectURL(new Blob([body], { type: mime }));
  const link = document.createElement('a'); link.href = url;
  link.download = `threatsumm4ry-bulk-${new Date().toISOString().replace(/[:.]/g, '-')}.${extension}`;
  link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
};

export default function BulkEnrichment() {
  const { language } = useLanguage(); const pt = language === 'pt'; const navigate = useNavigate();
  const [input, setInput] = useState(''); const [prepared, setPrepared] = useState<ReturnType<typeof prepareBulkInput> | null>(null);
  const [rows, setRows] = useState<BulkRow[]>([]); const [busy, setBusy] = useState(false); const [stopping, setStopping] = useState(false);
  const [error, setError] = useState(''); const [search, setSearch] = useState(''); const [type, setType] = useState('all'); const [status, setStatus] = useState('all');
  const [exporting, setExporting] = useState(false);
  const [resumeAt, setResumeAt] = useState<number | null>(null);
  const retryTimer = useRef<ReturnType<typeof setTimeout>>();
  const retryAttempts = useRef(new Map<string, number>());
  const pendingRetries = useRef(new Map<string, number>());
  const resumeRun = useRef<(queries: string[], resume: boolean) => Promise<void>>();
  const [page, setPage] = useState(1); const [size, setSize] = useState(20); const [selected, setSelected] = useState<string | null>(null);
  const [vendors, setVendors] = useState<string[]>([...SUPPORTED_VENDORS]);
  const stop = useRef(false); const running = useRef(false); const mounted = useRef(true); const fileRef = useRef<HTMLInputElement>(null);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; stop.current = true; clearTimeout(retryTimer.current); }; }, []);
  const labels: Record<BulkState, string> = pt ? { queued: 'Na fila', running: 'Consultando', complete: 'Concluído', partial: 'Parcial', error: 'Falha', unsupported: 'Sem fonte compatível', stopped: 'Interrompido' } : { queued: 'Queued', running: 'Querying', complete: 'Complete', partial: 'Partial', error: 'Failed', unsupported: 'No compatible source', stopped: 'Stopped' };
  const verdict = (row: BulkRow) => {
    if (!row.result || row.state === 'error') return '—';
    return ({ malicious: pt ? 'Malicioso' : 'Malicious', suspicious: pt ? 'Suspeito' : 'Suspicious', safe: pt ? 'Sem sinal nas fontes' : 'No signal in sources', unknown: pt ? 'Indeterminado' : 'Unknown' })[row.result.threatLevel];
  };
  const field = (row: BulkRow, keys: string[]) => { const found = bulkField(row, keys); return <span title={found.source}>{found.value}</span>; };
  const update = (query: string, value: Partial<BulkRow>) => {
    if (mounted.current) setRows(previous => previous.map(row => row.query === query ? { ...row, ...value } : row));
  };
  const extract = () => {
    if (new Blob([input]).size > BULK_MAX_BYTES) { setError(pt ? 'Limite de entrada: 3,8 MB.' : 'Input limit: 3.8 MB.'); return; }
    const parsed = prepareBulkInput(input); setPrepared(parsed); setSelected(null); setPage(1); setSearch(''); setType('all'); setStatus('all');
    setRows(parsed.indicators.map(query => ({ query, state: 'queued' })));
    setError(parsed.indicators.length ? '' : pt ? 'Nenhum IP público, domínio, URL ou hash válido encontrado.' : 'No valid public IP, domain, URL or hash found.');
  };
  const run = async (queries: string[], resume = false) => {
    if (running.current || !queries.length || !vendors.length) return;
    running.current = true; stop.current = false; setBusy(true); setStopping(false); setError('');
    clearTimeout(retryTimer.current); setResumeAt(null);
    if (!resume) { retryAttempts.current.clear(); pendingRetries.current.clear(); }
    const sources = [...vendors];
    const retained = new Map(resume ? rows.filter(row => row.result).map(row => [row.query, row.result]) : []);
    setRows(previous => previous.map(row => queries.includes(row.query) ? { ...row, ...(resume ? {} : { result: undefined, context: undefined }), state: 'queued' } : row));
    try {
      await runBulkQueue(queries, async query => {
        const eligible = resolveVendorsForQuery(query, sources);
        if (!eligible.length) { update(query, { state: 'unsupported' }); return; }
        update(query, { state: 'running', result: { query, overallScore: 0, threatLevel: 'unknown', totalVendors: eligible.length, detections: 0, vendorData: eligible.map(name => retained.get(query)?.vendorData.find(vendor => vendor.name === name && !vendor.error && !vendor.isLoading) || ({ name, data: {}, isLoading: true })) } });
        try {
          update(query, { contextLoading: true });
          const result = await fetchThreatDataProgressive(query, sources, data => {
            if (mounted.current) setRows(previous => previous.map(row => row.query === query && row.result ? { ...row, result: { ...row.result, vendorData: row.result.vendorData.map(vendor => vendor.name === data.name ? data : vendor) } } : row));
          }, { includeRaw: true, previous: retained.get(query) });
          // Provider responses are persisted before this resolves. Read once
          // afterwards so the table and exports include this run's new links.
          const context = await fetchBulkContext(query);
          const state = bulkResultState(result);
          update(query, { state: context.errors.length && state === 'complete' ? 'partial' : state, result, context, contextLoading: false, completedAt: new Date().toISOString() });
          const nextAt = bulkRetryAt(result, retryAttempts.current);
          if (nextAt) pendingRetries.current.set(query, nextAt); else pendingRetries.current.delete(query);
        } catch {
          pendingRetries.current.delete(query);
          update(query, { state: 'error', contextLoading: false, error: pt ? 'Não foi possível consultar o indicador.' : 'Could not query this indicator.', completedAt: new Date().toISOString() });
        }
      }, () => stop.current);
    } finally {
      running.current = false;
      if (mounted.current) {
        setRows(previous => previous.map(row => row.state === 'queued' && stop.current ? { ...row, state: 'stopped' } : row));
        setStopping(false);
        if (!stop.current && pendingRetries.current.size) {
          const at = Math.max(Date.now() + 1000, Math.min(...pendingRetries.current.values()));
          setResumeAt(at); setBusy(true);
          retryTimer.current = setTimeout(() => { if (mounted.current && !stop.current) void resumeRun.current?.([...pendingRetries.current].filter(([, due]) => due <= Date.now()).map(([query]) => query), true); }, Math.max(0, at - Date.now()) + 100);
        } else { setBusy(false); setResumeAt(null); }
      }
    }
  };
  resumeRun.current = run;
  const visible = useMemo(() => rows.filter(row => row.query.toLowerCase().includes(search.toLowerCase()) && (type === 'all' || detectIOCType(row.query) === type) && (status === 'all' || row.state === status)), [rows, search, type, status]);
  const current = Math.min(page, Math.max(1, Math.ceil(visible.length / size)));
  const sourceColumns = SUPPORTED_VENDORS.filter(name => rows.some(row => row.result?.vendorData.some(vendor => vendor.name === name)));
  const detail = rows.find(row => row.query === selected);
  const done = rows.filter(row => ['complete', 'partial', 'error', 'unsupported'].includes(row.state)).length;
  const retry = rows.filter(row => ['error', 'partial', 'stopped', 'unsupported'].includes(row.state)).map(row => row.query);
  const excluded = prepared ? Object.values(prepared.excluded).reduce((a, b) => a + b, 0) : 0;
  const exportRows = async (format: 'xlsx' | 'csv' | 'json' | 'txt') => {
    if (exporting) return;
    setExporting(true);
    try {
      if (format === 'xlsx') {
        const { exportBulkExcel } = await import('@/utils/iocExcelExport');
        await exportBulkExcel(visible);
      }
      if (format === 'csv') download('\uFEFF' + bulkCsv(visible), 'csv', 'text/csv;charset=utf-8');
      if (format === 'txt') download(visible.map(row => row.query).join('\n'), 'txt', 'text/plain');
      if (format === 'json') download(JSON.stringify({ generatedAt: new Date().toISOString(), count: visible.length, rows: visible }, null, 2), 'json', 'application/json');
    } catch { setError(pt ? 'Não foi possível exportar o lote.' : 'Could not export the batch.'); }
    finally { setExporting(false); }
  };
  return <PageLayout width="max-w-[1600px]">
    <PageHeader title={pt ? 'Enriquecimento em lote' : 'Bulk enrichment'} subtitle={pt ? 'Consulte todas as fontes compatíveis e reúna reputação, infraestrutura, publicações e evidências por indicador.' : 'Query every compatible source and collect reputation, infrastructure, publications and evidence per indicator.'} />
    {!prepared ? <section className="intel-panel overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-3"><label htmlFor="bulk-input" className="text-sm font-medium">{pt ? 'IPs públicos, domínios, URLs e hashes' : 'Public IPs, domains, URLs and hashes'}</label><div className="flex gap-2"><Button size="sm" variant="outline" onClick={() => fileRef.current?.click()}><Upload className="mr-2 h-4 w-4" />{pt ? 'Importar arquivo' : 'Import file'}</Button><Button size="sm" disabled={!input.trim()} onClick={extract}>{pt ? 'Extrair indicadores' : 'Extract indicators'}</Button></div></div>
      <textarea id="bulk-input" spellCheck={false} value={input} onChange={event => setInput(event.target.value)} placeholder={'1.1.1.1\n8.8.8.8\nexample.com\nhxxps://example[.]com/login'} className="min-h-[280px] w-full resize-y bg-transparent p-4 font-mono text-sm leading-6 outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring" />
      <div className="flex flex-wrap justify-between gap-2 border-t px-4 py-3 text-xs text-muted-foreground"><span>{pt ? 'Aceita texto livre e indicadores defanged. Remove duplicados.' : 'Accepts free text and defanged indicators. Removes duplicates.'}</span><span>{(new Blob([input]).size / 1000).toFixed(1)} KB / 3,8 MB</span></div>
      <input ref={fileRef} type="file" accept=".txt,.log,.csv,.json" className="hidden" aria-label={pt ? 'Arquivo de indicadores' : 'Indicator file'} onChange={async event => {
        const file = event.target.files?.[0]; event.target.value = ''; if (!file) return;
        if (file.size > BULK_MAX_BYTES) { setError(pt ? 'Arquivo maior que 3,8 MB.' : 'File exceeds 3.8 MB.'); return; }
        try { setInput(await file.text()); setError(''); } catch { setError(pt ? 'Falha ao ler arquivo.' : 'Could not read file.'); }
      }} />
    </section> : <>
      <section className="intel-panel mb-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b p-4"><div><span className="text-lg font-semibold">{rows.length}</span><span className="ml-2 text-sm text-muted-foreground">{pt ? 'indicadores únicos' : 'unique indicators'}</span></div><div className="flex gap-2"><Button size="sm" variant="outline" disabled={busy} onClick={() => { setPrepared(null); setRows([]); setSelected(null); setError(''); }}>{pt ? 'Editar entrada' : 'Edit input'}</Button>{busy ? <Button size="sm" variant="outline" disabled={stopping} onClick={() => { stop.current = true; clearTimeout(retryTimer.current); setResumeAt(null); if (running.current) setStopping(true); else { setBusy(false); setStopping(false); } }}><Square className="mr-2 h-3.5 w-3.5" />{stopping ? (pt ? 'Finalizando consultas…' : 'Finishing lookups…') : (pt ? 'Interromper fila' : 'Stop queue')}</Button> : <Button size="sm" disabled={!rows.length || !vendors.length} onClick={() => run(rows.map(row => row.query))}><Play className="mr-2 h-3.5 w-3.5" />{done ? (pt ? 'Enriquecer novamente' : 'Re-enrich') : (pt ? 'Enriquecer lote' : 'Enrich batch')}</Button>}</div></div>
        <div className="grid grid-cols-2 divide-x md:grid-cols-4">{[['ip', pt ? 'IPs públicos' : 'Public IPs'], ['domain', pt ? 'Domínios / hosts' : 'Domains / hosts'], ['url', 'URLs'], ['hash', 'Hashes']].map(([key, label]) => <div key={key} className="px-4 py-3"><div className="text-xs text-muted-foreground">{label}</div><div className="mt-1 font-mono text-lg">{rows.filter(row => detectIOCType(row.query) === key).length}</div></div>)}</div>
        {!!excluded && <p className="border-t px-4 py-3 text-xs text-muted-foreground">{pt ? 'Não consultados' : 'Not queried'}: {prepared.excluded.emails} e-mails · {prepared.excluded.cidrs} CIDRs · {prepared.excluded.nonPublicIps} {pt ? 'IPs privados ou reservados' : 'private or reserved IPs'}.</p>}
      </section>
      <details className="intel-panel mb-4"><summary className="cursor-pointer px-4 py-3 text-sm"><ListFilter className="mr-2 inline h-4 w-4" />{pt ? 'Fontes de enriquecimento' : 'Enrichment sources'} · {vendors.length}/{SUPPORTED_VENDORS.length}</summary><div className="border-t p-4"><div className="mb-3 flex flex-wrap items-center gap-3 text-xs"><button disabled={busy} onClick={() => setVendors([...SUPPORTED_VENDORS])} className="text-primary disabled:opacity-50">{pt ? 'Selecionar todas' : 'Select all'}</button><button disabled={busy} onClick={() => setVendors([])} className="text-muted-foreground disabled:opacity-50">{pt ? 'Limpar seleção' : 'Clear selection'}</button><Link to="/settings?section=api-keys" className="ml-auto text-primary">{pt ? 'Chaves de API' : 'API keys'}</Link></div><div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">{SUPPORTED_VENDORS.map(name => <label key={name} className="flex items-center gap-2 text-xs"><input type="checkbox" checked={vendors.includes(name)} disabled={busy} onChange={event => setVendors(previous => event.target.checked ? [...previous, name] : previous.filter(value => value !== name))} className="accent-primary" />{name}</label>)}</div><p className="mt-4 text-xs text-muted-foreground">{pt ? 'Cada indicador usa somente fontes compatíveis. Cotas e chaves das integrações se aplicam.' : 'Each indicator uses compatible sources only. Integration quotas and keys apply.'}</p></div></details>
      <div className="mb-4 flex flex-wrap items-center gap-3 text-xs" aria-live="polite">{resumeAt && <span className="text-amber-500">{pt ? 'Fontes em espera · retomada automática às ' : 'Sources waiting · automatic resume at '}{new Date(resumeAt).toLocaleTimeString(pt ? 'pt-BR' : 'en-US')}</span>}<span>{done}/{rows.length} {pt ? 'processados' : 'processed'}</span><span>{rows.filter(row => row.state === 'error').length} {pt ? 'falhas' : 'failed'}</span><span>{rows.filter(row => row.state === 'partial').length} {pt ? 'parciais' : 'partial'}</span>{rows.some(row => row.state === 'stopped') && <span>{rows.filter(row => row.state === 'stopped').length} {pt ? 'interrompidos' : 'stopped'}</span>}{retry.length > 0 && !busy && <Button size="sm" variant="outline" disabled={!vendors.length} onClick={() => run(retry, true)}>{pt ? 'Repetir incompletos' : 'Retry incomplete'}</Button>}</div>
      <div className="intel-panel overflow-hidden"><div className="flex flex-wrap items-center gap-2 border-b p-4"><Input className="w-full sm:w-64" aria-label={pt ? 'Buscar indicador' : 'Search indicator'} placeholder={pt ? 'Buscar indicador…' : 'Search indicator…'} value={search} onChange={event => { setSearch(event.target.value); setPage(1); }} /><select aria-label={pt ? 'Tipo de indicador' : 'Indicator type'} className="h-9 rounded-md border bg-background px-3 text-xs" value={type} onChange={event => { setType(event.target.value); setPage(1); }}><option value="all">{pt ? 'Todos os tipos' : 'All types'}</option>{['ip', 'domain', 'url', 'hash'].map(value => <option key={value} value={value}>{value.toUpperCase()}</option>)}</select><select aria-label={pt ? 'Estado da consulta' : 'Lookup status'} className="h-9 rounded-md border bg-background px-3 text-xs" value={status} onChange={event => { setStatus(event.target.value); setPage(1); }}><option value="all">{pt ? 'Todos os estados' : 'All statuses'}</option>{Object.entries(labels).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select><details className="relative ml-auto"><summary className="cursor-pointer rounded-md border px-3 py-2 text-xs"><Download className="mr-2 inline h-3.5 w-3.5" />{pt ? 'Exportar' : 'Export'} · {visible.length}</summary><div className="absolute right-0 z-10 mt-1 w-32 rounded-md border bg-popover p-1 shadow-lg">{(['xlsx', 'csv', 'json', 'txt'] as const).map(format => <button key={format} disabled={!visible.length || busy || exporting} className="block w-full rounded px-3 py-2 text-left text-xs hover:bg-muted disabled:opacity-50" onClick={() => exportRows(format)}>{format.toUpperCase()}</button>)}</div></details></div>
        <DataPager total={visible.length} page={current} pageSize={size} onPage={setPage} onPageSize={value => { setSize(value); setPage(1); }} pt={pt} />
        <div className="overflow-x-auto"><table className="intel-table min-w-[1200px]"><thead><tr>{[pt ? 'Indicador' : 'Indicator', pt ? 'Tipo' : 'Type', pt ? 'Consulta' : 'Lookup', pt ? 'Sinal nas fontes' : 'Source signal', pt ? 'Detecções / fontes' : 'Detections / sources', pt ? 'Publicações' : 'Publications', pt ? 'Entidades citadas · contexto' : 'Mentioned entities · context', ...sourceColumns, pt ? 'País' : 'Country', 'ASN', pt ? 'Organização / ISP' : 'Organization / ISP', pt ? 'Concluído em' : 'Completed at'].map((label,index) => <th key={label} className={index === 0 ? 'sticky left-0 z-[1] bg-card' : ''}>{label}</th>)}</tr></thead><tbody>{visible.slice((current - 1) * size, current * size).map(row => <tr key={row.query}><td className="sticky left-0 z-[1] max-w-md bg-card"><button type="button" onClick={() => setSelected(row.query)} className="max-w-full break-all text-left font-mono text-xs hover:text-primary focus-visible:ring-2 focus-visible:ring-ring">{row.query}</button></td><td className="text-xs uppercase">{detectIOCType(row.query)}</td><td><span className={['error', 'partial'].includes(row.state) ? 'text-amber-500' : row.state === 'running' ? 'text-primary' : ''}>{labels[row.state]}</span></td><td className={row.result?.threatLevel === 'malicious' ? 'text-red-500' : row.result?.threatLevel === 'suspicious' ? 'text-amber-500' : 'text-muted-foreground'}>{verdict(row)}</td><td className="font-mono">{row.result && row.state !== 'running' ? `${row.result.detections} / ${row.result.vendorData.filter(vendor => !vendor.error).length}` : '—'}</td><td className="min-w-72 max-w-sm">{row.contextLoading ? <span role="status">{pt ? 'Buscando publicações…' : 'Loading publications…'}</span> : <div className="max-h-56 space-y-2 overflow-auto text-xs">{row.context?.publications.map(item => <a key={item.link} href={item.link} target="_blank" rel="noreferrer" className="block text-primary hover:underline">{item.title}<span className="block text-muted-foreground">{item.source} · {new Date(item.pubDate).toLocaleDateString(pt ? 'pt-BR' : 'en-US')}</span></a>)}{row.context && !row.context.publications.length && <span className="text-muted-foreground">{pt ? 'Nenhuma menção na base' : 'No mentions in inventory'}</span>}{row.context?.errors.map(message => <p key={message} className="text-amber-500">{message}</p>)}</div>}</td><td className="min-w-56 max-w-sm"><div className="max-h-56 space-y-2 overflow-auto text-xs">{row.context?.evidence.filter(item => item.entities.length).map((item, index) => <p key={index}><span className="text-muted-foreground">{item.source || item.provider}: </span>{item.entities.map(entity => entity.name).join(', ')}<span className="block text-muted-foreground">{item.entities.map(entity => entity.relation).filter((value,index,array)=>array.indexOf(value)===index).map(value => ({'mentioned-with':pt?'Citado na publicação':'Mentioned in publication','attributed-by-source':pt?'Atribuição da fonte':'Source attribution','mentioned-by-source':pt?'Citado pela fonte':'Mentioned by source','reported-label':pt?'Rótulo da fonte':'Source label','observed-on-host':pt?'Observado no host':'Observed on host'}[value] || value)).join(' · ')}</span></p>)}</div></td>{sourceColumns.map(name => <td key={name} className="align-top"><BulkSourceCell vendor={row.result?.vendorData.find(vendor => vendor.name === name)} pt={pt} /></td>)}<td>{field(row, ['Country'])}</td><td>{field(row, ['ASN', 'AS'])}</td><td className="max-w-48 break-words">{field(row, ['Organization', 'ISP'])}</td><td className="whitespace-nowrap text-xs text-muted-foreground">{row.completedAt ? new Date(row.completedAt).toLocaleString(pt ? 'pt-BR' : 'en-US') : '—'}</td></tr>)}</tbody></table>{!visible.length && <p className="p-8 text-center text-sm text-muted-foreground">{pt ? 'Nenhum indicador neste filtro.' : 'No indicators match these filters.'}</p>}</div><DataPager total={visible.length} page={current} pageSize={size} onPage={setPage} pt={pt} />
      </div>
      <p className="mt-4 text-xs leading-5 text-muted-foreground">{pt ? 'Até 3 indicadores simultâneos. Interromper encerra a fila após as consultas em andamento. O lote fica nesta página durante a sessão; CSV e JSON incluem respostas completas, referências, publicações e falhas. TXT contém somente os indicadores.' : 'Up to 3 indicators at a time. Stopping finishes in-flight lookups before ending the queue. The batch stays on this page during the session; CSV and JSON include full responses, references, publications and errors. TXT contains indicators only.'}</p>
    </>}
    {error && <p role="alert" className="mt-4 text-sm text-destructive">{error}</p>}
    <RecordDrawer open={Boolean(detail)} onClose={() => setSelected(null)} title={detail?.query || ''} description={detail ? `${labels[detail.state]} · ${verdict(detail)}` : ''}>
      {detail?.error && <p role="alert" className="text-sm text-destructive">{detail.error}</p>}
      {detail?.result?.vendorData.map(vendor => <section key={vendor.name} className="intel-panel p-4"><div className="mb-3 flex items-center justify-between gap-3"><h3 className="text-sm font-semibold">{vendor.name}</h3>{vendor.link && /^https?:\/\//i.test(vendor.link) && <a href={vendor.link} target="_blank" rel="noopener noreferrer" className="text-xs text-primary">{pt ? 'Consultar fonte' : 'View source'}</a>}</div>{vendor.isLoading ? <p role="status" className="text-xs text-muted-foreground">{pt ? 'Consultando…' : 'Querying…'}</p> : <VendorContent vendor={vendor} />}</section>)}
      {!detail?.result && <p className="text-sm text-muted-foreground">{pt ? 'Este indicador ainda não tem respostas de fontes.' : 'This indicator has no source responses yet.'}</p>}
      {detail && <Button variant="outline" onClick={() => { localStorage.setItem('pivotSearchQuery', detail.query); navigate('/analyzer'); }}>{pt ? 'Abrir investigação de IOC' : 'Open IOC investigation'}</Button>}
    </RecordDrawer>
  </PageLayout>;
}
