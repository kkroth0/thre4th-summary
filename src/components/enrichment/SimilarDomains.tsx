import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ArrowUpRight, Download, Globe2, RefreshCw } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import { domainRequest, fetchSimilarDomains, type SimilarDomain } from '@/services/domainIntelligence';
import { formatVendorData } from '@/services/threatApi';
import { domainDate } from '@/utils/domainInvestigation';

function DomainRow({ row, pt, owner, onPivot }: { row: SimilarDomain; pt: boolean; owner: string; onPivot: (value: string) => void }) {
  const [requested, setRequested] = useState(false); const l = (a: string, b: string) => pt ? a : b;
  const whois = useQuery({ queryKey: ['domain-whois', owner, row.domain], enabled: requested, staleTime: 1800_000, retry: false, queryFn: async ({ signal }) => {
    const raw = await domainRequest<{ WhoisRecord?: unknown }>('/api/whois', signal, { query: row.domain });
    if (!raw.WhoisRecord) throw new Error('Invalid WHOIS response');
    return formatVendorData('WHOIS', raw, row.domain) as Record<string, unknown>;
  } });
  const registrar = row.registrar || (typeof whois.data?.Registrar === 'string' ? whois.data.Registrar : null);
  const expiry = row.expiresAt || (typeof whois.data?.Expires === 'string' ? whois.data.Expires : null);
  const records = row.addresses.length ? row.addresses : row.nameservers;
  return <tr><td><button className="inline-flex items-center gap-2 text-left font-mono font-semibold text-primary hover:underline" onClick={() => onPivot(row.domain)}>{row.domain}<ArrowUpRight className="h-3.5 w-3.5 shrink-0" /></button></td><td><span className="whitespace-nowrap rounded-full bg-muted px-2.5 py-1">{row.kind === 'tld' ? 'TLD' : row.kind === 'omission' ? l('Letra omitida', 'Omitted letter') : l('Letras trocadas', 'Swapped letters')}</span></td><td className="max-w-64 break-all font-mono">{records.slice(0, 3).map(value => <div key={value}>{value}</div>)}{records.length > 3 && <details className="mt-1"><summary className="cursor-pointer text-muted-foreground">+{records.length - 3}</summary>{records.slice(3).map(value => <div key={value}>{value}</div>)}</details>}</td><td className="whitespace-nowrap">{domainDate(expiry, pt)}</td><td className="max-w-60 break-words">{registrar || '—'}{(!registrar || !expiry) && <div className="mt-2">{!requested ? <button className="text-primary hover:underline" onClick={() => setRequested(true)} aria-label={`${l('Consultar WHOIS de', 'Look up WHOIS for')} ${row.domain}`}>{l('Consultar WHOIS', 'Look up WHOIS')}</button> : <span className="text-[11px] text-muted-foreground">{whois.isFetching ? l('Consultando…', 'Loading…') : whois.isError ? l('WHOIS indisponível', 'WHOIS unavailable') : l('Campo não informado pela fonte', 'Field not reported by source')}</span>}</div>}</td><td><span className="whitespace-nowrap">{[...row.source, ...(whois.data ? ['Who.is'] : [])].join(' · ')}</span></td></tr>;
}

export function SimilarDomains({ domain, pt, onPivot }: { domain: string; pt: boolean; onPivot: (value: string) => void }) {
  const { auth } = useAuth(); const [filter, setFilter] = useState(''); const l = (a: string, b: string) => pt ? a : b;
  const result = useQuery({ queryKey: ['domain-similar', auth.login || '', domain], queryFn: ({ signal }) => fetchSimilarDomains(domain, signal), staleTime: 21_600_000, retry: false });
  const rows = (result.data?.domains || []).filter(row => row.domain.includes(filter.toLowerCase().trim()));
  const exportRows = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(result.data, null, 2)], { type: 'application/json' }));
    const link = document.createElement('a'); link.href = url; link.download = `${domain}-similar-domains.json`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return <article className="actor-surface overflow-hidden">
    <header className="space-y-4 border-b p-5">
      <div className="flex flex-wrap items-center justify-between gap-3"><div className="flex items-center gap-3"><Globe2 className="h-5 w-5 text-primary" /><h3 className="font-semibold">{l('Domínios semelhantes', 'Similar domains')}</h3>{result.data && <span className="rounded-full bg-primary/10 px-2.5 py-1 text-xs text-primary">{result.data.domains.length}</span>}</div><div className="flex gap-2"><Button size="sm" variant="outline" disabled={result.isFetching} onClick={() => void result.refetch()}><RefreshCw className={`mr-2 h-3.5 w-3.5 ${result.isFetching ? 'animate-spin' : ''}`} />{l('Atualizar', 'Refresh')}</Button><Button size="sm" variant="outline" disabled={!result.data?.domains.length} onClick={exportRows}><Download className="mr-2 h-3.5 w-3.5" />JSON</Button></div></div>
      <p className="max-w-3xl text-sm text-muted-foreground">{l('Variações do nome e de TLD com registros DNS encontrados. A semelhança não confirma vínculo com a empresa nem atividade maliciosa.', 'Name and TLD variations with observed DNS records. Similarity does not confirm company ownership or malicious activity.')}</p>
      {result.data && <p className="text-xs text-muted-foreground">{l('Base', 'Base')}: <span className="font-mono text-foreground">{result.data.apex}</span> · {result.data.checked || 0}/{result.data.candidateCount || 0} {l('variações consultadas', 'variations checked')} · {l('Atualizado', 'Updated')}: {domainDate(result.data.fetchedAt || null, pt)}</p>}
      <input aria-label={l('Filtrar domínios semelhantes', 'Filter similar domains')} className="w-full max-w-lg rounded-lg border bg-background px-3 py-2 text-sm" placeholder={l('Filtrar domínio…', 'Filter domain…')} value={filter} onChange={event => setFilter(event.target.value)} />
    </header>
    {result.isFetching && !result.data && <p role="status" className="p-6 text-sm text-muted-foreground">{l('Verificando variações em DNS e registros públicos…', 'Checking variations in DNS and public registries…')}</p>}
    {(result.isError || result.data?.status === 'unavailable') && <p role="alert" className="p-5 text-sm text-muted-foreground">{result.data?.error === 'busy' ? l('Há outras consultas em andamento. Tente novamente em instantes.', 'Other searches are running. Please try again shortly.') : l('Não foi possível concluir a consulta. Tente novamente.', 'Could not complete the search. Please try again.')}</p>}
    {!!result.data?.incomplete && result.data.status === 'available' && <p role="status" className="px-5 pt-4 text-xs text-muted-foreground">{l('Resultado parcial: algumas consultas DNS não responderam no prazo.', 'Partial results: some DNS queries did not respond in time.')}</p>}
    {!result.isFetching && result.data?.status === 'available' && !rows.length && <p className="p-6 text-sm text-muted-foreground">{filter ? l('Nenhum domínio corresponde ao filtro.', 'No domains match the filter.') : l('Nenhum domínio com DNS foi encontrado nas variações consultadas. Isso não indica disponibilidade para registro.', 'No domain with DNS was found among the checked variations. This does not imply availability for registration.')}</p>}
    {!!rows.length && <div className="overflow-x-auto"><table className="actor-table w-full min-w-[850px] text-left text-xs"><thead><tr>{[l('Domínio', 'Domain'), l('Variação', 'Variation'), l('DNS observado', 'Observed DNS'), l('Expiração', 'Expiry'), l('Registrador', 'Registrar'), l('Fontes', 'Sources')].map(label => <th key={label}>{label}</th>)}</tr></thead><tbody>{rows.map(row => <DomainRow key={row.domain} row={row} pt={pt} owner={auth.login || ''} onPivot={onPivot} />)}</tbody></table></div>}
    <footer className="border-t p-5 text-xs text-muted-foreground">{l('Até 32 variações verificadas. Domínios registrados sem DNS podem não aparecer. Consulte o WHOIS de um resultado para completar os dados de registro.', 'Up to 32 variations checked. Registered domains without DNS may not appear. Look up WHOIS for a result to complete its registration details.')}</footer>
  </article>;
}
