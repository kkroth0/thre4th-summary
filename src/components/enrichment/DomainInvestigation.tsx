import { useAuth } from '@/contexts/AuthContext';
import { useState, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Globe2, RefreshCw } from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { DataPager } from '@/components/workbench/DataPager';
import { lookupDomain } from '@/services/networkInvestigation';
import { domainHosts } from '@/utils/networkInvestigation';
import type { ThreatIntelligenceResult } from '@/types/threat-intelligence';
import { SourceIdentity } from '@/components/SourceIdentity';

export function DomainInvestigation({ data, pt, onPivot, children }: { data: ThreatIntelligenceResult; pt: boolean; onPivot: (value: string) => void; children: ReactNode }) {
  const { auth } = useAuth();
  const domain = data.query.toLowerCase(); const l = (a: string, b: string) => pt ? a : b;
  const [page, setPage] = useState(1); const [size, setSize] = useState(25); const [tab, setTab] = useState('summary');
  const dns = useQuery({ queryKey: ['domain-dns', auth.login || '', domain], queryFn: ({ signal }) => lookupDomain(domain, signal), staleTime: 300_000, retry: false });
  const hosts = domainHosts(domain, data.vendorData, dns.data?.records);
  const whois = data.vendorData.find(item => item.name === 'WHOIS');
  const dnsRows = Object.entries(dns.data?.records || {}).flatMap(([type, values]) => (Array.isArray(values) ? values : []).map(value => ({ type, value })));
  const current = Math.min(page, Math.max(1, Math.ceil(hosts.length / size)));
  const loading = data.vendorData.some(item => item.isLoading);
  const responded = data.vendorData.filter(item => !item.isLoading && !item.error && Object.keys(item.data).length > 0);
  const shodan = data.vendorData.find(item => item.name === 'Shodan');
  const pager = <DataPager pt={pt} total={hosts.length} page={current} pageSize={size} pageSizes={[25, 50, 100]} onPage={setPage} onPageSize={value => { setSize(value); setPage(1); }} />;
  return <section className="space-y-5">
    <div className="flex items-center gap-2 text-xs text-muted-foreground"><Globe2 className="h-4 w-4" />{l('Domínio', 'Domain')}</div>
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">{[
      { label: l('Fontes com detecção', 'Sources with detections'), value: loading || !data.reportingVendors ? '—' : data.detections, view: 'summary' },
      { label: l('Hosts observados', 'Observed hosts'), value: hosts.length || (dns.isFetching || dns.isError || shodan?.error ? '—' : 0), view: 'subdomains' },
      { label: l('Registros DNS atuais', 'Current DNS records'), value: dns.data ? dnsRows.length : '—', view: 'dns' },
      { label: l('Fontes respondidas', 'Responding sources'), value: responded.length, view: 'summary' },
    ].map(metric => <button key={metric.label} onClick={() => setTab(metric.view)} className="actor-surface p-4 text-left hover:border-primary/40 focus-visible:ring-2 focus-visible:ring-ring"><p className="text-xs text-muted-foreground">{metric.label}</p><p className="mt-3 font-mono text-2xl font-semibold">{metric.value}</p></button>)}</div>
    <Tabs value={tab} onValueChange={setTab}><div className="overflow-x-auto"><TabsList variant="underline" className="w-max" aria-label={l('Investigação do domínio', 'Domain investigation')}><TabsTrigger value="summary">{l('Resumo e fontes', 'Summary and sources')}</TabsTrigger><TabsTrigger value="subdomains">{l('Subdomínios', 'Subdomains')}</TabsTrigger><TabsTrigger value="dns">DNS</TabsTrigger><TabsTrigger value="whois">WHOIS</TabsTrigger></TabsList></div>
      <TabsContent value="summary" className="space-y-5">{children}</TabsContent>
      <TabsContent value="subdomains" className="actor-surface overflow-hidden"><header className="p-5"><h2 className="text-base font-semibold">{l('Subdomínios e hosts', 'Subdomains and hosts')}</h2><p className="mt-1 text-xs text-muted-foreground">{l('Observações do Shodan e resolução DNS atual. Os hosts não são consultados individualmente.', 'Shodan observations and current DNS resolution. Hosts are not looked up individually.')}</p></header>{pager}<div className="overflow-x-auto"><table className="actor-table w-full min-w-[640px] text-left text-xs"><thead><tr><th>Hostname</th><th>{l('Endereços', 'Addresses')}</th><th>{l('Fonte', 'Source')}</th><th>{l('Última observação', 'Last observation')}</th></tr></thead><tbody>{hosts.slice((current - 1) * size, current * size).map(host => <tr key={host.hostname}><td><button type="button" className="font-mono text-primary hover:underline" onClick={() => onPivot(host.hostname)}>{host.hostname}</button></td><td>{host.addresses.length ? host.addresses.map(ip => <button key={ip} onClick={() => onPivot(ip)} className="mr-2 font-mono text-primary hover:underline">{ip}</button>) : '—'}</td><td>{host.sources.join(', ')}</td><td>{host.lastSeen ? new Date(host.lastSeen).toLocaleDateString(pt ? 'pt-BR' : 'en-US') : '—'}</td></tr>)}</tbody></table></div>{!hosts.length && <p className="p-8 text-center text-sm text-muted-foreground">{loading || dns.isFetching ? l('Consultando hosts…', 'Loading hosts…') : l('Nenhum host retornado nas respostas disponíveis.', 'No hosts returned in the available responses.')}</p>}{(shodan?.error || dns.isError) && <p role="alert" className="px-5 pb-5 text-xs text-muted-foreground">{l('Cobertura parcial: uma das fontes está indisponível.', 'Partial coverage: a source is unavailable.')}</p>}{pager}</TabsContent>
      <TabsContent value="dns" className="actor-surface overflow-hidden"><header className="flex items-center justify-between p-5"><div><h2 className="text-base font-semibold">DNS</h2><p className="mt-1 text-xs text-muted-foreground">{l('Resolução atual do domínio.', 'Current domain resolution.')}</p></div><Button size="sm" variant="outline" disabled={dns.isFetching} onClick={() => void dns.refetch()}><RefreshCw className="mr-2 h-3.5 w-3.5" />{l('Atualizar', 'Refresh')}</Button></header>{dns.isError ? <p role="alert" className="p-5 text-sm text-muted-foreground">{l('Não foi possível consultar o DNS.', 'Could not retrieve DNS records.')}</p> : dns.isFetching ? <p role="status" className="p-5 text-sm text-muted-foreground">{l('Consultando DNS…', 'Loading DNS…')}</p> : <><div className="overflow-x-auto"><table className="actor-table w-full min-w-[420px] text-left text-xs"><thead><tr><th>{l('Tipo', 'Type')}</th><th>{l('Valor', 'Value')}</th></tr></thead><tbody>{dnsRows.map((row, i) => <tr key={`${row.type}-${i}`}><td className="w-24 font-mono">{row.type}</td><td className="break-all font-mono">{row.value}</td></tr>)}</tbody></table></div>{!dnsRows.length && <p className="p-8 text-center text-sm text-muted-foreground">{l('Nenhum registro retornado pelo resolvedor.', 'No records returned by the resolver.')}</p>}</>}</TabsContent>
      <TabsContent value="whois" className="actor-surface p-5"><h2 className="mb-5 text-base font-semibold">WHOIS</h2>{whois?.isLoading ? <p role="status" className="text-sm text-muted-foreground">{l('Consultando registro…', 'Loading registration…')}</p> : !whois || whois.error ? <p role="alert" className="text-sm text-muted-foreground">{l('WHOIS não selecionado ou indisponível. Verifique a configuração da fonte.', 'WHOIS not selected or unavailable. Check source configuration.')}</p> : <><SourceIdentity name="WHOIS" url={whois.link} className="mb-5 text-xs text-muted-foreground" /><dl className="grid gap-5 sm:grid-cols-2">{Object.entries(whois.data).map(([label, value]) => <div key={label}><dt className="text-xs text-muted-foreground">{label}</dt><dd className="mt-2 break-all text-sm">{String(value ?? '—')}</dd></div>)}</dl></>}</TabsContent>
    </Tabs>
  </section>;
}
