import { useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import { fetchVendorQuotas, type VendorQuota, type QuotaWindow } from '@/services/threatApi';
import { SourceIdentity } from '@/components/SourceIdentity';
import { Button } from '@/components/ui/button';

export function VendorQuotaDashboard({ pt, refreshKey = 0 }: { pt: boolean; refreshKey?: number }) {
    const [items, setItems] = useState<VendorQuota[]>([]);
    const [loading, setLoading] = useState(true);
    const [failed, setFailed] = useState(false);
    const [retry, setRetry] = useState(0);
    const l = (a: string, b: string) => pt ? a : b;
    const format = (value: number) => value.toLocaleString(pt ? 'pt-BR' : 'en-US');
    const date = (value?: string | null) => value && Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString(pt ? 'pt-BR' : 'en-US', { dateStyle: 'short', timeStyle: 'short' }) : null;
    useEffect(() => {
        const controller = new AbortController();
        setLoading(true); setFailed(false);
        void fetchVendorQuotas(refreshKey > 0 || retry > 0, controller.signal).then(result => {
            if (!controller.signal.aborted) setItems(result.quotas);
        }).catch(() => { if (!controller.signal.aborted) setFailed(true); }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
        return () => controller.abort();
    }, [refreshKey, retry]);

    const label = (operation?: string) => ({ check: l('IPs', 'IPs'), 'check-block': 'CIDR', blacklist: l('Coleta', 'Collection'), search: l('Pesquisas', 'Searches'), query_credits: l('Créditos de pesquisa', 'Query credits'), credits: l('Créditos mensais ou comprados', 'Monthly or purchased credits'), api: 'API' }[operation || ''] || '');
    const cell = (item: VendorQuota, periods: string[]) => {
        if (item.state === 'unconfigured') return <span className="text-muted-foreground">{l('Sem chave', 'No key')}</span>;
        if (item.state === 'error') return <span className="text-destructive">{l('Indisponível', 'Unavailable')} {item.error?.startsWith('HTTP') ? `· ${item.error}` : ''}</span>;
        const windows: QuotaWindow[] = item.windows || (item.period && item.state === 'ok' ? [{ ...item, state: 'ok' }] : []);
        const matching = windows.filter(window => periods.includes(window.period || ''));
        if (!matching.length) return <span className="text-muted-foreground">{l('Não informado pela API', 'Not provided by the API')}</span>;
        return <div className="space-y-3">{matching.map(window => {
            const hasRemaining = window.remaining !== null && window.remaining !== undefined;
            const depleted = hasRemaining && window.remaining! <= 0;
            const low = hasRemaining && !!window.limit && window.remaining! / window.limit <= 0.2;
            const period = window.period === 'minute' ? l('/min', '/min') : window.period === 'hour' ? l('/hora', '/hour') : '';
            return <div key={window.period + ':' + window.operation}>
                <p className="text-[10px] text-muted-foreground">{label(window.operation)}{period}</p>
                {window.state === 'pending' ? <p className="text-muted-foreground">{l('Após a próxima consulta', 'After the next lookup')}</p> : <>
                    <p className={depleted ? 'font-semibold text-destructive' : low ? 'font-semibold text-amber-500' : 'font-semibold text-foreground'}>{hasRemaining ? `${format(window.remaining!)} ${l('restantes', 'remaining')}` : l('Saldo não informado', 'Balance not provided')}</p>
                    <p className="mt-0.5 text-[10px] text-muted-foreground">{window.used != null ? `${format(window.used)} ${l('usados', 'used')}` : l('Uso não informado', 'Usage not provided')}{window.limit != null ? ` · ${l('limite', 'limit')} ${format(window.limit)}` : ''}</p>
                    <p className="mt-0.5 text-[10px] text-muted-foreground">{date(window.resetAt) ? `${l('Renova', 'Resets')} ${date(window.resetAt)}` : l('Renovação não informada', 'Reset not provided')}</p>
                </>}
            </div>;
        })}</div>;
    };
    return <section aria-label={l('Cotas das APIs', 'API quotas')} className="actor-surface overflow-hidden">
        <div className="flex items-center justify-between gap-3 border-b p-4"><div><h2 className="text-base font-semibold">{l('Cotas e limites das APIs', 'API quotas and limits')}</h2><p className="mt-1 text-xs text-muted-foreground">{l('Saldo diário e mensal, consumo e renovação informados pelas fontes. Atualize para consultar o saldo novamente.', 'Daily and monthly balance, usage and reset reported by each source. Refresh to check the balance again.')}</p></div>{loading && <Loader2 aria-label={l('Atualizando cotas', 'Refreshing quotas')} className="h-4 w-4 shrink-0 animate-spin" />}</div>
        {failed ? <div role="alert" className="flex items-center gap-3 p-4 text-sm"><span>{l('Não foi possível atualizar as cotas.', 'Could not refresh quotas.')}</span><Button variant="outline" size="sm" onClick={() => setRetry(value => value + 1)}>{l('Tentar novamente', 'Retry')}</Button></div> : !items.length ? <p className="p-4 text-sm text-muted-foreground">{l('Consultando cotas…', 'Loading quotas…')}</p> : <>
            <div className="overflow-x-auto"><table className="actor-table w-full min-w-[760px] text-left text-xs"><thead><tr>{[l('Fonte / chave', 'Source / key'), l('Cota diária', 'Daily quota'), l('Cota mensal / créditos', 'Monthly quota / credits'), l('Limites por minuto / hora', 'Minute / hour limits'), l('Última leitura', 'Last reading')].map(title => <th key={title}>{title}</th>)}</tr></thead><tbody>{items.filter(item => item.state !== 'none').map(item => <tr key={item.name}>
                <td className="align-top"><SourceIdentity name={item.name} /><p className="mt-2 text-[10px] text-muted-foreground">{item.credential === 'personal' ? l('Chave pessoal', 'Personal key') : l('Chave da plataforma', 'Platform key')}{(item.keyCount || 0) > 1 ? l(' · principal', ' · primary') : ''}</p></td>
                <td className="align-top">{cell(item, ['day'])}</td><td className="align-top">{cell(item, ['month', 'credits'])}</td><td className="align-top">{cell(item, ['minute', 'hour'])}</td>
                <td className="align-top text-muted-foreground">{['AbuseIPDB', 'WHOIS'].includes(item.name) ? <div className="space-y-2">{item.windows?.filter(window => window.at).map(window => <p key={window.operation}>{label(window.operation)} · {date(window.at)}</p>)}</div> : date(item.at) || '—'}</td>
            </tr>)}</tbody></table></div>
            <p className="border-t p-4 text-xs leading-relaxed text-muted-foreground">{l('As demais fontes não disponibilizam saldo consultável nesta integração. “Não informado” não significa acesso ilimitado. As cotas do AbuseIPDB são lidas nas chamadas reais de IP, CIDR e coleta; abrir esta tela não consome consultas nessas operações.', 'The other sources do not expose a queryable balance in this integration. “Not provided” does not mean unlimited access. AbuseIPDB quotas are read from real IP, CIDR and collection calls; opening this page does not consume those lookups.')}</p>
        </>}
    </section>;
}
