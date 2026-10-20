import { Copy, ExternalLink } from 'lucide-react';
import { toast } from 'sonner';
import type { ActorAliasEvidence, ActorInfrastructure } from '@/pages/actorsTypes';

export function ActorNameSources({ rows, pt }: { rows: ActorAliasEvidence[]; pt: boolean }) {
  if (!rows.length) return null;
  return <section className="mt-6 border-t pt-5"><h3 className="text-sm font-semibold">{pt ? 'Nomes nas fontes' : 'Names in sources'}</h3>
    <p className="mt-1 text-xs text-muted-foreground">{pt ? 'Nomes relacionados ajudam a investigar sobreposições entre grupos; não são tratados como aliases para atribuição automática.' : 'Related names help investigate group overlaps; they are not aliases for automatic attribution.'}</p>
    <div className="mt-3 max-h-80 overflow-auto"><table className="actor-table"><thead><tr><th>{pt ? 'Nome' : 'Name'}</th><th>{pt ? 'Relação' : 'Relation'}</th><th>{pt ? 'Fonte' : 'Source'}</th></tr></thead><tbody>{rows.map((row,index)=><tr key={`${row.source}-${row.name}-${index}`}><td>{row.name}</td><td className="text-muted-foreground">{row.relation==='source-declared-name'?'Alias':(pt?'Nome relacionado':'Related name')}</td><td><a href={row.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline">{row.source}<ExternalLink className="h-3 w-3"/></a>{row.declaredBy&&<span className="mt-1 block text-xs text-muted-foreground">{row.declaredBy}</span>}</td></tr>)}</tbody></table></div>
  </section>;
}

export function ActorInfrastructureTable({ rows, pt }: { rows: ActorInfrastructure[]; pt: boolean }) {
  const labels=pt?{listed:'Listado na fonte',historical:'Histórico na fonte','reported-offline':'Offline na fonte','reported-seized':'Apreendido na fonte'}:{listed:'Listed in source',historical:'Historical in source','reported-offline':'Reported offline','reported-seized':'Reported seized'};
  const copy=async (host:string)=>{try{await navigator.clipboard.writeText(host);toast.success(pt?'Endereço copiado':'Address copied');}catch{toast.error(pt?'Não foi possível copiar':'Unable to copy');}};
  return <><h3 className="text-sm font-semibold">{pt?'Endereços onion do grupo':'Group onion addresses'}</h3>
    <p className="mb-4 mt-1 text-xs text-muted-foreground">{pt?'O estado reflete o que a fonte publicou. A plataforma não acessa esses endereços para verificar disponibilidade.':'Status reflects the source publication. The platform does not visit these addresses to check availability.'}</p>
    <div className="overflow-x-auto"><table className="actor-table"><thead><tr><th>{pt?'Endereço':'Address'}</th><th>{pt?'Estado informado':'Reported status'}</th><th>{pt?'Referência':'Reference'}</th></tr></thead><tbody>{rows.map(row=><tr key={row.host}><td><div className="flex min-w-64 items-start gap-2"><span className="break-all font-mono text-xs">{row.host}</span><button type="button" className="shrink-0 rounded p-1 text-muted-foreground hover:text-foreground" onClick={()=>void copy(row.host)} aria-label={`${pt?'Copiar':'Copy'} ${row.host}`}><Copy className="h-3.5 w-3.5"/></button></div>{row.addressVersion===2&&<span className="text-xs text-muted-foreground">{pt?'Endereço Tor v2 legado':'Legacy Tor v2 address'}</span>}</td><td className="text-xs">{labels[row.reportedStatus]}</td><td><a href={row.sourceUrl} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-primary hover:underline">{row.source}<ExternalLink className="h-3 w-3"/></a></td></tr>)}</tbody></table></div>
    {!rows.length&&<p className="py-6 text-sm text-muted-foreground">{pt?'Nenhum endereço onion vinculado a este perfil nas fontes integradas.':'No onion address linked to this profile in the integrated sources.'}</p>}
  </>;
}
