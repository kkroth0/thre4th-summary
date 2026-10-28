import { useState } from 'react';
import type { VendorData } from '@/types/threat-intelligence';
import { VendorContent } from '@/components/VendorContent';

export function BulkSourceCell({ vendor, pt, onDetails }: { vendor?: VendorData; pt: boolean; onDetails?:()=>void }) {
  const [expanded,setExpanded]=useState(false),[rawExpanded,setRawExpanded]=useState(false);
  if (!vendor) return <span className="text-muted-foreground">—</span>;
  if (vendor.isLoading) return <span role="status" className="text-primary">{vendor.data['Próxima tentativa'] ? (pt ? 'Aguardando nova tentativa…' : 'Waiting to retry…') : vendor.data['Estado da fonte']==='pending' ? (pt?'Na fila':'Queued') : (pt ? 'Consultando…' : 'Querying…')}</span>;
  if (vendor.error) return <p className="max-w-64 break-words text-xs text-amber-500">{vendor.error}{vendor.retryAt && vendor.errorCode !== 'PROVIDER_AUTH_FAILED' && <span className="block">{pt ? 'Nova tentativa a partir de ' : 'Retry from '}{new Date(vendor.retryAt).toLocaleString(pt ? 'pt-BR' : 'en-US')}</span>}</p>;
  const priority = ['Status', 'Registros Axur', 'Relatórios', 'Origem', 'Detection Rate', 'Abuse Confidence Score', 'Total Reports', 'Malware', 'IOC Matches', 'Pulse Count', 'Ports', 'ISP', 'Country'];
  const summary = priority.filter(key => vendor.data[key] !== undefined).slice(0, 4);
  return <div className="min-w-48 max-w-72 space-y-2 text-xs">
    {summary.map(key => <p key={key} className="break-words"><span className="text-muted-foreground">{key}: </span>{String(vendor.data[key])}</p>)}
    {vendor.collectedAt&&<p className="text-[10px] text-muted-foreground">{pt?'Resposta salva: ':'Saved response: '}{new Date(vendor.collectedAt).toLocaleString(pt?'pt-BR':'en-US',{timeZone:'America/Fortaleza'})}{vendor.cacheState&&vendor.cacheState!=='miss'?(pt?' · reutilizada':' · reused'):''}</p>}
    <details onToggle={e=>setExpanded(e.currentTarget.open)}><summary className="cursor-pointer text-primary">{pt ? 'Todos os dados' : 'All data'}</summary>{expanded&&<div className="mt-3 max-h-96 space-y-3 overflow-auto"><VendorContent vendor={vendor} />{vendor.rawDeferred?<button type="button" onClick={onDetails} className="block text-primary hover:underline">{pt?'Ver resposta original no indicador':'View original response in indicator'}</button>:<details onToggle={e=>setRawExpanded(e.currentTarget.open)}><summary className="cursor-pointer text-muted-foreground">{pt ? 'Resposta completa da fonte' : 'Complete source response'}</summary>{rawExpanded&&<pre className="mt-2 whitespace-pre-wrap break-all text-[11px]">{JSON.stringify(vendor.rawPayload ?? vendor.data, null, 2)}</pre>}</details>}{vendor.link && <a href={vendor.link} target="_blank" rel="noreferrer" className="block text-primary hover:underline">{pt ? 'Ver fonte' : 'View source'}</a>}</div>}</details>
  </div>;
}
