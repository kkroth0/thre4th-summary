import { useState, type CSSProperties } from 'react';
import { Eye, EyeOff, Loader2, Trash2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { addCredentialKeys, removeCredentialKey, type CredentialPoolStatus } from '@/services/threatApi';
import { toast } from 'sonner';

export function CredentialPoolRow({ provider, pool, pt, onChanged }: { provider: { id: string; label: string }; pool?: CredentialPoolStatus; pt: boolean; onChanged: () => void }) {
  const [input, setInput] = useState(''), [visible, setVisible] = useState(false), [busy, setBusy] = useState(false), [open, setOpen] = useState(false);
  const keys = pool?.keys || [];
  const entries = input.split(/[\r\n,]+/).map(key => key.trim()).filter(Boolean);
  const count = new Set(entries).size;
  async function save() {
    setBusy(true);
    try { await addCredentialKeys(provider.id, entries); setInput(''); setOpen(false); onChanged(); toast.success(pt ? 'Chaves adicionadas ao roteamento.' : 'Keys added to routing.'); }
    catch (error) { toast.error(error instanceof Error ? error.message : 'Error'); }
    finally { setBusy(false); }
  }
  async function remove(id: string) {
    setBusy(true);
    try { await removeCredentialKey(provider.id, id); onChanged(); }
    catch (error) { toast.error(error instanceof Error ? error.message : 'Error'); }
    finally { setBusy(false); }
  }
  const states: Record<string, string> = pt ? { available: 'Disponível', busy: 'Em consulta', cooldown: 'Aguardando cota', authentication_error: 'Credencial recusada' } : { available: 'Available', busy: 'In use', cooldown: 'Awaiting quota', authentication_error: 'Credential rejected' };
  return <div className="mt-3 space-y-3">
    <div className="flex flex-wrap items-center gap-2 text-xs">
      <span className="mr-auto text-muted-foreground">{keys.length ? `${keys.length} ${pt ? 'chaves pessoais no roteamento' : 'personal routing keys'}` : pool?.effectiveCount ? `${pool.effectiveCount} ${pt ? 'chaves herdadas da configuração compartilhada' : 'keys inherited from shared configuration'}` : pt ? 'Nenhuma chave configurada.' : 'No keys configured.'}</span>
      <Button variant="outline" size="sm" disabled={busy} onClick={() => setOpen(value => !value)}>{open ? (pt ? 'Fechar' : 'Close') : (pt ? 'Adicionar chaves' : 'Add keys')}</Button>
    </div>
    {open && <div className="space-y-3 rounded-md border p-3">
      <label className="block text-xs font-medium" htmlFor={`credential-input-${provider.id}`}>{pt ? 'Cole as chaves adicionais, uma por linha' : 'Paste additional keys, one per line'}</label>
      <textarea id={`credential-input-${provider.id}`} value={input} onChange={event => setInput(event.target.value)} rows={5} maxLength={20500} spellCheck={false} autoComplete="off" autoCapitalize="none" disabled={busy} style={{ WebkitTextSecurity: visible ? 'none' : 'disc' } as CSSProperties} className="w-full resize-y rounded-md border bg-background p-3 font-mono text-xs" />
      <div className="flex flex-wrap items-center gap-2"><Button variant="ghost" size="sm" onClick={() => setVisible(value => !value)}>{visible ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}{pt ? (visible ? 'Ocultar' : 'Mostrar') : (visible ? 'Hide' : 'Show')}</Button><span className="mr-auto text-xs text-muted-foreground">{count}/50 · {pt ? 'duplicadas são ignoradas' : 'duplicates are ignored'}</span><Button size="sm" disabled={busy || !count || entries.length > 50 || count + keys.length > 50} onClick={() => void save()}>{busy && <Loader2 className="h-4 w-4 animate-spin" />}{pt ? 'Adicionar ao roteamento' : 'Add to routing'}</Button></div>
      <p className="text-xs leading-5 text-muted-foreground">{pt ? 'As chaves existentes são mantidas. Os valores ficam cifrados no servidor e não são devolvidos à interface.' : 'Existing keys are preserved. Values are encrypted on the server and never returned to the interface.'}</p>
    </div>}
    {!!keys.length && <details className="rounded-md border"><summary className="cursor-pointer px-3 py-2 text-xs">{pt ? 'Ver disponibilidade das chaves' : 'View key availability'} · {keys.filter(key => key.status === 'available').length}/{keys.length}</summary><ul className="max-h-72 divide-y overflow-y-auto border-t">{keys.map((key, index) => <li key={key.id} className="flex items-center gap-2 px-3 py-2 text-xs"><span className="font-medium">{pt ? 'Chave' : 'Key'} {index + 1}</span><span className={`mr-auto ${key.status === 'available' ? 'text-emerald-500' : 'text-amber-500'}`}>{states[key.status]}{key.retryAt && <span className="block text-muted-foreground">{new Date(key.retryAt).toLocaleString(pt ? 'pt-BR' : 'en-US')}</span>}</span><span className="text-muted-foreground">{key.usedToday} {pt ? 'chamadas hoje (UTC)' : 'calls today (UTC)'}</span><Button variant="ghost" size="icon" className="h-8 w-8" disabled={busy} aria-label={`${pt ? 'Remover chave' : 'Remove key'} ${index + 1} · ${provider.label}`} onClick={() => void remove(key.id)}><Trash2 className="h-3 w-3" /></Button></li>)}</ul></details>}
  </div>;
}
