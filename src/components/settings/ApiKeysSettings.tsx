import { useQueryClient } from '@tanstack/react-query';
import { useCallback, useEffect, useState } from "react";
import { CheckCircle2, ExternalLink, KeyRound, Loader2, ShieldCheck, Trash2 } from "lucide-react";
import { toast } from "sonner";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { LoadingRows } from "@/components/LoadingState";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/contexts/AuthContext";
import { useLanguage } from "@/contexts/LanguageContext";
import { deleteApiKey, fetchApiKeys, saveApiKey, fetchAxurImportStatus, type AxurImportStatus, type ApiKeysState } from "@/services/threatApi";

import { CredentialPoolRow } from './CredentialPoolRow';
import { fetchCredentialPools, type CredentialPoolStatus } from '@/services/threatApi';
const POOL_IDS = new Set(['virustotal','abuseipdb','otx','abuse_ch','threatfox','urlhaus','malwarebazaar']);

interface Provider {
  id: string;
  label: string;
  url?: string;
  placeholder?: string;
  description?: { pt: string; en: string };
}

interface Group {
  title: { pt: string; en: string };
  items: Provider[];
}

// Só providers cuja chave é REALMENTE usada numa consulta. Os outros doze
// ficavam aqui, guardavam a chave cifrada e apareciam como "configurado" —
// mas nenhuma rota do server os lia, todas leem só a env. Oferecer campo que
// não faz nada é pior do que não oferecer.
const CATALOG: Group[] = [
  {
    title: { pt: 'Coleta contínua de inteligência', en: 'Continuous intelligence collection' },
    items: [
      { id:'axur',label:'Axur',url:'https://docs.axur.com/en/axur/api/',placeholder:'Axur API Key',description:{pt:'Importa os IOCs e seus relatórios para a sua base privada, com retomada automática. Na Axur, realiza apenas consultas de leitura.',en:'Imports IOCs and linked insights into your private inventory, with automatic resume. Axur requests are read-only.'} },
      { id:'otx',label:'AlienVault OTX',url:'https://otx.alienvault.com/api',placeholder:'OTX API Key',description:{pt:'Usada nas consultas e na coleta contínua dos seus pulsos. Evidências privadas ficam vinculadas à sua conta.',en:'Used for lookups and continuous pulse collection. Private evidence remains scoped to your account.'} },
      { id:'abuseipdb',label:'AbuseIPDB',url:'https://www.abuseipdb.com/account/api',placeholder:'API Key',description:{pt:'Acrescenta reputação de IPs às consultas e à base de IOCs. A coleta respeita as cotas da sua chave.',en:'Adds IP reputation to lookups and the IOC inventory. Collection respects your key quota.'} },
    ],
  },
  {
    title: { pt: 'Inteligência de malware', en: 'Malware intelligence' },
    items: [{ id: 'abuse_ch', label: 'Abuse.ch', url: 'https://auth.abuse.ch/', placeholder: 'Auth-Key',
      description: { pt: 'Usa sua Auth-Key no MalwareBazaar, ThreatFox e URLhaus, incluindo buscas de famílias e hashes. A chave é armazenada cifrada por conta.', en: 'Uses your Auth-Key for MalwareBazaar, ThreatFox and URLhaus, including family and hash lookups. The key is encrypted per account.' } }],
  },
  { title: { pt: 'Enriquecimento e chaves dedicadas', en: 'Enrichment and dedicated keys' }, items: [
    { id: 'virustotal', label: 'VirusTotal', url: 'https://www.virustotal.com/gui/my-apikey' },
    ...[{ id: 'threatfox', label: 'ThreatFox' }, { id: 'urlhaus', label: 'URLhaus' }, { id: 'malwarebazaar', label: 'MalwareBazaar' }].map(provider => ({ ...provider, url: 'https://auth.abuse.ch/', description: { pt: 'Opcional: cadastre um conjunto dedicado. Sem ele, esta fonte usa as chaves compartilhadas de Abuse.ch acima.', en: 'Optional: configure a dedicated pool. Otherwise this source uses the shared Abuse.ch keys above.' } })),
  ] },
  {
    title: { pt: "Superfície de Ataque", en: "Attack Surface" },
    items: [
      { id: "shodan", label: "Shodan", url: "https://account.shodan.io/" },
    ],
  },
  {
    title: { pt: "Vigilância de marcas", en: "Brand monitoring" },
    items: [
      {
        id: "urlscan", label: "urlscan.io", url: "https://urlscan.io/user/profile/",
        description: {
          pt: "Usa sua cota nas buscas manuais e automáticas por domínios suspeitos relacionados às marcas dos seus perfis. Consulta páginas já escaneadas pelo urlscan.io.",
          en: "Uses your quota for manual and automatic searches for suspicious domains related to your profiles' brands. Searches pages already scanned by urlscan.io.",
        },
      },
    ],
  },
];

function AxurProgress() {
  const { language } = useLanguage();
  const pt = language === 'pt';
  const [progress, setProgress] = useState<AxurImportStatus | null>(null);
  useEffect(() => {
    let active = true;
    const refresh = () => { void fetchAxurImportStatus().then(value => { if (active) setProgress(value); }).catch(() => {}); };
    refresh();
    const interval = window.setInterval(refresh, 15000);
    return () => { active = false; window.clearInterval(interval); };
  }, []);
  if (!progress) return null;
  const labels = pt ? { pending:'Aguardando importação', running:'Importando', retrying:'Aguardando nova tentativa', complete:'Varredura concluída' }
    : { pending:'Waiting to import', running:'Importing', retrying:'Waiting to retry', complete:'Scan complete' };
  const format = (value: number) => value.toLocaleString(pt ? 'pt-BR' : 'en-US');
  const stages=pt?{iocs:'Consultando IOCs na Axur',insights:'Consultando relatórios relacionados',conversion:'Preparando correlações',ingest:'Salvando na base'}
    :{iocs:'Reading IOCs from Axur',insights:'Reading related reports',conversion:'Preparing correlations',ingest:'Saving to the database'};
  return <div role="status" className="rounded-md border border-border bg-secondary/30 px-3 py-2 text-xs leading-relaxed text-muted-foreground">
    <p className="font-medium text-foreground">{labels[progress.status]}</p>
    <p>{format(progress.processed)}{progress.total !== undefined ? ` / ${format(progress.total)}` : ''} {pt ? 'registros percorridos' : 'records scanned'} · {format(progress.observations || 0)} {pt ? 'evidências processadas' : 'evidence records processed'}</p>
    {progress.error && <p>{progress.error}</p>}
    {progress.status === 'running' && progress.activeStage && <p>{stages[progress.activeStage]}{progress.pageSize ? ` · ${format(progress.pageSize)} ${pt ? 'registros por lote' : 'records per batch'}` : ''}</p>}
    {progress.status === 'retrying' && progress.nextAttemptAt && <p>{pt ? 'Nova tentativa a partir de ' : 'Next retry from '}{new Date(progress.nextAttemptAt).toLocaleTimeString(pt ? 'pt-BR' : 'en-US', { hour:'2-digit', minute:'2-digit' })}{progress.pageSize ? ` · ${format(progress.pageSize)} ${pt ? 'registros por lote' : 'records per batch'}` : ''}</p>}
    <p>{pt ? 'Os IOCs são deduplicados na base. A contagem acima acompanha a leitura das páginas da fonte.' : 'IOCs are deduplicated in the inventory. Counts above track source pages.'}</p>
  </div>;
}

function KeyRow({ provider, configured, pool, onChanged }: { provider: Provider; configured: boolean; pool?: CredentialPoolStatus; onChanged: () => void }) {
  const { language } = useLanguage();
  const pt = language === "pt";
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);

  const save = async () => {
    const nextValue = value.trim();
    if (!nextValue) return;
    setBusy(true);
    try {
      await saveApiKey(provider.id, nextValue);
      setValue("");
      setEditing(false);
      toast.success(pt ? `Chave ${provider.label} salva` : `${provider.label} key saved`);
      onChanged();
    } catch (error) {
      toast.error((error as Error).message || (pt ? "Falha ao salvar" : "Failed to save"));
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    setBusy(true);
    try {
      await deleteApiKey(provider.id);
      toast.success(pt ? `Chave ${provider.label} removida` : `${provider.label} key removed`);
      onChanged();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : (pt ? "Falha ao remover" : "Failed to remove"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col gap-4 py-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2 text-sm font-medium">
          {provider.label}
          {configured ? (
            <Badge variant="outline" className="h-5 gap-1 border-emerald-500/20 bg-emerald-500/5 text-xs">
              <CheckCircle2 className="h-3 w-3 text-emerald-500" /> {pt ? "Conectada" : "Connected"}
            </Badge>
          ) : null}
        </div>
        {provider.url ? (
          <a href={provider.url} target="_blank" rel="noreferrer" className="inline-flex shrink-0 items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
            {pt ? "Obter chave" : "Get key"} <ExternalLink className="h-3 w-3" />
          </a>
        ) : null}
      </div>

      {provider.description ? <p className="text-xs leading-relaxed text-muted-foreground">{pt ? provider.description.pt : provider.description.en}</p> : null}
      {provider.id === 'axur' && configured && <AxurProgress />}

      {POOL_IDS.has(provider.id) ? <CredentialPoolRow provider={provider} pool={pool} pt={pt} onChanged={onChanged} /> : configured && !editing ? (
        <div className="flex flex-1 items-center gap-2">
          <span className="flex-1 rounded-md border border-border bg-secondary/40 px-3 py-2 font-mono text-sm tracking-wider text-muted-foreground">••••••••••••</span>
          <Button variant="outline" size="sm" disabled={busy} onClick={() => setEditing(true)}>{pt ? "Alterar" : "Change"}</Button>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="ghost" size="sm" disabled={busy} className="text-muted-foreground hover:text-destructive"><Trash2 /><span className="sr-only">{pt ? "Remover" : "Remove"}</span></Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>{pt ? `Remover a chave ${provider.label}?` : `Remove the ${provider.label} key?`}</AlertDialogTitle>
                <AlertDialogDescription>{pt ? "Você pode adicionar outra depois." : "You can add another one later."}</AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>{pt ? "Cancelar" : "Cancel"}</AlertDialogCancel>
                <AlertDialogAction onClick={remove}>{pt ? "Remover" : "Remove"}</AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          <Input
            type="password"
            aria-label={pt ? `Chave de API ${provider.label}` : `${provider.label} API key`}
            placeholder={provider.placeholder || (pt ? "cole a chave…" : "paste key…")}
            value={value}
            onChange={(event) => setValue(event.target.value)}
            onKeyDown={(event) => { if (event.key === "Enter") save(); }}
            className="min-w-0 flex-1 basis-40"
          />
          <Button size="sm" onClick={save} disabled={busy || !value.trim()}>
            {busy ? <Loader2 className="animate-spin" /> : (pt ? "Salvar" : "Save")}
          </Button>
          {configured ? <Button variant="ghost" size="sm" onClick={() => { setEditing(false); setValue(""); }}>{pt ? "Cancelar" : "Cancel"}</Button> : null}
        </div>
      )}
    </div>
  );
}

export function ApiKeysSettings() {
  const queryClient = useQueryClient();
  const { language } = useLanguage();
  const { refresh } = useAuth();
  const pt = language === "pt";
  const [keys, setKeys] = useState<ApiKeysState>({});
  const [pools, setPools] = useState<Record<string, CredentialPoolStatus>>({});
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const [nextKeys, nextPools] = await Promise.all([fetchApiKeys(), fetchCredentialPools()]);
      setKeys(nextKeys); setPools(nextPools);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Falha ao carregar chaves");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); const timer = setInterval(() => { if (document.visibilityState === 'visible') void load(); }, 15000); return () => clearInterval(timer); }, [load]);

  const onChanged = () => {
    void queryClient.invalidateQueries({ predicate: query => ['malware-catalog', 'malware-family', 'malware-sample', 'cidr-shodan', 'cidr-abuse'].includes(String(query.queryKey[0])) });
    load();
    refresh();
  };

  const total = CATALOG.reduce((count, group) => count + group.items.length, 0);
  const configured = CATALOG.flatMap(group => group.items).filter(provider => !!keys[provider.id]).length;

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold">{pt ? "Chaves de API" : "API keys"}</h2>
          {/* FLX-07: as chaves apareciam em dois lugares — aqui e em Admin >
              Integrações — sem dizer qual vence quando as duas existem. A regra
              está no código (getUserApiKey(...) || process.env), então ela pode
              ser dita com todas as letras. */}
          <p className="mt-1 text-sm text-muted-foreground">
            {pt
              ? "Conecte suas fontes e adicione até 50 chaves por fonte. As consultas distribuem a carga entre credenciais disponíveis e respeitam a espera informada pelo provedor."
              : "Connect your sources to query and expand your intelligence inventory."}
          </p>
        </div>
        <Badge variant="outline" className="mt-1 shrink-0 text-xs">{loading ? "…" : `${configured}/${total}`} {pt ? "conectada" : "connected"}</Badge>
      </div>

      {loading ? (
        <LoadingRows rows={4} />
      ) : (
        <div className="flex flex-col gap-5">
          {CATALOG.map((group) => (
            <Card key={group.title.en} className="overflow-hidden rounded-sm shadow-none">
              <CardHeader className="border-b border-border px-4 py-3">
                <CardTitle className="flex items-center gap-2 text-sm"><KeyRound className="h-4 w-4 text-muted-foreground" /> {pt ? group.title.pt : group.title.en}</CardTitle>
              </CardHeader>
              <CardContent className="divide-y divide-border/50 px-4 pb-2 pt-0">
                {group.items.map((provider) => <KeyRow key={provider.id} provider={provider} configured={!!keys[provider.id]} pool={pools[provider.id]} onChanged={onChanged} />)}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
      <div className="flex items-start gap-2 text-xs leading-relaxed text-muted-foreground"><ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" /><p>{pt ? "Sua chave é criptografada e vinculada à sua conta. Sem uma chave pessoal, as consultas usam a chave da plataforma." : "Your key is encrypted and tied to your account. Without a personal key, lookups use the platform key."}</p></div>
    </div>
  );
}
