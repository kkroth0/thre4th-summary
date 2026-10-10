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
import { deleteApiKey, fetchApiKeys, saveApiKey, type ApiKeysState } from "@/services/threatApi";

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

function KeyRow({ provider, configured, onChanged }: { provider: Provider; configured: boolean; onChanged: () => void }) {
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

      {configured && !editing ? (
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
  const { language } = useLanguage();
  const { refresh } = useAuth();
  const pt = language === "pt";
  const [keys, setKeys] = useState<ApiKeysState>({});
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      setKeys(await fetchApiKeys());
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Falha ao carregar chaves");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const onChanged = () => {
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
              ? "Use suas próprias chaves e cotas do Shodan e do urlscan.io."
              : "Use your own Shodan and urlscan.io keys and quotas."}
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
                {group.items.map((provider) => <KeyRow key={provider.id} provider={provider} configured={!!keys[provider.id]} onChanged={onChanged} />)}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
      <div className="flex items-start gap-2 text-xs leading-relaxed text-muted-foreground"><ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" /><p>{pt ? "Sua chave é criptografada e vinculada à sua conta. Sem uma chave pessoal, as consultas usam a chave da plataforma." : "Your key is encrypted and tied to your account. Without a personal key, lookups use the platform key."}</p></div>
    </div>
  );
}
