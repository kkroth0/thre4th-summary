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
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
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
}

interface Group {
  title: { pt: string; en: string };
  items: Provider[];
}

// Só o provider cuja chave é REALMENTE usada numa consulta. Os outros doze
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
    await deleteApiKey(provider.id);
    toast.success(pt ? `Chave ${provider.label} removida` : `${provider.label} key removed`);
    onChanged();
  };

  return (
    <div className="flex flex-col gap-2.5 py-3.5 sm:flex-row sm:items-center">
      <div className="shrink-0 sm:w-52">
        <div className="flex items-center gap-2 text-sm font-medium">
          {provider.label}
          {configured ? (
            <Badge variant="secondary" className="h-5 gap-1">
              <CheckCircle2 className="text-emerald-500" /> {pt ? "Ativa" : "Set"}
            </Badge>
          ) : null}
        </div>
        {provider.url ? (
          <a href={provider.url} target="_blank" rel="noreferrer" className="mt-0.5 inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
            {pt ? "obter chave" : "get key"} <ExternalLink />
          </a>
        ) : null}
      </div>

      {configured && !editing ? (
        <div className="flex flex-1 items-center gap-2">
          <span className="flex-1 font-mono text-sm text-muted-foreground">••••••••••••••••</span>
          <Button variant="outline" size="sm" onClick={() => setEditing(true)}>{pt ? "Trocar" : "Change"}</Button>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="ghost" size="sm" className="text-muted-foreground hover:text-destructive"><Trash2 /><span className="sr-only">{pt ? "Remover" : "Remove"}</span></Button>
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
        <div className="flex flex-1 items-center gap-2">
          <Input
            type="password"
            placeholder={provider.placeholder || (pt ? "cole a chave…" : "paste key…")}
            value={value}
            onChange={(event) => setValue(event.target.value)}
            onKeyDown={(event) => { if (event.key === "Enter") save(); }}
            className="flex-1"
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
    setKeys(await fetchApiKeys());
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const onChanged = () => {
    load();
    refresh();
  };

  const total = CATALOG.reduce((count, group) => count + group.items.length, 0);
  const configured = Object.values(keys).filter(Boolean).length;

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold">{pt ? "Chaves de API" : "API Keys"}</h2>
          {/* FLX-07: as chaves apareciam em dois lugares — aqui e em Admin >
              Integrações — sem dizer qual vence quando as duas existem. A regra
              está no código (getUserApiKey(...) || process.env), então ela pode
              ser dita com todas as letras. */}
          <p className="mt-1 text-sm text-muted-foreground">
            {pt
              ? "Sua chave, cifrada no servidor. Ela tem precedência sobre a chave da plataforma nos scans de exposição; sem ela, a plataforma usa a própria."
              : "Your key, encrypted on the server. It takes precedence over the platform key in exposure scans; without it, the platform uses its own."}
          </p>
        </div>
        <Badge variant="secondary" className="mt-1 shrink-0">{configured}/{total} {pt ? "config." : "set"}</Badge>
      </div>

      <Alert>
        <ShieldCheck />
        <AlertDescription>
          {pt
            ? "As chaves são armazenadas cifradas (AES) e vinculadas à sua conta. Elas são opcionais e usadas nos lookups de vendor."
            : "Keys are stored encrypted (AES) and tied to your account. They are optional and used for vendor lookups."}
        </AlertDescription>
      </Alert>

      {loading ? (
        <Card><CardContent className="flex items-center gap-2 p-6 text-muted-foreground"><Loader2 className="animate-spin" /> {pt ? "Carregando chaves…" : "Loading keys…"}</CardContent></Card>
      ) : (
        <div className="flex flex-col gap-5">
          {CATALOG.map((group) => (
            <Card key={group.title.en}>
              <CardHeader className="pb-1">
                <CardTitle className="flex items-center gap-2 text-base"><KeyRound /> {pt ? group.title.pt : group.title.en}</CardTitle>
              </CardHeader>
              <CardContent className="divide-y divide-border/50 pt-0">
                {group.items.map((provider) => <KeyRow key={provider.id} provider={provider} configured={!!keys[provider.id]} onChanged={onChanged} />)}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
