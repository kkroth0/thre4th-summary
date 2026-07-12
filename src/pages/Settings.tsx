import { useEffect, useState, useCallback } from "react";
import { Navigate } from "react-router-dom";
import { KeyRound, Loader2, CheckCircle2, Trash2, ExternalLink, Settings as SettingsIcon, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import {
  AlertDialog, AlertDialogTrigger, AlertDialogContent, AlertDialogHeader,
  AlertDialogFooter, AlertDialogTitle, AlertDialogDescription, AlertDialogAction,
  AlertDialogCancel,
} from "@/components/ui/alert-dialog";
import { PageLayout } from "@/components/PageLayout";
import { useLanguage } from "@/contexts/LanguageContext";
import { useAuth } from "@/contexts/AuthContext";
import { fetchApiKeys, saveApiKey, deleteApiKey, type ApiKeysState } from "@/services/threatApi";
import { toast } from "sonner";

interface Provider { id: string; label: string; url?: string; placeholder?: string; note?: { pt: string; en: string } }
interface Group { title: { pt: string; en: string }; items: Provider[] }

const CATALOG: Group[] = [
  {
    title: { pt: "Enriquecimento & Reputação", en: "Enrichment & Reputation" },
    items: [
      { id: "virustotal", label: "VirusTotal", url: "https://www.virustotal.com/gui/my-apikey" },
      { id: "abuseipdb", label: "AbuseIPDB", url: "https://www.abuseipdb.com/account/api" },
      { id: "shodan", label: "Shodan", url: "https://account.shodan.io/" },
      { id: "alienvault", label: "AlienVault OTX", url: "https://otx.alienvault.com/api" },
      { id: "pulsedive", label: "Pulsedive", url: "https://pulsedive.com/api/" },
      { id: "criminalip", label: "Criminal IP", url: "https://www.criminalip.io/" },
      { id: "censys", label: "Censys", url: "https://search.censys.io/account/api" },
    ],
  },
  {
    title: { pt: "Malware & Arquivos", en: "Malware & Files" },
    items: [
      { id: "hybridanalysis", label: "Hybrid Analysis", url: "https://www.hybrid-analysis.com/" },
      { id: "metadefender", label: "MetaDefender", url: "https://metadefender.opswat.com/" },
      { id: "threatfox", label: "ThreatFox (abuse.ch)", url: "https://threatfox.abuse.ch/" },
      { id: "urlhaus", label: "URLhaus (abuse.ch)", url: "https://urlhaus.abuse.ch/" },
    ],
  },
  {
    title: { pt: "Phishing & DNS", en: "Phishing & DNS" },
    items: [
      { id: "phishtank", label: "PhishTank", url: "https://www.phishtank.com/" },
      { id: "dnsdumpster", label: "DNSDumpster", url: "https://dnsdumpster.com/" },
      { id: "whois", label: "WHOIS", url: "" },
    ],
  },
];

const KeyRow = ({ p, configured, onChanged }: { p: Provider; configured: boolean; onChanged: () => void }) => {
  const { language } = useLanguage();
  const pt = language === "pt";
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);

  const save = async () => {
    const v = value.trim();
    if (!v) return;
    setBusy(true);
    try {
      await saveApiKey(p.id, v);
      setValue(""); setEditing(false);
      toast.success(pt ? `Chave ${p.label} salva` : `${p.label} key saved`);
      onChanged();
    } catch (e) {
      toast.error((e as Error).message || (pt ? "Falha ao salvar" : "Failed to save"));
    } finally { setBusy(false); }
  };

  const remove = async () => {
    await deleteApiKey(p.id);
    toast.success(pt ? `Chave ${p.label} removida` : `${p.label} key removed`);
    onChanged();
  };

  return (
    <div className="flex flex-col sm:flex-row sm:items-center gap-2.5 py-3.5">
      <div className="sm:w-52 shrink-0">
        <div className="flex items-center gap-2 font-medium text-sm">
          {p.label}
          {configured && <Badge variant="secondary" className="gap-1 h-5"><CheckCircle2 className="h-3 w-3 text-emerald-500" /> {pt ? "Ativa" : "Set"}</Badge>}
        </div>
        {p.url && (
          <a href={p.url} target="_blank" rel="noreferrer" className="text-xs text-muted-foreground hover:text-foreground inline-flex items-center gap-1 mt-0.5">
            {pt ? "obter chave" : "get key"} <ExternalLink className="h-3 w-3" />
          </a>
        )}
      </div>

      {configured && !editing ? (
        <div className="flex-1 flex items-center gap-2">
          <span className="flex-1 font-mono text-sm text-muted-foreground">••••••••••••••••</span>
          <Button variant="outline" size="sm" onClick={() => setEditing(true)}>{pt ? "Trocar" : "Change"}</Button>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="ghost" size="sm" className="text-muted-foreground hover:text-destructive"><Trash2 className="h-3.5 w-3.5" /></Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>{pt ? `Remover a chave ${p.label}?` : `Remove the ${p.label} key?`}</AlertDialogTitle>
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
        <div className="flex-1 flex items-center gap-2">
          <Input
            type="password" placeholder={p.placeholder || (pt ? "cole a chave…" : "paste key…")}
            value={value} onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") save(); }}
            className="flex-1"
          />
          <Button size="sm" onClick={save} disabled={busy || !value.trim()}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : (pt ? "Salvar" : "Save")}
          </Button>
          {configured && <Button variant="ghost" size="sm" onClick={() => { setEditing(false); setValue(""); }}>{pt ? "Cancelar" : "Cancel"}</Button>}
        </div>
      )}
    </div>
  );
};

const Settings = () => {
  const { language } = useLanguage();
  const { auth, loading: authLoading, refresh } = useAuth();
  const pt = language === "pt";

  const [keys, setKeys] = useState<ApiKeysState>({});
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setKeys(await fetchApiKeys());
    setLoading(false);
  }, []);
  useEffect(() => { if (auth.authenticated) load(); }, [auth.authenticated, load]);

  const onChanged = () => { load(); refresh(); };

  const shell = (children: React.ReactNode) => (
    <PageLayout width="max-w-3xl">{children}</PageLayout>
  );

  if (authLoading) {
    return shell(<Card><CardContent className="p-6 flex items-center gap-2 text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> {pt ? "Verificando sessão…" : "Checking session…"}</CardContent></Card>);
  }
  if (!auth.authenticated) return <Navigate to="/login" replace />;

  const total = CATALOG.reduce((n, g) => n + g.items.length, 0);
  const set = Object.values(keys).filter(Boolean).length;

  return shell(
    <>
      <div className="mb-6 flex items-start justify-between gap-3">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2"><SettingsIcon className="h-7 w-7 text-primary" /> {pt ? "Configurações" : "Settings"}</h1>
          <p className="text-muted-foreground mt-1">{pt ? "Suas chaves de API (BYOK). Cifradas no servidor e nunca exibidas de volta." : "Your API keys (BYOK). Encrypted server-side and never shown back."}</p>
        </div>
        <Badge variant="secondary" className="shrink-0 mt-1">{set}/{total} {pt ? "config." : "set"}</Badge>
      </div>

      <div className="rounded-lg border border-border/60 bg-muted/20 px-4 py-3 mb-6 text-sm text-muted-foreground flex items-start gap-2.5">
        <ShieldCheck className="h-4 w-4 mt-0.5 text-primary shrink-0" />
        {pt
          ? "As chaves são armazenadas cifradas (AES) e vinculadas só à sua conta. Opcionais — usadas nos lookups de vendor. O gerador de relatórios roda na chave do servidor."
          : "Keys are stored encrypted (AES) and tied only to your account. Optional — used for vendor lookups. The report generator runs on the server's key."}
      </div>

      {loading ? (
        <Card><CardContent className="p-6 flex items-center gap-2 text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> {pt ? "Carregando chaves…" : "Loading keys…"}</CardContent></Card>
      ) : (
        <div className="space-y-5">
          {CATALOG.map((g) => (
            <Card key={g.title.en}>
              <CardHeader className="pb-1">
                <CardTitle className="text-base flex items-center gap-2"><KeyRound className="h-4 w-4 text-primary" /> {pt ? g.title.pt : g.title.en}</CardTitle>
              </CardHeader>
              <CardContent className="pt-0 divide-y divide-border/50">
                {g.items.map((p) => (
                  <KeyRow key={p.id} p={p} configured={!!keys[p.id]} onChanged={onChanged} />
                ))}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </>
  );
};

export default Settings;
