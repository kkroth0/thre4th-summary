import { useEffect, useState } from "react";
import { CheckCircle2, Loader2, Plug, Unlock, XCircle } from "lucide-react";
import { toast } from "sonner";
import AllowlistManager from "@/components/AllowlistManager";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/contexts/AuthContext";
import { useLanguage } from "@/contexts/LanguageContext";
import { fetchIntegrationStatus, fetchPremiumOpen, setPremiumOpen, type IntegrationStatus } from "@/services/threatApi";

export function AdminSettings() {
  const { language } = useLanguage();
  const { refresh } = useAuth();
  const pt = language === "pt";
  const [integrations, setIntegrations] = useState<IntegrationStatus[]>([]);
  const [keyless, setKeyless] = useState<string[]>([]);
  const [premiumOpen, setOpen] = useState(false);
  const [savingGate, setSavingGate] = useState(false);
  const [loadingIntegrations, setLoadingIntegrations] = useState(true);
  const [integrationError, setIntegrationError] = useState(false);
  const [gateLoaded, setGateLoaded] = useState(false);

  const loadIntegrations = () => {
    setLoadingIntegrations(true);
    setIntegrationError(false);
    fetchIntegrationStatus()
      .then((result) => {
        setIntegrations(result.integrations);
        setKeyless(result.keyless);
      })
      .catch(() => setIntegrationError(true))
      .finally(() => setLoadingIntegrations(false));
  };

  useEffect(() => {
    loadIntegrations();
    fetchPremiumOpen().then(value => { setOpen(value); setGateLoaded(true); }).catch(() => toast.error(pt ? "Falha ao carregar acesso premium" : "Failed to load premium access"));
    // Load once when entering the administration section.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // O gate vale no servidor, então a sessão precisa reler isPremium pra UI
  // acompanhar sem F5.
  const toggleGate = async (next: boolean) => {
    setSavingGate(true);
    try {
      setOpen(await setPremiumOpen(next));
      await refresh();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Falha ao salvar");
    } finally {
      setSavingGate(false);
    }
  };

  const missing = integrations.filter((integration) => !integration.configured && integration.required).length;

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h2 className="text-sm font-semibold">{pt ? "Administração" : "Administration"}</h2>
        <p className="mt-1.5 text-sm text-muted-foreground">{pt ? "Controle o acesso e acompanhe os serviços da plataforma." : "Control access and monitor platform services."}</p>
      </div>

      <AllowlistManager />

      <Card className="rounded-sm shadow-none">
        <CardContent className="flex items-start gap-3 p-4">
          <Unlock className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 text-sm font-semibold" id="premium-access-heading">
              {pt ? "Premium para todas as contas" : "Premium for every account"}
            </div>
            <div className="text-sm text-muted-foreground">
              {pt
                ? "Ao ativar, qualquer usuário conectado terá acesso premium, mesmo fora da lista de autorizados."
                : "When enabled, every signed-in user gets premium access, including accounts outside the authorized list."}
            </div>
          </div>
          <Switch
            checked={premiumOpen}
            disabled={savingGate || !gateLoaded}
            onCheckedChange={toggleGate}
            aria-labelledby="premium-access-heading"
          />
        </CardContent>
      </Card>

      <Card className="overflow-hidden rounded-sm shadow-none">
        <CardContent className="p-0">
          <div className="flex items-start gap-3 border-b border-border p-4">
            <Plug className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2 text-sm font-semibold">
                {pt ? "Serviços de inteligência" : "Intelligence services"}
                {missing > 0 ? <Badge variant="outline" className="text-[10px]">{missing} {pt ? "sem chave" : "missing"}</Badge> : null}
              </div>
              <div className="text-sm text-muted-foreground">
                {pt ? "Status das integrações compartilhadas. As credenciais são gerenciadas no servidor." : "Shared integration status. Credentials are managed on the server."}
              </div>
            </div>
          </div>

          <div className="divide-y divide-border">
            {loadingIntegrations ? <div className="flex items-center gap-2 p-5 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />{pt ? "Carregando serviços…" : "Loading services…"}</div> : integrationError ? <div className="flex flex-wrap items-center justify-between gap-3 p-5 text-sm text-muted-foreground"><span>{pt ? "Não foi possível carregar os serviços." : "Unable to load services."}</span><Button variant="outline" size="sm" onClick={loadIntegrations}>{pt ? "Tentar novamente" : "Try again"}</Button></div> : integrations.map((integration) => (
              <div key={integration.name} className="flex items-center gap-3 px-5 py-3 sm:px-6">
                {integration.configured ? <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" /> : <XCircle className="h-4 w-4 shrink-0 text-muted-foreground" />}
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-medium">{integration.name}</div>
                  {integration.note && <div className="mt-0.5 text-xs text-muted-foreground">{integration.note}</div>}
                </div>
                <Badge variant={integration.configured ? "secondary" : "outline"} className="shrink-0 text-[10px]">
                  {integration.configured ? (pt ? "ativo" : "active") : integration.required ? (pt ? "faltando" : "missing") : (pt ? "opcional" : "optional")}
                </Badge>
              </div>
            ))}
            {keyless.length > 0 ? (
              <div className="bg-secondary/30 p-5 sm:p-6"><p className="mb-2 text-xs font-medium text-muted-foreground">{pt ? "Fontes públicas · sem chave de API" : "Public sources · no API key required"}</p><div className="flex flex-wrap gap-1.5">{keyless.map(name => <Badge key={name} variant="outline" className="bg-background text-xs font-normal">{name}</Badge>)}</div></div>
            ) : null}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
