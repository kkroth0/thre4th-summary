import { ArrowLeft, KeyRound, Loader2, Radar, Settings as SettingsIcon, ShieldCheck, SlidersHorizontal } from "lucide-react";
import { Link, Navigate, useSearchParams } from "react-router-dom";
import { AdminSettings } from "@/components/settings/AdminSettings";
import { ApiKeysSettings } from "@/components/settings/ApiKeysSettings";
import { MonitoringSettings } from "@/components/settings/MonitoringSettings";
import { PreferencesSettings } from "@/components/settings/PreferencesSettings";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageLayout } from "@/components/PageLayout";
import { useNavCatalog } from "@/components/Header";
import { useAuth } from "@/contexts/AuthContext";
import { useLanguage } from "@/contexts/LanguageContext";

type SettingsSection = "general" | "monitoring" | "api-keys" | "admin";

export default function Settings() {
  const { language, tr } = useLanguage();
  const { auth, loading } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const pt = language === "pt";
  // Todos os hooks antes de qualquer return: `loading` e o redirect abaixo
  // saem cedo, e um hook depois deles rodaria em alguns renders e não em outros.
  const { homeItem, navGroups } = useNavCatalog();

  if (loading) {
    return (
      <PageLayout width="max-w-4xl">
        <Card><CardContent className="flex items-center gap-2 p-6 text-muted-foreground"><Loader2 className="animate-spin" /> {pt ? "Verificando sessão…" : "Checking session…"}</CardContent></Card>
      </PageLayout>
    );
  }

  if (!auth.authenticated) return <Navigate to="/login" replace />;

  const requested = searchParams.get("section");
  const section: SettingsSection = requested === "api-keys"
    ? "api-keys"
    : requested === "monitoring"
      ? "monitoring"
      : requested === "admin" && auth.isAdmin
        ? "admin"
        : "general";

  // FLX-06: entrar aqui era saída sem volta — o botão do cabeçalho devolve
  // para /analyzer, não para a tela de onde se veio. Quem manda o link passa a
  // origem, e ela vira trilha.
  //
  // Só caminho interno: `//host` e `http://` sairiam do produto, e isso com um
  // parâmetro de URL é redirecionamento aberto.
  const rawFrom = searchParams.get("from") || "";
  const from = /^\/[^/]/.test(rawFrom) ? rawFrom : "";
  const fromLabel = [homeItem, ...navGroups.flatMap((g) => g.items)]
    .find((nav) => nav.path === from)?.label || "";

  const selectSection = (value: string) => {
    const next = value as SettingsSection;
    setSearchParams(next === "general" ? {} : { section: next }, { replace: true });
  };

  return (
    <PageLayout width="max-w-4xl">
      <div className="mb-7">
        {from && fromLabel && (
          <nav aria-label="trilha" className="mb-2 flex items-center gap-1.5 text-sm text-muted-foreground">
            <Link to={from} className="inline-flex items-center gap-1 hover:text-foreground">
              <ArrowLeft className="h-3.5 w-3.5" /> {fromLabel}
            </Link>
            <span aria-hidden>/</span>
            <span className="text-foreground">{tr({ pt: "Configurações", en: "Settings", es: "Configuración", fr: "Paramètres" })}</span>
          </nav>
        )}
        <h1 className="flex items-center gap-2 text-3xl font-bold"><SettingsIcon className="text-primary" /> {tr({ pt: "Configurações", en: "Settings", es: "Configuración", fr: "Paramètres" })}</h1>
        <p className="mt-1 text-muted-foreground">{tr({ pt: "Preferências, integrações e administração da sua conta.", en: "Account preferences, integrations, and administration.", es: "Preferencias, integraciones y administración de tu cuenta.", fr: "Préférences, intégrations et administration de votre compte." })}</p>
      </div>

      <Tabs value={section} onValueChange={selectSection}>
        <div className="mb-6 overflow-x-auto pb-1">
          <TabsList className="w-max justify-start">
            <TabsTrigger value="general"><SlidersHorizontal /> {tr({ pt: "Geral", en: "General", es: "General", fr: "Général" })}</TabsTrigger>
            <TabsTrigger value="monitoring"><Radar /> {tr({ pt: "Monitoramento", en: "Monitoring", es: "Monitoreo", fr: "Surveillance" })}</TabsTrigger>
            <TabsTrigger value="api-keys"><KeyRound /> {tr({ pt: "Chaves de API", en: "API Keys", es: "Claves de API", fr: "Clés API" })}</TabsTrigger>
            {auth.isAdmin ? <TabsTrigger value="admin"><ShieldCheck /> Admin</TabsTrigger> : null}
          </TabsList>
        </div>

        <TabsContent value="general" className="mt-0"><PreferencesSettings /></TabsContent>
        <TabsContent value="monitoring" className="mt-0"><MonitoringSettings /></TabsContent>
        <TabsContent value="api-keys" className="mt-0"><ApiKeysSettings /></TabsContent>
        {auth.isAdmin ? <TabsContent value="admin" className="mt-0"><AdminSettings /></TabsContent> : null}
      </Tabs>
    </PageLayout>
  );
}
