import { ArrowLeft, Bot, Building2, ChevronRight, KeyRound, Loader2, Monitor, Rss, ShieldCheck, Target, UserRound } from "lucide-react";
import { Link, Navigate, useSearchParams } from "react-router-dom";
import { AdminSettings } from "@/components/settings/AdminSettings";
import { ApiKeysSettings } from "@/components/settings/ApiKeysSettings";
import { AssistantSettings } from "@/components/settings/AssistantSettings";
import { MonitoringSettings } from "@/components/settings/MonitoringSettings";
import { PreferencesSettings } from "@/components/settings/PreferencesSettings";
import { OrgProfileEditor } from "@/components/settings/OrgProfileEditor";
import { MonitoredAssetsSettings } from "@/components/settings/MonitoredAssetsSettings";
import { PageLayout } from "@/components/PageLayout";
import { useNavCatalog } from "@/components/useNavCatalog";
import { useAuth } from "@/contexts/AuthContext";
import { useLanguage } from "@/contexts/LanguageContext";
import { cn } from "@/lib/utils";

type SettingsSection = "general" | "monitoring" | "organization" | "assets" | "api-keys" | "assistant" | "admin";
type SettingsGroup = { label: string; items: { id: SettingsSection; icon: typeof Rss; label: string; description: string }[] };

export default function Settings() {
  const { language, tr } = useLanguage();
  const { auth, loading } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const { homeItem, navGroups } = useNavCatalog();
  const pt = language === "pt";

  if (loading) return <PageLayout width="max-w-6xl"><div className="flex items-center gap-2 py-12 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />{pt ? "Verificando sessão…" : "Checking session…"}</div></PageLayout>;
  if (!auth.authenticated) return <Navigate to="/login" replace />;

  const requested = searchParams.get("section");
  // Only accept local paths for the return link.
  const rawFrom = searchParams.get("from") || "";
  const from = /^\/[^/]/.test(rawFrom) ? rawFrom : "";
  const fromLabel = [homeItem, ...navGroups.flatMap(g => g.items)].find(nav => nav.path === from)?.label || "";
  const selectSection = (value: SettingsSection) => {
    const next = new URLSearchParams(searchParams);
    next.set("section", value);
    setSearchParams(next, { replace: true });
  };
  const groups: SettingsGroup[] = [
    { label: pt ? "Monitoramento" : "Monitoring", items: [
      { id: "monitoring" as const, icon: Rss, label: pt ? "Notícias" : "News", description: pt ? "Escolha os fornecedores do feed e consulte as fontes de notícias." : "Choose feed vendors and browse news sources." },
      { id: "organization" as const, icon: Building2, label: pt ? "Organização" : "Organization", description: pt ? "Defina os setores, regiões, tecnologias e marcas dos seus perfis." : "Define the sectors, regions, technologies and brands in your profiles." },
      { id: "assets" as const, icon: Target, label: pt ? "Ativos monitorados" : "Monitored assets", description: pt ? "Acompanhe os domínios e IPs da sua watchlist de exposição." : "Track the domains and IPs in your exposure watchlist." },
    ] },
    { label: pt ? "Sua conta" : "Your account", items: [
      { id: "api-keys" as const, icon: KeyRound, label: tr({ pt: "Chaves de API", en: "API keys", es: "Claves de API", fr: "Clés API" }), description: pt ? "Conecte suas chaves pessoais aos serviços de inteligência." : "Connect your personal keys to intelligence services." },
      { id: "assistant" as const, icon: Bot, label: pt ? "IA e Telegram" : "AI & Telegram", description: pt ? "Consulte o assistente, conecte seu bot e configure os briefings." : "Query the assistant, connect your bot and set up briefings." },
      { id: "general" as const, icon: Monitor, label: tr({ pt: "Interface", en: "Interface", es: "Interfaz", fr: "Interface" }), description: pt ? "Ajuste o idioma e a aparência neste dispositivo." : "Adjust language and appearance on this device." },
    ] },
    ...(auth.isAdmin ? [{ label: pt ? "Plataforma" : "Platform", items: [
      { id: "admin" as const, icon: ShieldCheck, label: pt ? "Administração" : "Administration", description: pt ? "Gerencie permissões de acesso e acompanhe os serviços compartilhados." : "Manage access permissions and monitor shared services." },
    ] }] : []),
  ];
  const sections = groups.flatMap(group => group.items);
  const section: SettingsSection = sections.find(item => item.id === requested)?.id ?? "monitoring";
  const activeSection = sections.find(item => item.id === section)!;
  const ActiveIcon = activeSection.icon;

  return (
    <PageLayout width="max-w-7xl" className="lg:pt-6" breadcrumbItems={[{ label: activeSection.label }]}>
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3 border-b border-border pb-5">
        <div>
          {from && fromLabel && <Link to={from} className="mb-3 inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" />{fromLabel}</Link>}
          <h1 className="text-xl font-semibold tracking-tight">{tr({ pt: "Configurações", en: "Settings", es: "Configuración", fr: "Paramètres" })}</h1>
          <p className="mt-1.5 text-sm text-muted-foreground">{pt ? "Personalize seu monitoramento, integrações e preferências." : "Customize your monitoring, integrations and preferences."}</p>
        </div>
        <span className="inline-flex max-w-full items-center gap-2 rounded-md border border-border bg-card px-3 py-2 text-xs text-muted-foreground"><UserRound aria-hidden="true" className="h-3.5 w-3.5 shrink-0" /><span className="truncate font-mono">{auth.login}</span></span>
      </div>
      <div className="grid items-start gap-6 lg:grid-cols-[232px_minmax(0,1fr)] lg:gap-8">
        <div className="lg:hidden">
          <label htmlFor="settings-section" className="mb-2 block text-xs font-medium text-muted-foreground">{pt ? "Seção de configurações" : "Settings section"}</label>
          <select id="settings-section" value={section} onChange={event => selectSection(event.target.value as SettingsSection)} className="h-11 w-full rounded-md border border-input bg-card px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
            {groups.map(group => <optgroup key={group.label} label={group.label}>{group.items.map(item => <option key={item.id} value={item.id}>{item.label}</option>)}</optgroup>)}
          </select>
        </div>
        <nav aria-label={pt ? "Seções de configurações" : "Settings sections"} className="hidden space-y-4 rounded-md border border-border bg-card p-3 lg:sticky lg:top-20 lg:block">
          {groups.map(group => <div key={group.label}>
            <p className="mb-2 px-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{group.label}</p>
            <div className="grid grid-cols-2 gap-1 sm:grid-cols-3 lg:grid-cols-1">
              {group.items.map(({ id, icon: Icon, label }) => <button key={id} type="button" onClick={() => selectSection(id)} aria-current={section === id ? "page" : undefined} aria-controls="settings-content"
                className={cn("flex min-h-10 items-center gap-2 rounded px-2.5 py-2 text-left text-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring lg:text-sm", section === id ? "bg-primary/10 font-semibold text-primary" : "text-muted-foreground hover:bg-muted hover:text-foreground")}>
                <Icon aria-hidden="true" className="h-4 w-4 shrink-0" /><span className="min-w-0">{label}</span><ChevronRight aria-hidden="true" className={cn("ml-auto hidden h-3.5 w-3.5 shrink-0 lg:block", section !== id && "invisible")} />
              </button>)}
            </div>
          </div>)}
        </nav>
        <section id="settings-content" aria-labelledby="settings-section-title" className="min-w-0">
          <div className="mb-5 flex items-start gap-3">
            <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md border border-primary/15 bg-primary/5 text-primary"><ActiveIcon aria-hidden="true" className="h-5 w-5" /></span>
            <div className="min-w-0"><h2 id="settings-section-title" className="text-base font-semibold tracking-tight">{activeSection.label}</h2><p className="mt-1 text-sm leading-relaxed text-muted-foreground">{activeSection.description}</p></div>
          </div>
          <div className="min-w-0 [&_button]:rounded-sm [&_input]:rounded-sm" key={section}>
            {section === "general" && <PreferencesSettings />}
            {section === "monitoring" && <MonitoringSettings />}
            {section === "organization" && <OrgProfileEditor />}
            {section === "assets" && <MonitoredAssetsSettings />}
            {section === "api-keys" && <ApiKeysSettings />}
            {section === "assistant" && <AssistantSettings />}
            {section === "admin" && auth.isAdmin && <AdminSettings />}
          </div>
        </section>
      </div>
    </PageLayout>
  );
}
