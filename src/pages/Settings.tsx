import { ArrowLeft, ChevronRight, KeyRound, Loader2, Radar, ShieldCheck, SlidersHorizontal } from "lucide-react";
import { Link, Navigate, useSearchParams } from "react-router-dom";
import { AdminSettings } from "@/components/settings/AdminSettings";
import { ApiKeysSettings } from "@/components/settings/ApiKeysSettings";
import { MonitoringSettings } from "@/components/settings/MonitoringSettings";
import { PreferencesSettings } from "@/components/settings/PreferencesSettings";
import { PageLayout } from "@/components/PageLayout";
import { useNavCatalog } from "@/components/Header";
import { useAuth } from "@/contexts/AuthContext";
import { useLanguage } from "@/contexts/LanguageContext";
import { cn } from "@/lib/utils";

type SettingsSection = "general" | "monitoring" | "api-keys" | "admin";

export default function Settings() {
  const { language, tr } = useLanguage();
  const { auth, loading } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const { homeItem, navGroups } = useNavCatalog();
  const pt = language === "pt";

  if (loading) return <PageLayout width="max-w-6xl"><div className="flex items-center gap-2 py-12 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />{pt ? "Verificando sessão…" : "Checking session…"}</div></PageLayout>;
  if (!auth.authenticated) return <Navigate to="/login" replace />;

  const requested = searchParams.get("section");
  const section: SettingsSection = requested === "api-keys" ? "api-keys" : requested === "monitoring" ? "monitoring" : requested === "admin" && auth.isAdmin ? "admin" : "general";
  // Only accept local paths for the return link.
  const rawFrom = searchParams.get("from") || "";
  const from = /^\/[^/]/.test(rawFrom) ? rawFrom : "";
  const fromLabel = [homeItem, ...navGroups.flatMap(g => g.items)].find(nav => nav.path === from)?.label || "";
  const selectSection = (value: string) => {
    const next = new URLSearchParams(searchParams);
    if (value === "general") next.delete("section");
    else next.set("section", value);
    setSearchParams(next, { replace: true });
  };
  const sections = [
    { id: "general", icon: SlidersHorizontal, label: tr({ pt: "Preferências", en: "Preferences", es: "Preferencias", fr: "Préférences" }), detail: pt ? "Idioma e aparência" : "Language and appearance" },
    { id: "monitoring", icon: Radar, label: tr({ pt: "Monitoramento", en: "Monitoring", es: "Monitoreo", fr: "Surveillance" }), detail: pt ? "Organização, fontes e ativos" : "Organization, sources and assets" },
    { id: "api-keys", icon: KeyRound, label: tr({ pt: "Chaves de API", en: "API keys", es: "Claves de API", fr: "Clés API" }), detail: pt ? "Suas integrações pessoais" : "Your personal integrations" },
    ...(auth.isAdmin ? [{ id: "admin", icon: ShieldCheck, label: pt ? "Administração" : "Administration", detail: pt ? "Acesso e serviços da plataforma" : "Platform access and services" }] : []),
  ];

  return (
    <PageLayout width="max-w-6xl" className="lg:pt-10">
      <div className="mb-8 border-b border-border pb-6">
        {from && fromLabel && <Link to={from} className="mb-3 inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" />{fromLabel}</Link>}
        <h1 className="page-title">{tr({ pt: "Configurações", en: "Settings", es: "Configuración", fr: "Paramètres" })}</h1>
        <p className="mt-2 text-sm text-muted-foreground">{tr({ pt: "Seu espaço de trabalho, do seu jeito.", en: "Make this workspace your own.", es: "Tu espacio de trabajo, a tu manera.", fr: "Votre espace de travail, à votre façon." })}</p>
      </div>
      <div className="grid items-start gap-8 lg:grid-cols-[224px_minmax(0,1fr)] lg:gap-12">
        <aside className="lg:sticky lg:top-24">
          <nav aria-label={pt ? "Seções de configurações" : "Settings sections"} className="grid grid-cols-2 gap-1.5 lg:grid-cols-1">
            {sections.map(({ id, icon: Icon, label, detail }) => (
              <button key={id} type="button" onClick={() => selectSection(id)} aria-current={section === id ? "page" : undefined}
                className={cn("flex min-w-0 items-center gap-3 rounded-lg border border-transparent px-3 py-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring", section === id ? "border-primary/15 bg-primary/10 text-foreground" : "text-muted-foreground hover:bg-secondary hover:text-foreground")}>
                <Icon className={cn("h-4 w-4 shrink-0", section === id && "text-primary")} />
                <span className="min-w-0 flex-1"><span className="block text-sm font-semibold">{label}</span><span className="mt-0.5 hidden text-xs text-muted-foreground lg:block">{detail}</span></span>
                {section === id && <ChevronRight className="hidden h-3.5 w-3.5 shrink-0 text-primary lg:block" />}
              </button>
            ))}
          </nav>
          <div className="mt-8 hidden items-center gap-2.5 border-t border-border px-3 pt-5 lg:flex">
            <span className="flex h-8 w-8 items-center justify-center rounded-full bg-secondary text-xs font-semibold">{auth.login?.[0]?.toUpperCase()}</span>
            <div className="min-w-0"><p className="truncate text-sm font-medium">{auth.login}</p><p className="text-xs text-muted-foreground">{pt ? "Sua conta" : "Your account"}</p></div>
          </div>
        </aside>
        <div className="min-w-0" key={section}>
          {section === "general" && <PreferencesSettings />}
          {section === "monitoring" && <MonitoringSettings />}
          {section === "api-keys" && <ApiKeysSettings />}
          {section === "admin" && auth.isAdmin && <AdminSettings />}
        </div>
      </div>
    </PageLayout>
  );
}
