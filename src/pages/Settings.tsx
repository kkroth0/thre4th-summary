import { ArrowLeft, Loader2 } from "lucide-react";
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
  const section: SettingsSection = requested === "api-keys" ? "api-keys" : requested === "general" ? "general" : requested === "admin" && auth.isAdmin ? "admin" : "monitoring";
  // Only accept local paths for the return link.
  const rawFrom = searchParams.get("from") || "";
  const from = /^\/[^/]/.test(rawFrom) ? rawFrom : "";
  const fromLabel = [homeItem, ...navGroups.flatMap(g => g.items)].find(nav => nav.path === from)?.label || "";
  const selectSection = (value: string) => {
    const next = new URLSearchParams(searchParams);
    next.set("section", value);
    setSearchParams(next, { replace: true });
  };
  const sections = [
    { id: "monitoring", label: tr({ pt: "Monitoramento", en: "Monitoring", es: "Monitoreo", fr: "Surveillance" }) },
    { id: "api-keys", label: tr({ pt: "Chaves de API", en: "API keys", es: "Claves de API", fr: "Clés API" }) },
    { id: "general", label: tr({ pt: "Interface", en: "Interface", es: "Interfaz", fr: "Interface" }) },
    ...(auth.isAdmin ? [{ id: "admin", label: pt ? "Administração" : "Administration" }] : []),
  ];

  return (
    <PageLayout width="max-w-6xl" className="lg:pt-6">
      <div className="mb-4 flex flex-wrap items-end justify-between gap-3 border-b border-border pb-4">
        <div>
          {from && fromLabel && <Link to={from} className="mb-3 inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" />{fromLabel}</Link>}
          <h1 className="text-xl font-semibold tracking-tight">{tr({ pt: "Configurações", en: "Settings", es: "Configuración", fr: "Paramètres" })}</h1>
          <p className="mt-1 text-xs text-muted-foreground">{pt ? "Escopo de monitoramento e integrações de inteligência." : "Intelligence monitoring scope and integrations."}</p>
        </div>
        <span className="font-mono text-xs text-muted-foreground">{auth.login}</span>
      </div>
      <nav aria-label={pt ? "Seções de configurações" : "Settings sections"} className="mb-5 flex overflow-x-auto border-b border-border">
        {sections.map(({ id, label }) => (
          <button key={id} type="button" onClick={() => selectSection(id)} aria-current={section === id ? "page" : undefined}
            className={cn("shrink-0 border-b-2 px-4 py-2 text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring", section === id ? "border-primary font-semibold text-foreground" : "border-transparent text-muted-foreground hover:text-foreground")}>
            {label}
          </button>
        ))}
      </nav>
      <div className="min-w-0 [&_button]:rounded-sm [&_input]:rounded-sm" key={section}>
        {section === "general" && <PreferencesSettings />}
        {section === "monitoring" && <MonitoringSettings />}
        {section === "api-keys" && <ApiKeysSettings />}
        {section === "admin" && auth.isAdmin && <AdminSettings />}
      </div>
    </PageLayout>
  );
}
