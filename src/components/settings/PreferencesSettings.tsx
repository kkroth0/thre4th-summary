import { useTheme } from "@/components/theme-provider";
import { useLanguage } from "@/contexts/LanguageContext";

const controlClass = "h-9 w-full rounded-sm border border-input bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring sm:w-56";

export function PreferencesSettings() {
  const { language, setLanguage, tr } = useLanguage();
  const { theme, setTheme } = useTheme();

  return (
    <section className="rounded-sm border border-border bg-card" aria-labelledby="interface-heading">
      <h2 id="interface-heading" className="border-b border-border px-4 py-3 text-sm font-semibold">{tr({ pt: "Interface", en: "Interface", es: "Interfaz", fr: "Interface" })}</h2>
      <div className="divide-y divide-border">
        <div className="flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
          <label htmlFor="settings-language" className="text-sm">{tr({ pt: "Idioma", en: "Language", es: "Idioma", fr: "Langue" })}</label>
          <select id="settings-language" value={language} onChange={(event) => setLanguage(event.target.value as typeof language)} className={controlClass}>
            <option value="pt">Português</option><option value="en">English</option><option value="es">Español</option><option value="fr">Français</option>
          </select>
        </div>
        <div className="flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
          <label htmlFor="settings-theme" className="text-sm">{tr({ pt: "Tema", en: "Theme", es: "Tema", fr: "Thème" })}</label>
          <select id="settings-theme" value={theme} onChange={(event) => { const value = event.target.value; if (value === "light" || value === "dark" || value === "system") setTheme(value); }} className={controlClass}>
            <option value="light">{tr({ pt: "Claro", en: "Light", es: "Claro", fr: "Clair" })}</option>
            <option value="dark">{tr({ pt: "Escuro", en: "Dark", es: "Oscuro", fr: "Sombre" })}</option>
            <option value="system">{tr({ pt: "Sistema", en: "System", es: "Sistema", fr: "Système" })}</option>
          </select>
        </div>
      </div>
      <p className="border-t border-border px-4 py-2 text-xs text-muted-foreground">{tr({ pt: "Salvo neste dispositivo.", en: "Saved on this device.", es: "Guardado en este dispositivo.", fr: "Enregistré sur cet appareil." })}</p>
    </section>
  );
}
