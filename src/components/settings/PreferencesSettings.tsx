import { Check, Languages, Monitor, Moon, Sun } from "lucide-react";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { useTheme } from "@/components/theme-provider";
import { useLanguage } from "@/contexts/LanguageContext";
import { cn } from "@/lib/utils";

const languages = [
  { value: "pt", label: "Português", detail: "Brasil", code: "PT" },
  { value: "en", label: "English", detail: "United States", code: "EN" },
  { value: "es", label: "Español", detail: "España", code: "ES" },
  { value: "fr", label: "Français", detail: "France", code: "FR" },
] as const;

export function PreferencesSettings() {
  const { language, setLanguage, tr } = useLanguage();
  const { theme, setTheme } = useTheme();
  const themes = [
    { value: "light", label: tr({ pt: "Claro", en: "Light", es: "Claro", fr: "Clair" }), icon: Sun },
    { value: "dark", label: tr({ pt: "Escuro", en: "Dark", es: "Oscuro", fr: "Sombre" }), icon: Moon },
    { value: "system", label: tr({ pt: "Sistema", en: "System", es: "Sistema", fr: "Système" }), icon: Monitor },
  ] as const;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">{tr({ pt: "Preferências", en: "Preferences", es: "Preferencias", fr: "Préférences" })}</h2>
        <p className="mt-1.5 text-sm text-muted-foreground">{tr({ pt: "Ajuste como você usa e visualiza a plataforma.", en: "Adjust how you use and view the platform.", es: "Ajusta cómo usas y ves la plataforma.", fr: "Adaptez l’utilisation et l’affichage de la plateforme." })}</p>
      </div>
      <div className="overflow-hidden rounded-xl border border-border bg-card">
        <section className="p-5 sm:p-6" aria-labelledby="language-heading">
          <h3 id="language-heading" className="flex items-center gap-2 text-sm font-semibold"><Languages className="h-4 w-4 text-muted-foreground" />{tr({ pt: "Idioma da interface", en: "Interface language", es: "Idioma de la interfaz", fr: "Langue de l’interface" })}</h3>
          <p className="mt-1.5 text-sm text-muted-foreground">{tr({ pt: "Escolha o idioma dos menus e das ferramentas.", en: "Choose the language for menus and tools.", es: "Elige el idioma de los menús y herramientas.", fr: "Choisissez la langue des menus et des outils." })}</p>
          <ToggleGroup type="single" value={language} onValueChange={value => { if (value) setLanguage(value as typeof language); }} variant="outline" className="mt-5 grid grid-cols-1 gap-2 sm:grid-cols-2" aria-labelledby="language-heading">
            {languages.map(option => (
              <ToggleGroupItem key={option.value} value={option.value} className="h-auto min-h-16 justify-start gap-3 rounded-lg px-3 py-3 text-left data-[state=on]:border-primary/50 data-[state=on]:bg-primary/5" aria-label={`${option.label}, ${option.detail}`}>
                <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-secondary text-[10px] font-bold tracking-wide text-muted-foreground">{option.code}</span>
                <span className="flex-1"><span className="block text-sm font-medium">{option.label}</span><span className="block text-xs text-muted-foreground">{option.detail}</span></span>
                {language === option.value && <Check className="h-4 w-4 text-primary" />}
              </ToggleGroupItem>
            ))}
          </ToggleGroup>
        </section>
        <section className="border-t border-border p-5 sm:p-6" aria-labelledby="appearance-heading">
          <h3 id="appearance-heading" className="flex items-center gap-2 text-sm font-semibold"><Sun className="h-4 w-4 text-muted-foreground" />{tr({ pt: "Aparência", en: "Appearance", es: "Apariencia", fr: "Apparence" })}</h3>
          <p className="mt-1.5 text-sm text-muted-foreground">{tr({ pt: "Use um tema fixo ou acompanhe o tema do dispositivo.", en: "Use a fixed theme or follow your device’s theme.", es: "Usa un tema fijo o sigue el tema de tu dispositivo.", fr: "Choisissez un thème fixe ou celui de votre appareil." })}</p>
          <ToggleGroup type="single" value={theme} onValueChange={value => { if (value === "light" || value === "dark" || value === "system") setTheme(value); }} variant="outline" className="mt-5 grid grid-cols-3 gap-2" aria-labelledby="appearance-heading">
            {themes.map(({ value, label, icon: Icon }) => (
              <ToggleGroupItem key={value} value={value} aria-label={label} className="h-auto flex-col gap-2 rounded-lg p-2.5 data-[state=on]:border-primary/50 data-[state=on]:bg-primary/5">
                <span aria-hidden className={cn("flex h-16 w-full overflow-hidden rounded-md border p-2 sm:h-20", value === "dark" ? "border-slate-700 bg-slate-950" : "border-slate-200 bg-slate-50")}>
                  <span className={cn("w-1/4 rounded-sm", value === "dark" ? "bg-slate-800" : "bg-slate-200")} />
                  <span className="flex flex-1 flex-col gap-1.5 pl-2"><span className="h-1.5 w-2/3 rounded-full bg-orange-500/70" /><span className={cn("flex-1 rounded-sm", value === "dark" ? "bg-slate-800" : value === "system" ? "bg-gradient-to-r from-white from-50% to-slate-800 to-50%" : "bg-white")} /><span className={cn("h-1.5 w-3/4 rounded-full", value === "dark" ? "bg-slate-700" : "bg-slate-200")} /></span>
                </span>
                <span className="flex items-center gap-1.5 text-xs sm:text-sm"><Icon className="h-3.5 w-3.5" />{label}{theme === value && <Check className="h-3.5 w-3.5 text-primary" />}</span>
              </ToggleGroupItem>
            ))}
          </ToggleGroup>
        </section>
      </div>
      <p className="flex items-center gap-1.5 text-xs text-muted-foreground"><Check className="h-3.5 w-3.5" />{tr({ pt: "Preferências salvas automaticamente neste dispositivo.", en: "Preferences are saved automatically on this device.", es: "Las preferencias se guardan automáticamente en este dispositivo.", fr: "Les préférences sont enregistrées automatiquement sur cet appareil." })}</p>
    </div>
  );
}
