import { Languages, Moon, Palette, Sun } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { useTheme } from "@/components/theme-provider";
import { useLanguage } from "@/contexts/LanguageContext";

const languages = [
  { value: "pt", label: "Português", detail: "Brasil" },
  { value: "en", label: "English", detail: "United States" },
  { value: "es", label: "Español", detail: "España" },
  { value: "fr", label: "Français", detail: "France" },
] as const;

const themes = [
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
] as const;

export function PreferencesSettings() {
  const { language, setLanguage, tr } = useLanguage();
  const { theme, setTheme } = useTheme();
  const selectedTheme = theme === "dark" ? "dark" : "light";

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h2 className="text-xl font-semibold">{tr({ pt: "Geral", en: "General", es: "General", fr: "Général" })}</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          {tr({
            pt: "Escolha o idioma e a aparência da interface.",
            en: "Choose the interface language and appearance.",
            es: "Elige el idioma y la apariencia de la interfaz.",
            fr: "Choisissez la langue et l’apparence de l’interface.",
          })}
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><Languages /> {tr({ pt: "Idioma", en: "Language", es: "Idioma", fr: "Langue" })}</CardTitle>
          <CardDescription>{tr({ pt: "Define o idioma usado em toda a aplicação.", en: "Sets the language used throughout the application.", es: "Define el idioma utilizado en toda la aplicación.", fr: "Définit la langue utilisée dans toute l’application." })}</CardDescription>
        </CardHeader>
        <CardContent>
          <ToggleGroup
            type="single"
            value={language}
            onValueChange={(value) => { if (value) setLanguage(value as typeof language); }}
            variant="outline"
            className="grid grid-cols-1 items-stretch sm:grid-cols-2"
            aria-label={tr({ pt: "Selecionar idioma", en: "Select language", es: "Seleccionar idioma", fr: "Sélectionner la langue" })}
          >
            {languages.map((option) => (
              <ToggleGroupItem key={option.value} value={option.value} className="h-14 justify-start px-4 text-left" aria-label={`${option.label}, ${option.detail}`}>
                <span>
                  <span className="block font-medium">{option.label}</span>
                  <span className="block text-xs text-muted-foreground">{option.detail}</span>
                </span>
              </ToggleGroupItem>
            ))}
          </ToggleGroup>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><Palette /> {tr({ pt: "Aparência", en: "Appearance", es: "Apariencia", fr: "Apparence" })}</CardTitle>
          <CardDescription>{tr({ pt: "Alterne entre os modos claro e escuro.", en: "Switch between light and dark modes.", es: "Alterna entre los modos claro y oscuro.", fr: "Passez du mode clair au mode sombre." })}</CardDescription>
        </CardHeader>
        <CardContent>
          <ToggleGroup
            type="single"
            value={selectedTheme}
            onValueChange={(value) => { if (value === "light" || value === "dark") setTheme(value); }}
            variant="outline"
            className="grid grid-cols-2 items-stretch"
            aria-label={tr({ pt: "Selecionar aparência", en: "Select appearance", es: "Seleccionar apariencia", fr: "Sélectionner l’apparence" })}
          >
            {themes.map((option) => {
              const Icon = option.icon;
              return (
                <ToggleGroupItem key={option.value} value={option.value} className="h-12 gap-2" aria-label={option.label}>
                  <Icon /> {option.label}
                </ToggleGroupItem>
              );
            })}
          </ToggleGroup>
        </CardContent>
      </Card>
    </div>
  );
}
