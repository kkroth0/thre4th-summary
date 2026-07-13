import type { Language } from "../utils/translations";

export interface NewsletterFilterItem {
  title: string;
  description: string;
  source: string;
  pubDate: string;
  layer?: number;
  severity?: string;
  kev?: boolean;
  score?: number;
}

export interface NewsletterFilterOptions {
  search: string;
  layer: string;
  severity: string;
  kevOnly: boolean;
  sortByRelevance: boolean;
}

const LOCALES: Record<Language, string> = {
  pt: "pt-BR",
  en: "en-US",
  es: "es-ES",
  fr: "fr-FR",
};

const TODAY: Record<Language, string> = {
  pt: "Hoje",
  en: "Today",
  es: "Hoy",
  fr: "Aujourd’hui",
};

export const formatNewsletterDate = (date: Date, language: Language): string => {
  const formatted = new Intl.DateTimeFormat(LOCALES[language], {
    day: "numeric",
    month: "long",
    year: "numeric",
  }).format(date);

  return `${TODAY[language]}, ${formatted}`;
};

export const filterNewsletterAdvisories = <T extends NewsletterFilterItem>(
  advisories: T[],
  options: NewsletterFilterOptions,
): T[] => {
  const query = options.search.toLowerCase();
  const filtered = advisories.filter((item) => {
    const matchesSearch = item.title.toLowerCase().includes(query)
      || item.description.toLowerCase().includes(query)
      || item.source.toLowerCase().includes(query);

    if (!matchesSearch) return false;
    if (options.severity !== "all" && item.severity !== options.severity) return false;
    if (options.kevOnly && !item.kev) return false;
    if (options.layer === "l1" && item.layer !== 1) return false;
    if (options.layer === "l2" && item.layer !== 2) return false;
    if (options.layer === "l3" && (item.layer ?? 0) < 3) return false;

    return true;
  });

  return options.sortByRelevance
    ? [...filtered].sort((a, b) => (b.score ?? 0) - (a.score ?? 0)
      || new Date(b.pubDate).getTime() - new Date(a.pubDate).getTime())
    : filtered;
};
