import type { Language } from "../utils/translations";
import type { OrgMatch } from "@/utils/orgRelevance";

export interface NewsletterFilterItem {
  title: string;
  description: string;
  source: string;
  pubDate: string;
  severity?: string;
  kev?: boolean;
  score?: number;
}

export interface NewsletterFilterOptions {
  search: string;
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

    return true;
  });

  return options.sortByRelevance
    ? [...filtered].sort((a, b) => (b.score ?? 0) - (a.score ?? 0)
      || new Date(b.pubDate).getTime() - new Date(a.pubDate).getTime())
    : filtered;
};

// Same order as NEWS_CATEGORIES on the server: precedence, not importance.
export const NEWS_CATEGORY_ORDER = [
  "Ransomware", "APTs", "Data Leaks", "OT/ICS", "Vulnerabilities", "Malware", "Microsoft",
  "Finance/Banking", "Health/Pharma",
] as const;

export interface StoryActor {
  id: string;
  name: string;
  matched?: string;
  via?: string;
}

export interface StorySource {
  link: string;
  source: string;
  title: string;
  pubDate: string;
  storyId?: string | null;
  actors?: StoryActor[];
  // Navigation buckets from the server's categorize() — not scoreArticle's CTI
  // scoring labels, which the API keeps on the unrelated `categories` field.
  newsCategories?: string[];
  primaryCategory?: string | null;
  cves?: string[];
  score?: number;
  // Relevância para o perfil ativo. Calculada na tela a cada render e nunca
  // persistida: é o que faz trocar de perfil reanotar o cache inteiro.
  orgScore?: number;
  orgMatches?: OrgMatch[];
}

export interface StoryCard<T extends StorySource = StorySource> {
  storyId: string;
  title: string;
  primaryCategory: string | null;
  categories: string[];
  actors: StoryActor[];
  cves: string[];
  lastSeen: string;
  score: number;
  orgScore: number;
  orgMatches: OrgMatch[];
  sources: T[];
}

// An item with no storyId is its own story. The grouping is enrichment: if the
// server could not group, the reader still sees every headline.
export const groupAdvisoriesIntoStories = <T extends StorySource>(
  advisories: T[],
  options: { sortByRelevance?: boolean; sortByOrg?: boolean } = {},
): StoryCard<T>[] => {
  const byStory = new Map<string, StoryCard<T>>();

  for (const item of advisories) {
    const key = item.storyId || `link:${item.link}`;
    const card = byStory.get(key);
    if (!card) {
      byStory.set(key, {
        storyId: key,
        title: item.title,
        primaryCategory: item.primaryCategory ?? null,
        categories: [...(item.newsCategories ?? [])],
        actors: [...(item.actors ?? [])],
        cves: [...(item.cves ?? [])],
        lastSeen: item.pubDate,
        score: item.score ?? 0,
        orgScore: item.orgScore ?? 0,
        orgMatches: [...(item.orgMatches ?? [])],
        sources: [item],
      });
      continue;
    }
    card.sources.push(item);
    if (item.pubDate > card.lastSeen) card.lastSeen = item.pubDate;
    if ((item.score ?? 0) > card.score) card.score = item.score ?? 0;
    if ((item.orgScore ?? 0) > card.orgScore) card.orgScore = item.orgScore ?? 0;
    for (const match of item.orgMatches ?? []) {
      if (!card.orgMatches.some((seen) => seen.kind === match.kind && seen.label === match.label)) card.orgMatches.push(match);
    }
    for (const category of item.newsCategories ?? []) if (!card.categories.includes(category)) card.categories.push(category);
    for (const cve of item.cves ?? []) if (!card.cves.includes(cve)) card.cves.push(cve);
    for (const actor of item.actors ?? []) if (!card.actors.some((a) => a.id === actor.id)) card.actors.push(actor);
  }

  const cards = [...byStory.values()];
  for (const card of cards) {
    card.categories.sort((a, b) => (NEWS_CATEGORY_ORDER as readonly string[]).indexOf(a) - (NEWS_CATEGORY_ORDER as readonly string[]).indexOf(b));
    card.primaryCategory = card.categories[0] ?? null;
  }
  // O contexto manda quando pedido; o score do feed é o desempate, e lastSeen
  // fecha a ordem para ela nunca depender da ordem de chegada.
  if (options.sortByOrg) {
    return cards.sort((a, b) => b.orgScore - a.orgScore || b.score - a.score || b.lastSeen.localeCompare(a.lastSeen));
  }
  return options.sortByRelevance
    ? cards.sort((a, b) => b.score - a.score || b.lastSeen.localeCompare(a.lastSeen))
    : cards.sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));
};

export const countByCategory = (cards: StoryCard[]): Record<string, number> => {
  const counts: Record<string, number> = {};
  for (const card of cards) for (const category of card.categories) counts[category] = (counts[category] ?? 0) + 1;
  return counts;
};

export const filterStoryCards = <T extends StorySource>(
  cards: StoryCard<T>[],
  options: { category: string; orgOnly?: boolean },
): StoryCard<T>[] =>
  cards.filter((card) => {
    if (options.category && !card.categories.includes(options.category)) return false;
    if (options.orgOnly && card.orgScore <= 0) return false;
    return true;
  });
