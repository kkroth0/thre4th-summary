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

// "all" nunca filtra — as demais são uma janela em horas a partir de `now`.
export const TIME_RANGES = ["all", "24h", "7d", "30d"] as const;
export type TimeRange = (typeof TIME_RANGES)[number];
const TIME_RANGE_HOURS: Record<Exclude<TimeRange, "all">, number> = { "24h": 24, "7d": 24 * 7, "30d": 24 * 30 };

export interface NewsletterFilterOptions {
  search: string;
  severity: string;
  kevOnly: boolean;
  sortByRelevance: boolean;
  // "all" nunca filtra, igual a severity — mesma convenção, mesmo motivo.
  source?: string;
  // Opcional: telas antigas que ainda não passam período continuam sem filtrar
  // por data, exatamente como hoje.
  timeRange?: TimeRange;
  now?: Date;
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
  const range = options.timeRange ?? "all";
  const cutoff = range === "all" ? null : (options.now ?? new Date()).getTime() - TIME_RANGE_HOURS[range] * 3600_000;
  const filtered = advisories.filter((item) => {
    const matchesSearch = item.title.toLowerCase().includes(query)
      || item.description.toLowerCase().includes(query)
      || item.source.toLowerCase().includes(query);

    if (!matchesSearch) return false;
    if (options.severity !== "all" && item.severity !== options.severity) return false;
    if (options.source && options.source !== "all" && item.source !== options.source) return false;
    if (options.kevOnly && !item.kev) return false;
    // Item sem data parseável não é descartado pelo período — silenciar uma
    // notícia por falta de metadado é pior do que mostrá-la fora de hora.
    if (cutoff !== null) {
      const published = new Date(item.pubDate).getTime();
      if (!Number.isNaN(published) && published < cutoff) return false;
    }

    return true;
  });

  return options.sortByRelevance
    ? [...filtered].sort((a, b) => (b.score ?? 0) - (a.score ?? 0)
      || new Date(b.pubDate).getTime() - new Date(a.pubDate).getTime())
    : filtered;
};

// Same order as NEWS_CATEGORIES on the server: precedence, not importance.
export const NEWS_CATEGORY_ORDER = [
  "Ransomware", "APTs", "Data Leaks", "OT/ICS", "Vulnerabilities", "Malware", "Phishing", "Microsoft",
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
  malware?: StoryActor[];
  campaigns?: StoryActor[];
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
  malware: StoryActor[];
  campaigns: StoryActor[];
  cves: string[];
  lastSeen: string;
  score: number;
  orgScore: number;
  orgMatches: OrgMatch[];
  sources: T[];
}

// EST-05: a lista abria com USN-8666-3, USN-8644-3, USN-8661-3 e USN-8688-1 em
// sequência — dois deles com exatamente as mesmas CVEs. Um aviso de distribuição
// por dia é notícia; oito são ruído com o mesmo texto. O identificador do aviso
// diz de quem ele é, e é isso que agrupa: mesmo fornecedor, mesmo dia, um card.
const ADVISORY_VENDORS: [RegExp, string][] = [
  [/^USN-/i, "Ubuntu"],
  [/^(DSA|DLA)-/i, "Debian"],
  [/^RH(SA|BA|EA)-/i, "Red Hat"],
  [/^ELSA-/i, "Oracle Linux"],
  [/^(openSUSE-SU|SUSE-SU)-/i, "SUSE"],
  [/^FEDORA-/i, "Fedora"],
  [/^GLSA-/i, "Gentoo"],
  [/^MFSA-/i, "Mozilla"],
];

/** O fornecedor por trás do identificador do aviso, ou null se não for um. */
export const advisoryVendor = (title: string): string | null => {
  const clean = (title || "").trim();
  for (const [pattern, vendor] of ADVISORY_VENDORS) if (pattern.test(clean)) return vendor;
  return null;
};

const ROLLUP = "vendor-advisory:";

// An item with no storyId is its own story. The grouping is enrichment: if the
// server could not group, the reader still sees every headline.
export const groupAdvisoriesIntoStories = <T extends StorySource>(
  advisories: T[],
  options: { sortByRelevance?: boolean; pt?: boolean } = {},
): StoryCard<T>[] => {
  const byStory = new Map<string, StoryCard<T>>();
  const vendorOfKey = new Map<string, string>();

  for (const item of advisories) {
    const vendor = advisoryVendor(item.title);
    const day = (item.pubDate || "").slice(0, 10);
    const rollup = vendor && day ? `${ROLLUP}${vendor}:${day}` : null;
    if (rollup) vendorOfKey.set(rollup, vendor as string);
    const key = rollup || item.storyId || `link:${item.link}`;
    const card = byStory.get(key);
    if (!card) {
      byStory.set(key, {
        storyId: key,
        title: item.title,
        primaryCategory: item.primaryCategory ?? null,
        categories: [...(item.newsCategories ?? [])],
        actors: [...(item.actors ?? [])],
        malware: [...(item.malware ?? [])],
        campaigns: [...(item.campaigns ?? [])],
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
    for (const m of item.malware ?? []) if (!card.malware.some((seen) => seen.id === m.id)) card.malware.push(m);
    for (const c of item.campaigns ?? []) if (!card.campaigns.some((seen) => seen.id === c.id)) card.campaigns.push(c);
  }

  const cards = [...byStory.values()];
  for (const card of cards) {
    card.categories.sort((a, b) => (NEWS_CATEGORY_ORDER as readonly string[]).indexOf(a) - (NEWS_CATEGORY_ORDER as readonly string[]).indexOf(b));
    card.primaryCategory = card.categories[0] ?? null;
    // Aviso sozinho continua com o título dele: um card de resumo com um item
    // dentro esconderia a manchete e não pouparia linha nenhuma.
    const vendor = vendorOfKey.get(card.storyId);
    if (vendor && card.sources.length > 1) {
      card.title = options.pt
        ? `${vendor} · ${card.sources.length} avisos de segurança`
        : `${vendor} · ${card.sources.length} security advisories`;
    }
  }
  // O contexto filtra (orgOnly), nunca reordena: ou é tudo, ou é só o contexto.
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

// ─── EST-05: a severidade não dizia por quê ────────────────────────────────
// "Long Term Support Channel Update for ChromeOS" saía como CRÍTICO e um
// kernel com EPSS de 4% saía como BAIXO, sem nada explicando. Os sinais que
// decidem já viajam no item — KEV, EPSS, CVSS — mas só existiam num tooltip,
// que ninguém abre enquanto passa os olhos na lista.
//
// Aqui eles viram rótulos curtos. Só entra o que é medido: nada de inferir
// severidade a partir do título.

export type SeverityEvidenceItem = {
  kev?: boolean;
  epss?: number;
  cvss?: number | null;
  orgScore?: number;
};

export type SeverityChip = { label: string; tone: "kev" | "epss" | "cvss" | "org" };

export function severityEvidence(item: SeverityEvidenceItem, pt: boolean): SeverityChip[] {
  const chips: SeverityChip[] = [];

  // KEV é o sinal mais forte: a CISA registrou exploração no mundo real.
  if (item.kev) chips.push({ label: pt ? "Explorada (KEV)" : "Exploited (KEV)", tone: "kev" });

  // EPSS só informa quando é alto o bastante para mudar a decisão. Abaixo de 5%
  // o número vira ruído numa lista que já tem sete etiquetas.
  if (typeof item.epss === "number" && item.epss >= 0.05) {
    chips.push({ label: `EPSS ${Math.round(item.epss * 100)}%`, tone: "epss" });
  }
  if (typeof item.cvss === "number" && item.cvss > 0) {
    chips.push({ label: `CVSS ${item.cvss.toFixed(1)}`, tone: "cvss" });
  }
  return chips;
}

/** O card não tem nenhum sinal medido — a severidade veio só do texto. */
export const severityIsUnexplained = (item: SeverityEvidenceItem): boolean =>
  !item.kev && !(typeof item.cvss === "number" && item.cvss > 0)
  && !(typeof item.epss === "number" && item.epss >= 0.05);

// ─── DEN-02: filtro ativo invisível ────────────────────────────────────────
// A barra tinha busca, botão de Filtros e chips de categoria disputando o mesmo
// espaço, e o que estava filtrando só aparecia como um número no botão — para
// saber quais, ou remover um, era preciso reabrir o popover.

export type NewsFilterState = {
  severity: string;
  source?: string;
  kevOnly: boolean;
  orgOnly: boolean;
  sortByRelevance: boolean;
  search: string;
  timeRange?: TimeRange;
};

export type ActiveFilterChip = { key: keyof NewsFilterState; label: string };

const TIME_RANGE_LABEL: Record<Exclude<TimeRange, "all">, { pt: string; en: string }> = {
  "24h": { pt: "Últimas 24h", en: "Last 24h" },
  "7d": { pt: "Últimos 7 dias", en: "Last 7 days" },
  "30d": { pt: "Últimos 30 dias", en: "Last 30 days" },
};

export function activeFilterChips(state: NewsFilterState, pt: boolean): ActiveFilterChip[] {
  const chips: ActiveFilterChip[] = [];
  if (state.severity && state.severity !== "all") {
    chips.push({ key: "severity", label: `${pt ? "Severidade" : "Severity"}: ${state.severity}` });
  }
  if (state.source && state.source !== "all") {
    chips.push({ key: "source", label: `${pt ? "Fonte" : "Source"}: ${state.source}` });
  }
  if (state.kevOnly) chips.push({ key: "kevOnly", label: pt ? "Só KEV" : "KEV only" });
  if (state.orgOnly) chips.push({ key: "orgOnly", label: pt ? "Só da organização" : "Org only" });
  // Ordenar não filtra, mas muda o que aparece primeiro — o leitor precisa saber
  // que a ordem não é a cronológica.
  if (state.sortByRelevance) chips.push({ key: "sortByRelevance", label: pt ? "Por relevância" : "By relevance" });
  if (state.search.trim()) chips.push({ key: "search", label: `"${state.search.trim()}"` });
  if (state.timeRange && state.timeRange !== "all") {
    chips.push({ key: "timeRange", label: TIME_RANGE_LABEL[state.timeRange][pt ? "pt" : "en"] });
  }
  return chips;
}
