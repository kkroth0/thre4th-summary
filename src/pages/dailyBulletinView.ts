export const canOpenReport = (job: { status: string; json?: unknown; hasReport?: boolean }) =>
  job.status === "done" && Boolean(job.json || job.hasReport);

// ─── Sugestões do dia ──────────────────────────────────────────────────────
// A janela (hours) é do servidor; o resto filtra aqui, porque o analista muda
// de ideia mais rápido do que vale uma ida à rede.
export type SuggestionPrefs = {
  hours: number;
  minSeverity: "all" | "Medium" | "High" | "Critical";
  kevOnly: boolean;
  /** Palavras-chave separadas por vírgula. Vazio = tudo passa. */
  keywords: string;
};

export const DEFAULT_SUGGESTION_PREFS: SuggestionPrefs = {
  hours: 36, minSeverity: "all", kevOnly: false, keywords: "",
};

const SEVERITY_RANK: Record<string, number> = { Low: 1, Medium: 2, High: 3, Critical: 4 };

type SuggestionLike = { title: string; severity?: string; kev?: boolean; cves?: string[]; source?: string };

export function filterSuggestions<T extends SuggestionLike>(items: T[], prefs: SuggestionPrefs): T[] {
  const floor = prefs.minSeverity === "all" ? 0 : SEVERITY_RANK[prefs.minSeverity];
  const terms = prefs.keywords.split(",").map((term) => term.trim().toLowerCase()).filter(Boolean);
  return items.filter((item) => {
    if (prefs.kevOnly && !item.kev) return false;
    if ((SEVERITY_RANK[item.severity || "Low"] || 1) < floor) return false;
    if (!terms.length) return true;
    const haystack = [item.title, item.source, ...(item.cves || [])].filter(Boolean).join(" ").toLowerCase();
    return terms.some((term) => haystack.includes(term));
  });
}

export function buildHuntLink(report: { id: string; title?: string; techniques?: string[]; cves?: string[] }) {
  const params = new URLSearchParams({ new: "1", sourceReportId: report.id });
  if (report.title) params.set("title", report.title);
  if (report.techniques?.length) params.set("techniques", report.techniques.join(","));
  if (report.cves?.length) params.set("cves", report.cves.join(","));
  return `/hunting?${params}`;
}
