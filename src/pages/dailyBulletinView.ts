export const canOpenReport = (job: { status: string; json?: unknown; hasReport?: boolean }) =>
  job.status === "done" && Boolean(job.json || job.hasReport);

export const MAX_REPORT_SOURCES = 5;

export function parseReportSources(input: string): { urls: string[]; error?: "empty" | "invalid" | "limit" } {
  const urls = [...new Set(input.trim().split(/\s+/).filter(Boolean))];
  if (!urls.length) return { urls, error: "empty" };
  if (urls.length > MAX_REPORT_SOURCES) return { urls, error: "limit" };
  if (urls.some((value) => {
    try { return !["http:", "https:"].includes(new URL(value).protocol); } catch { return true; }
  })) return { urls, error: "invalid" };
  return { urls };
}

// O item que falhou também abre. Antes, clicar num erro caía no estado vazio
// "Nenhum relatório aberto" — 5 dos 48 relatórios estão nesse caso, e a mensagem
// só existia truncada na lista.
export const canOpenJob = (job: { status: string; json?: unknown; hasReport?: boolean }) =>
  canOpenReport(job) || job.status === "error";

// ─── Título da lista ───────────────────────────────────────────────────────
// Metade da lista mostrava a URL crua porque o job só ganha `title` depois que
// o worker responde. O nome da própria página de origem já está no fim da URL,
// então dá para ler alguma coisa enquanto o título de verdade não chega.

const SLUG_NOISE = /\.(html?|php|aspx?)$/i;

export function titleFromUrl(url: string): string {
  let parsed: URL;
  try { parsed = new URL(url); } catch { return url; }
  const segmentos = parsed.pathname.split("/").filter(Boolean);
  const ultimo = segmentos[segmentos.length - 1] || "";
  // Segmento que é só id ou data não vira título: "2026", "12345", "p=7".
  const slug = ultimo.replace(SLUG_NOISE, "");
  if (!slug || /^[\d-]+$/.test(slug) || slug.length < 8) return parsed.hostname.replace(/^www\./, "");
  return slug.replace(/[-_]+/g, " ").replace(/\s+/g, " ").trim();
}

export function reportTitle(job: { title?: string | null; url: string }): string {
  const titulo = (job.title || "").trim();
  // A URL às vezes chega gravada no campo de título; aí ela não serve como nome.
  if (titulo && !/^https?:\/\//i.test(titulo)) return titulo;
  return titleFromUrl(job.url);
}

/** One search for the report library and the entire available suggestion list. */
export function filterReportLibrary<T extends { title?: string | null; url: string; cves?: string[] }>(items: T[], query: string): T[] {
  const normalize = (value: string) => value.normalize("NFD").replace(/\p{Mn}/gu, "").toLowerCase();
  const terms = normalize(query.trim()).split(/\s+/).filter(Boolean);
  if (!terms.length) return items;
  return items.filter((item) => {
    const text = normalize([reportTitle(item), item.url, ...(item.cves ?? [])].join(" "));
    return terms.every((term) => text.includes(term));
  });
}

// ─── Falha legível ─────────────────────────────────────────────────────────
// A mensagem do worker é escrita para quem lê log: "timeout após 240s (árvore
// de processos encerrada)". O analista precisa saber o que fazer com isso.

export type FailureHelp = { resumo: string; causa: string; acoes: string[] };

export function explainFailure(raw: string | null | undefined, pt: boolean): FailureHelp {
  const texto = String(raw || "").toLowerCase();

  if (/timeout|tempo esgotado|240s/.test(texto)) {
    return pt ? {
      resumo: "A extração passou do tempo limite e foi encerrada",
      causa: "Páginas com paywall ou muito JavaScript costumam estourar os 4 minutos.",
      acoes: ["Tentar de novo", "Colar o texto do artigo", "Usar um link alternativo"],
    } : {
      resumo: "Extraction exceeded the time limit and was stopped",
      causa: "Paywalled or JavaScript-heavy pages usually blow past the 4-minute cap.",
      acoes: ["Try again", "Paste the article text", "Use an alternative link"],
    };
  }
  if (/perdido|reiniciou|restart/.test(texto)) {
    return pt ? {
      resumo: "O servidor reiniciou no meio da geração",
      causa: "O job se perdeu no restart; nada foi salvo.",
      acoes: ["Tentar de novo"],
    } : {
      resumo: "The server restarted mid-generation",
      causa: "The job was lost on restart; nothing was saved.",
      acoes: ["Try again"],
    };
  }
  if (/40[34]|forbidden|denied|blocked/.test(texto)) {
    return pt ? {
      resumo: "A fonte recusou o acesso",
      causa: "O site bloqueia leitor automático, ou o conteúdo exige login.",
      acoes: ["Colar o texto do artigo", "Usar um link alternativo"],
    } : {
      resumo: "The source refused access",
      causa: "The site blocks automated readers, or the content needs a login.",
      acoes: ["Paste the article text", "Use an alternative link"],
    };
  }
  return pt ? {
    resumo: "A geração falhou",
    causa: "A mensagem completa do worker está abaixo.",
    acoes: ["Tentar de novo"],
  } : {
    resumo: "Generation failed",
    causa: "The worker's full message is below.",
    acoes: ["Try again"],
  };
}

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
