export interface HuntLike {
  id: string;
  origin?: string;
  category?: string;
  title: string;
  hypothesis?: string;
  why?: string;
  query?: string;
  status?: string;
  tactics?: string[];
  techniques?: string[];
  cves?: string[];
  tags?: string[];
  technologies?: string[];
  dataSources?: string[];
}

export interface HuntFilters {
  query?: string;
  origin?: string;
  category?: string;
  tactic?: string;
  technique?: string;
  technology?: string;
  dataSource?: string;
  status?: string;
}

export const huntOrigin = (hunt: HuntLike) => hunt.origin === "hearth" ? "hearth" : "private";

export function filterHunts<T extends HuntLike>(hunts: T[], filters: HuntFilters): T[] {
  const chosen = (value: string | undefined, actual: string | undefined) => !value || value === "all" || value === actual;
  const contains = (value: string | undefined, list: string[] | undefined) => !value || value === "all" || (list || []).includes(value);
  const query = (filters.query || "").trim().toLowerCase();

  return hunts.filter((hunt) =>
    chosen(filters.origin, huntOrigin(hunt))
    && chosen(filters.category, hunt.category)
    && chosen(filters.status, hunt.status)
    && contains(filters.tactic, hunt.tactics)
    && contains(filters.technique, hunt.techniques)
    && contains(filters.technology, hunt.technologies)
    && contains(filters.dataSource, hunt.dataSources)
    && (!query || [
      hunt.title, hunt.hypothesis, hunt.why, hunt.query,
      ...(hunt.tactics || []), ...(hunt.techniques || []), ...(hunt.cves || []),
      ...(hunt.tags || []), ...(hunt.technologies || []), ...(hunt.dataSources || []),
    ].filter(Boolean).join(" ").toLowerCase().includes(query))
  );
}

export const parseList = (value: string, uppercase = false): string[] => [...new Set(
  value.split(/[,\n]/).map((item) => item.trim()).filter(Boolean).map((item) => uppercase ? item.toUpperCase() : item),
)];

// ─── Calendário do mês ─────────────────────────────────────────────────────
// A grade sai do próprio mês, não de biblioteca de data: são seis linhas de
// sete dias, com os vazios do começo e do fim marcados. Tudo em UTC, porque a
// execução é carimbada em UTC — usar hora local jogaria a hunt da meia-noite
// pro dia errado.

export type CalendarCell = { date: string; day: number; inMonth: boolean };

/** Semanas do mês, começando no domingo, com o preenchimento das pontas. */
export function monthGrid(month: string): CalendarCell[][] {
  const [year, monthIndex] = month.split("-").map(Number);
  if (!year || !monthIndex) return [];

  const first = new Date(Date.UTC(year, monthIndex - 1, 1));
  // Volta até o domingo da semana em que o mês começa.
  const start = new Date(first);
  start.setUTCDate(1 - first.getUTCDay());

  const weeks: CalendarCell[][] = [];
  const cursor = new Date(start);

  // Seis semanas cobrem qualquer mês, inclusive fevereiro começando no sábado.
  for (let week = 0; week < 6; week += 1) {
    const days: CalendarCell[] = [];
    for (let day = 0; day < 7; day += 1) {
      days.push({
        date: cursor.toISOString().slice(0, 10),
        day: cursor.getUTCDate(),
        inMonth: cursor.getUTCMonth() === monthIndex - 1,
      });
      cursor.setUTCDate(cursor.getUTCDate() + 1);
    }
    weeks.push(days);
    // Semana inteira fora do mês só existe no fim: corta em vez de mostrar vazia.
    if (days.every((cell) => !cell.inMonth) && week > 3) {
      weeks.pop();
      break;
    }
  }

  return weeks;
}

/** Agrupa qualquer coisa datada por dia (YYYY-MM-DD), na ordem que chegou. */
export function groupByDay<T>(items: T[], dateOf: (item: T) => string | null | undefined): Record<string, T[]> {
  const byDay: Record<string, T[]> = {};
  for (const item of items) {
    const day = String(dateOf(item) ?? "").slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) continue;
    (byDay[day] ||= []).push(item);
  }
  return byDay;
}

// ─── FLX-04: os 237 cartões chamados h001…h237 ─────────────────────────────
// A aba Queries listava `name` (o identificador do arquivo) e `folder` ("hearth"),
// e nada ali ajuda a escolher uma consulta. O nome bom já existe: o catálogo
// pt-BR descreve as mesmas hunts, e o `queryPath` dele é o `path` do KQL.
// Aqui é só a junção — dado novo, nenhum.

export type QueryCardSource = { path: string; folder: string; name: string };
export type QueryCatalogEntry = {
  queryPath: string;
  title?: string;
  hypothesis?: string;
  cadence?: string;
  technologies?: string[];
  dataSources?: string[];
};

export type QueryCard = {
  path: string;
  /** o que o analista lê primeiro: a hipótese, quando ela existe */
  title: string;
  /** identificador e pasta, agora como apoio */
  subtitle: string;
  cadence: string;
  /** só quando o catálogo descreve; vazio não vira chip */
  tags: string[];
  described: boolean;
};

const CADENCE_ORDER = ["diária", "diaria", "semanal", "mensal", "intel"];

export const cadenceRank = (cadence: string): number => {
  const i = CADENCE_ORDER.indexOf((cadence || "").toLowerCase().trim());
  return i === -1 ? CADENCE_ORDER.length : i;
};

export function buildQueryCards(queries: QueryCardSource[], catalog: QueryCatalogEntry[]): QueryCard[] {
  const porCaminho = new Map(catalog.filter((c) => c.queryPath).map((c) => [c.queryPath, c]));

  return (queries || []).map((q) => {
    const descrito = porCaminho.get(q.path);
    const titulo = (descrito?.hypothesis || descrito?.title || "").trim();
    return {
      path: q.path,
      title: titulo || q.name,
      // Quando há hipótese, o identificador desce para a linha de apoio; quando
      // não há, ele já é o título e repeti-lo abaixo seria ruído.
      subtitle: titulo ? [q.name, q.folder].filter(Boolean).join(" · ") : (q.folder || "raiz"),
      cadence: (descrito?.cadence || "").trim(),
      tags: [...(descrito?.technologies || []), ...(descrito?.dataSources || [])].filter(Boolean).slice(0, 3),
      described: Boolean(titulo),
    };
  });
}

/** Agrupa por cadência, porque 237 cartões iguais em lista única não se escolhem. */
export function groupQueryCards(cards: QueryCard[]): { cadence: string; cards: QueryCard[] }[] {
  const grupos = new Map<string, QueryCard[]>();
  for (const card of cards) {
    const chave = card.cadence || "";
    (grupos.get(chave) || grupos.set(chave, []).get(chave)!).push(card);
  }
  return [...grupos.entries()]
    .map(([cadence, cards]) => ({ cadence, cards }))
    .sort((a, b) => cadenceRank(a.cadence) - cadenceRank(b.cadence) || a.cadence.localeCompare(b.cadence));
}
