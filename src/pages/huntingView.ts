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
