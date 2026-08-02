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
