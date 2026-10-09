import type { NewsVendor, NewsMonitoringPreferences } from "@/services/threatApi";

export const NEWS_VENDOR_SECTORS: Record<string, { pt: string; en: string }> = {
  "cloud-platforms": { pt: "Nuvem e plataformas", en: "Cloud and platforms" },
  security: { pt: "Segurança", en: "Security" },
  networking: { pt: "Redes", en: "Networking" },
  "enterprise-software": { pt: "Software corporativo", en: "Enterprise software" },
  "backup-storage": { pt: "Backup e armazenamento", en: "Backup and storage" },
  "development-data": { pt: "Desenvolvimento, dados e IA", en: "Development, data and AI" },
  "web-platforms": { pt: "Plataformas web", en: "Web platforms" },
  "hardware-endpoints": { pt: "Hardware e endpoints", en: "Hardware and endpoints" },
  "ot-ics": { pt: "OT/ICS e automação", en: "OT/ICS and automation" },
};

const normalize = (value: string) => value.normalize("NFD").replace(/\p{Mn}/gu, "").toLowerCase();

export function filterNewsVendors(vendors: NewsVendor[], { search = "", sector = "all", selectedOnly = false, selectedIds = [] as string[] } = {}) {
  const query = normalize(search.trim());
  const selected = new Set(selectedIds);
  return vendors.filter((vendor) => (sector === "all" || vendor.sector === sector)
    && (!selectedOnly || selected.has(vendor.id))
    && (!query || [vendor.name, ...vendor.aliases].some((name) => normalize(name).includes(query))))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export function setNewsVendorSelection(selectedIds: string[], visibleIds: string[], checked: boolean): string[] {
  const next = new Set(selectedIds);
  for (const id of visibleIds) { if (checked) next.add(id); else next.delete(id); }
  return [...next].sort();
}

export function newsMonitoringCacheKey(owner: string, preferences: Pick<NewsMonitoringPreferences, "mode" | "vendorIds">): string {
  const selection = preferences.mode === "all" ? "all" : "selected:" + [...new Set(preferences.vendorIds)].sort().join(",");
  return `cached_cti_advisories_v4:${encodeURIComponent(owner)}:${selection}`;
}
