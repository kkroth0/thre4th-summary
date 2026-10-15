import { useCallback, useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Building2, Crosshair, Factory, Globe2, Layers, RefreshCw, Target } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PageLayout } from "@/components/PageLayout";
import { CtiFyiSource } from '@/components/CtiFyiSource';
import { PageHeader } from "@/components/PageHeader";
import { LoadingRows } from "@/components/LoadingState";
import { RansomwareVictimsTable, type RansomwareVictimFilters } from "@/components/workbench/RansomwareVictimsTable";
import { useLanguage } from "@/contexts/LanguageContext";
import { fetchThreatMap, fetchThreatSectors, type RegionOption, type SectorOption } from "@/services/threatApi";

const WINDOW_OPTIONS = [{ days: 1, label: "24h" }, { days: 3, label: "72h" }, { days: 7, label: "7d" }, { days: 30, label: "30d" }];
const compact = (value: number) => new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 }).format(value);
const fmtDate = (iso: string, pt: boolean) => Number.isFinite(Date.parse(iso)) ? new Date(iso).toLocaleString(pt ? 'pt-BR' : 'en-US', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }) : '—';

// Keywords used to pre-select the user's priority sectors from whatever exact
// names the API taxonomy exposes (matched case-insensitively as substrings).
const PRIORITY_SECTOR_KEYWORDS = [
  "energy", "power", "utilit", "oil", "gas",
  "cement", "construction", "building",
  "digital", "web", "platform", "internet", "online", "software", "technolog", "information technology",
  "industr", "manufactur",
  "mining", "metal",
];

const autoMatchSectors = (catalog: SectorOption[]): string[] =>
  catalog
    .filter((sector) => {
      const name = sector.name.toLowerCase();
      return PRIORITY_SECTOR_KEYWORDS.some((keyword) => name.includes(keyword));
    })
    .map((sector) => sector.name);

const LS = {
  scope: "threatmap.scope",
  sectors: "threatmap.sectors",
  regions: "threatmap.regions",
};

const readList = (key: string): string[] | null => {
  try {
    const value = JSON.parse(localStorage.getItem(key) || "null");
    return Array.isArray(value) ? (value as string[]) : null;
  } catch {
    return null;
  }
};

type Scope = "focus" | "global";

const readScope = (): Scope => { try { return localStorage.getItem(LS.scope) === "global" ? "global" : "focus"; } catch { return "focus"; } };

function SectorPicker({
  catalog,
  selected,
  onApply,
  pt,
}: {
  catalog: SectorOption[];
  selected: string[];
  onApply: (next: string[]) => void;
  pt: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<string[]>(selected);

  useEffect(() => {
    if (open) setDraft(selected);
  }, [open, selected]);

  const toggle = (name: string) =>
    setDraft((prev) => (prev.includes(name) ? prev.filter((s) => s !== name) : [...prev, name]));

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className="h-9 gap-2 font-semibold">
          <Factory className="h-4 w-4" />
          {pt ? "Setores" : "Sectors"}
          <Badge variant="secondary" className="ml-1">{selected.length}</Badge>
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="workbench w-80 max-w-[calc(100vw-2rem)] p-0">
        <div className="flex items-center justify-between gap-2 border-b border-border p-3">
          <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            {pt ? "Setores prioritários" : "Priority sectors"}
          </span>
          <div className="flex gap-1">
            <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={() => setDraft(autoMatchSectors(catalog))}>
              {pt ? "Padrão" : "Default"}
            </Button>
            <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={() => setDraft([])}>
              {pt ? "Limpar" : "Clear"}
            </Button>
          </div>
        </div>
        <ScrollArea className="h-72">
          <div className="p-2">
            {catalog.length === 0 ? (
              <div className="p-4 text-center text-xs text-muted-foreground">
                {pt ? "Lista de setores indisponível (requer API Pro)." : "Sector list unavailable (requires Pro API)."}
              </div>
            ) : (
              catalog.map((sector) => (
                <label
                  key={sector.name}
                  className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 hover:bg-muted/60"
                >
                  <Checkbox checked={draft.includes(sector.name)} onCheckedChange={() => toggle(sector.name)} />
                  <span className="min-w-0 flex-1 truncate text-sm">{sector.name}</span>
                  <span className="shrink-0 font-mono text-[11px] text-muted-foreground">{compact(sector.count)}</span>
                </label>
              ))
            )}
          </div>
        </ScrollArea>
        <div className="flex items-center justify-between gap-2 border-t border-border p-3">
          <span className="text-xs text-muted-foreground">{compact(draft.length)} {pt ? "selecionados" : "selected"}</span>
          <Button
            size="sm"
            className="h-8"
            onClick={() => {
              onApply(draft);
              setOpen(false);
            }}
          >
            {pt ? "Aplicar" : "Apply"}
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  );
}

function FocusControls({
  scope,
  setScope,
  regionCatalog,
  selectedRegions,
  toggleRegion,
  sectorCatalog,
  selectedSectors,
  setSelectedSectors,
  pt,
}: {
  scope: Scope;
  setScope: (scope: Scope) => void;
  regionCatalog: RegionOption[];
  selectedRegions: string[];
  toggleRegion: (key: string) => void;
  sectorCatalog: SectorOption[];
  selectedSectors: string[];
  setSelectedSectors: (next: string[]) => void;
  pt: boolean;
}) {
  return (
    <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center gap-3">
          <div className="flex rounded-md border border-border bg-background p-1">
            <Button
              size="sm"
              variant={scope === "focus" ? "secondary" : "ghost"}
              className="h-8 gap-1.5 px-3 text-xs font-medium"
              aria-pressed={scope === "focus"}
              onClick={() => setScope("focus")}
            >
              <Target className="h-3.5 w-3.5" />
              {pt ? "Prioridades" : "Priorities"}
            </Button>
            <Button
              size="sm"
              variant={scope === "global" ? "secondary" : "ghost"}
              className="h-8 gap-1.5 px-3 text-xs font-medium"
              aria-pressed={scope === "global"}
              onClick={() => setScope("global")}
            >
              <Globe2 className="h-3.5 w-3.5" />
              {pt ? "Global" : "Global"}
            </Button>
          </div>
          {scope === "focus" && (
            <SectorPicker catalog={sectorCatalog} selected={selectedSectors} onApply={setSelectedSectors} pt={pt} />
          )}
        </div>

        {scope === "focus" ? (
          <div className="flex flex-wrap items-center gap-2">
            <Layers className="h-4 w-4 text-muted-foreground" />
            {regionCatalog.map((region) => {
              const active = selectedRegions.includes(region.key);
              return (
                <button
                  key={region.key}
                  type="button"
                  aria-pressed={active}
                  onClick={() => toggleRegion(region.key)}
                  className={`rounded-md border px-3 py-1.5 text-xs font-medium transition-colors ${
                    active
                      ? "border-primary/40 bg-primary/15 text-primary"
                      : "border-border bg-background text-muted-foreground hover:bg-muted/60"
                  }`}
                >
                  {region.label}
                </button>
              );
            })}
          </div>
        ) : (
          <p className="text-xs font-medium text-muted-foreground">
            {pt ? "Visão global do feed recente da fonte." : "Global view of the source’s recent feed."}
          </p>
        )}
    </div>
  );
}

const ThreatMap = () => {
  const { language } = useLanguage(); const pt = language === "pt";
  const [windowDays, setWindowDays] = useState(3);
  const [victimFilters, setVictimFilters] = useState<RansomwareVictimFilters>({ search: '', group: 'all', country: 'all', sector: 'all' });
  const [scope, setScopeState] = useState<Scope>(readScope);
  const [sectorCatalog, setSectorCatalog] = useState<SectorOption[]>([]);
  const [regionCatalog, setRegionCatalog] = useState<RegionOption[]>([]);
  const [selectedSectors, setSelectedSectors] = useState<string[]>([]);
  const [selectedRegions, setSelectedRegions] = useState<string[]>([]);
  const [catalogLoaded, setCatalogLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetchThreatSectors().then(catalog => {
      if (cancelled) return;
      setSectorCatalog(catalog.sectors); setRegionCatalog(catalog.regions);
      setSelectedSectors(readList(LS.sectors) ?? autoMatchSectors(catalog.sectors));
      setSelectedRegions(readList(LS.regions) ?? catalog.defaultRegions);
    }).catch(() => { /* The existing API can still return the global recent feed. */ })
      .finally(() => { if (!cancelled) setCatalogLoaded(true); });
    return () => { cancelled = true; };
  }, []);
  const setScope = useCallback((next: Scope) => {
    setScopeState(next); try { localStorage.setItem(LS.scope, next); } catch { /* session preference remains usable */ }
  }, []);
  const applySectors = useCallback((next: string[]) => {
    setSelectedSectors(next); try { localStorage.setItem(LS.sectors, JSON.stringify(next)); } catch { /* session preference remains usable */ }
  }, []);
  const toggleRegion = useCallback((key: string) => {
    setSelectedRegions(previous => {
      const next = previous.includes(key) ? previous.filter(value => value !== key) : [...previous, key];
      try { localStorage.setItem(LS.regions, JSON.stringify(next)); } catch { /* session preference remains usable */ }
      return next;
    });
  }, []);
  const feed = useQuery({
    queryKey: ['ransomware-victims', windowDays, scope, scope === 'focus' ? selectedSectors : [], scope === 'focus' ? selectedRegions : []],
    queryFn: () => fetchThreatMap(windowDays, scope === 'focus' ? { sectors: selectedSectors, regions: selectedRegions } : undefined),
    enabled: scope === 'global' || catalogLoaded,
    staleTime: 60_000,
    retry: 1,
  });
  const data = feed.data;
  const metrics = data ? [
    { label: pt ? 'Reivindicações' : 'Claims', value: data.totalVictims ?? data.victims.length, icon: AlertTriangle },
    { label: pt ? 'Grupos' : 'Groups', value: data.activeGroups, icon: Crosshair },
    { label: pt ? 'Países' : 'Countries', value: data.countries.length, icon: Globe2 },
    { label: pt ? 'Setores' : 'Sectors', value: data.sectors.length, icon: Building2 },
  ] : [];
  return <PageLayout width="max-w-[1600px]">
    <PageHeader title={pt ? 'Vítimas de Ransomware' : 'Ransomware Victims'} subtitle={pt ? 'Reivindicações por grupo, país e setor, com referências para investigação.' : 'Claims by group, country and sector, with investigation references.'}
      actions={<Button size="sm" variant="outline" onClick={() => feed.refetch()} disabled={feed.isFetching || (scope === 'focus' && !catalogLoaded)}><RefreshCw className={`mr-2 h-3.5 w-3.5 ${feed.isFetching ? 'animate-spin' : ''}`} />{pt ? 'Atualizar' : 'Refresh'}</Button>} />
    <section className="intel-panel mb-4 p-4">
      <div className="mb-3 flex flex-wrap items-center gap-3 border-b pb-3"><span className="text-xs text-muted-foreground">{pt ? 'Período' : 'Period'}</span><div className="flex flex-wrap gap-1" aria-label={pt ? 'Período das reivindicações' : 'Claim period'}>{WINDOW_OPTIONS.map(option => <Button key={option.days} size="sm" variant={windowDays === option.days ? 'secondary' : 'ghost'} aria-pressed={windowDays === option.days} className="h-8 px-3 font-mono text-xs" onClick={() => setWindowDays(option.days)}>{option.label}</Button>)}</div><span className="ml-auto text-xs text-muted-foreground">{data?.source || 'ransomware.live'}</span></div>
      <FocusControls scope={scope} setScope={setScope} regionCatalog={regionCatalog} selectedRegions={selectedRegions} toggleRegion={toggleRegion} sectorCatalog={sectorCatalog} selectedSectors={selectedSectors} setSelectedSectors={applySectors} pt={pt} />
      {scope === 'focus' && catalogLoaded && !selectedSectors.length && <p className="mt-3 text-xs text-muted-foreground">{pt ? 'Sem setores selecionados: exibindo o feed recente global. O recorte por setor depende do catálogo disponível na fonte.' : 'No sectors selected: showing the recent global feed. Sector scope depends on the source catalog.'}</p>}
    </section>
    {feed.isPending ? <LoadingRows rows={6} /> : feed.isError ? <div role="alert" className="intel-panel p-6"><p className="text-sm text-destructive">{pt ? 'Não foi possível atualizar as vítimas de ransomware.' : 'Could not refresh ransomware victims.'}</p><Button variant="outline" size="sm" className="mt-3" onClick={() => feed.refetch()}>{pt ? 'Tentar novamente' : 'Try again'}</Button></div> : data ? <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">{metrics.map(metric => <div key={metric.label} className="intel-panel px-5 py-4"><div className="flex items-center justify-between gap-2 text-xs text-muted-foreground"><span>{metric.label}</span><metric.icon className="h-4 w-4" /></div><p className="mt-3 text-2xl font-semibold tabular-nums">{compact(metric.value)}</p></div>)}</div>
      <details className="intel-panel"><summary className="cursor-pointer px-4 py-3 text-xs">{pt ? 'Contexto do recorte' : 'Selection context'}<span className="ml-2 text-muted-foreground">· {pt ? 'Atualizado' : 'Updated'} {fmtDate(data.generatedAt, pt)}</span></summary><div className="grid gap-4 border-t p-4 text-sm sm:grid-cols-2 xl:grid-cols-4">{[
        [pt ? 'País com mais registros' : 'Country with most records', data.topCountry?.countryName || data.topCountry?.name || '—'],
        [pt ? 'Grupo com mais registros' : 'Group with most records', data.groups[0]?.name || '—'],
        [pt ? 'Setor com mais registros' : 'Sector with most records', data.sectors[0]?.name || '—'],
        ['LATAM', `${data.latam.victims} ${pt ? 'reivindicações' : 'claims'}`],
      ].map(([label, value]) => <div key={label}><p className="intel-eyebrow">{label}</p><p className="mt-2 break-words">{value}</p></div>)}<p className="text-xs text-muted-foreground sm:col-span-2 xl:col-span-4">{data.delta.previousVictims > 0 ? `${pt ? 'Variação contra a janela anterior' : 'Change against previous window'}: ${data.delta.victims > 0 ? '+' : ''}${data.delta.victims} (${data.delta.percent}%). ${pt ? 'Registros na janela anterior' : 'Previous-window records'}: ${data.delta.previousVictims}.` : pt ? 'Comparação indisponível: a fonte não retornou registros na janela anterior.' : 'Comparison unavailable: the source returned no previous-window records.'}</p></div></details>
      <CtiFyiSource pt={pt} /><RansomwareVictimsTable victims={data.victims} pt={pt} filters={victimFilters} onFiltersChange={setVictimFilters} />
      <p className="text-xs leading-5 text-muted-foreground">{pt ? 'Totais referentes ao recorte recebido da fonte. Os filtros da tabela refinam os registros exibidos. Reivindicações não representam confirmação independente dos incidentes; o feed recente pode ter cobertura limitada.' : 'Totals refer to the selection returned by the source. Table filters refine displayed records. Claims are not independent confirmation of incidents; the recent feed may have limited coverage.'}</p>
    </div> : null}
  </PageLayout>;
};
export default ThreatMap;
