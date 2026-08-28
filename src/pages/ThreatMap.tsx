import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Building2,
  Clock3,
  Crosshair,
  ExternalLink,
  Factory,
  Globe2,
  Layers,
  Loader2,
  RadioTower,
  Search,
  ShieldAlert,
  Target,
  TrendingDown,
  TrendingUp,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageLayout } from "@/components/PageLayout";
import { EmptyState } from "@/components/EmptyState";
import { MetricCard, type MetricTone } from "@/components/MetricCard";

// As telas guardavam o tom como classe do Tailwind; o cartão pede o papel.
const metricTone = (tone?: string): MetricTone =>
  !tone ? "neutral"
    : /red|destructive/.test(tone) ? "critical"
    : /amber|yellow|orange/.test(tone) ? "warning"
    : /emerald|green/.test(tone) ? "positive"
    : "neutral";
import { useLanguage } from "@/contexts/LanguageContext";
import {
  fetchThreatMap,
  fetchThreatSectors,
  type RansomwareVictim,
  type RegionOption,
  type SectorOption,
  type ThreatMapData,
} from "@/services/threatApi";
import { toast } from "sonner";

const WINDOW_OPTIONS = [
  { days: 1, label: "24h" },
  { days: 3, label: "72h" },
  { days: 7, label: "7d" },
  { days: 30, label: "30d" },
];

const fmtDate = (iso?: string | null) => {
  if (!iso) return "-";
  const d = new Date(iso);
  return Number.isNaN(+d)
    ? "-"
    : d.toLocaleString(undefined, { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
};

const compact = (value: number) => new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 }).format(value);

const uniqueValues = (values: Array<string | undefined | null>) =>
  Array.from(new Set(values.map((value) => value?.trim()).filter(Boolean) as string[])).sort((a, b) =>
    a.localeCompare(b),
  );

const matchesVictimSearch = (victim: RansomwareVictim, query: string) => {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;

  return [
    victim.name,
    victim.group,
    victim.countryName,
    victim.country,
    victim.sector,
    victim.website,
  ].some((value) => value?.toLowerCase().includes(needle));
};

const hasEvidence = (victim: RansomwareVictim) =>
  Boolean(victim.screenshot || victim.press?.length || victim.infostealer || victim.permalink);

type SignalState = { label: string; tone: string; copy: string };
type PriorityItem = { label: string; value: string; tone?: string };

function EvidenceBadges({ victim }: { victim: RansomwareVictim }) {
  const badges = [
    victim.screenshot && "screenshot",
    victim.press?.length ? "press" : null,
    victim.infostealer ? "infostealer" : null,
    victim.permalink ? "source" : null,
  ].filter(Boolean) as string[];

  if (!badges.length) return <span className="text-xs text-muted-foreground">-</span>;

  return (
    <div className="flex flex-wrap gap-1.5">
      {badges.map((badge) => (
        <Badge key={badge} variant="outline" className="h-5 px-1.5 text-[10px] uppercase tracking-wide">
          {badge}
        </Badge>
      ))}
    </div>
  );
}

function FilterSelect({
  value,
  onValueChange,
  options,
  allLabel,
}: {
  value: string;
  onValueChange: (value: string) => void;
  options: string[];
  allLabel: string;
}) {
  return (
    <Select value={value} onValueChange={onValueChange}>
      <SelectTrigger className="h-9 text-xs font-semibold">
        <SelectValue />
      </SelectTrigger>
      <SelectContent className="max-h-72">
        <SelectItem value="all">{allLabel}</SelectItem>
        {options.map((option) => (
          <SelectItem key={option} value={option}>
            {option}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function VictimTable({
  victims,
  totalVictims,
  pt,
  victimSearch,
  setVictimSearch,
  groupFilter,
  setGroupFilter,
  countryFilter,
  setCountryFilter,
  sectorFilter,
  setSectorFilter,
  groupOptions,
  countryOptions,
  sectorOptions,
}: {
  victims: RansomwareVictim[];
  totalVictims: number;
  pt: boolean;
  victimSearch: string;
  setVictimSearch: (value: string) => void;
  groupFilter: string;
  setGroupFilter: (value: string) => void;
  countryFilter: string;
  setCountryFilter: (value: string) => void;
  sectorFilter: string;
  setSectorFilter: (value: string) => void;
  groupOptions: string[];
  countryOptions: string[];
  sectorOptions: string[];
}) {
  const evidenceCount = victims.filter(hasEvidence).length;

  return (
    <Card>
      <CardContent className="p-0">
        <div className="flex flex-col gap-4 border-b border-border p-5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <Clock3 className="h-5 w-5 text-primary" />
                <h2 className="text-xl font-black tracking-tight">{pt ? "Vítimas recentes" : "Recent victims"}</h2>
              </div>
              <p className="mt-1 text-sm font-medium text-muted-foreground">
                {pt
                  ? "Claims de ransomware ordenados para triagem rápida."
                  : "Ransomware claims ordered for fast triage."}
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="outline">{compact(victims.length)} / {compact(totalVictims)}</Badge>
              <Badge variant="secondary">{compact(evidenceCount)} {pt ? "com evidência" : "with evidence"}</Badge>
            </div>
          </div>

          <div className="grid gap-2 lg:grid-cols-[minmax(260px,1fr)_160px_160px_160px]">
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={victimSearch}
                onChange={(event) => setVictimSearch(event.target.value)}
                placeholder={pt ? "Buscar vítima, grupo, país ou setor" : "Search victim, crew, country, or sector"}
                className="h-9 pl-9 text-sm"
              />
            </div>
            <FilterSelect
              value={groupFilter}
              onValueChange={setGroupFilter}
              options={groupOptions}
              allLabel={pt ? "Todos grupos" : "All crews"}
            />
            <FilterSelect
              value={countryFilter}
              onValueChange={setCountryFilter}
              options={countryOptions}
              allLabel={pt ? "Todos países" : "All countries"}
            />
            <FilterSelect
              value={sectorFilter}
              onValueChange={setSectorFilter}
              options={sectorOptions}
              allLabel={pt ? "Todos setores" : "All sectors"}
            />
          </div>
        </div>

        {victims.length ? (
          <>
            <div className="hidden md:block">
              <Table className="table-fixed" stickyHeader>
                <TableHeader>
                  <TableRow className="bg-muted/45 hover:bg-muted/45">
                    <TableHead className="w-[24%] px-3 text-[11px] font-black uppercase tracking-wide">
                      {pt ? "Vítima" : "Victim"}
                    </TableHead>
                    <TableHead className="w-[14%] px-3 text-[11px] font-black uppercase tracking-wide">
                      {pt ? "Grupo" : "Crew"}
                    </TableHead>
                    <TableHead className="w-[13%] px-3 text-[11px] font-black uppercase tracking-wide">
                      {pt ? "País" : "Country"}
                    </TableHead>
                    <TableHead className="w-[16%] px-3 text-[11px] font-black uppercase tracking-wide">
                      {pt ? "Setor" : "Sector"}
                    </TableHead>
                    <TableHead className="w-[12%] px-3 text-[11px] font-black uppercase tracking-wide">
                      {pt ? "Descoberto" : "Discovered"}
                    </TableHead>
                    <TableHead className="w-[12%] px-3 text-[11px] font-black uppercase tracking-wide">
                      {pt ? "Evidência" : "Evidence"}
                    </TableHead>
                    <TableHead className="w-[7%] px-3 text-right text-[11px] font-black uppercase tracking-wide">
                      {pt ? "Fonte" : "Source"}
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {victims.slice(0, 60).map((victim) => (
                    <TableRow key={`${victim.id || victim.name}-${victim.discovered || victim.published}`}>
                      <TableCell className="px-3 py-3">
                        <div className="min-w-0">
                          <div className="truncate font-semibold text-foreground">{victim.name}</div>
                          <div className="mt-1 truncate text-xs text-muted-foreground">{victim.website || victim.source}</div>
                        </div>
                      </TableCell>
                      <TableCell className="px-3 py-3">
                        <Badge variant="secondary" className="max-w-full whitespace-normal break-words text-left">
                          {victim.group || "-"}
                        </Badge>
                      </TableCell>
                      {/* DEN-05: "United States ..." cortado não diz nada. Quebra
                          em duas linhas em vez de truncar, e o nome inteiro fica
                          no title para quem passa o mouse. */}
                      <TableCell className="px-3 py-3 font-medium leading-tight" title={victim.countryName || victim.country || ""}>
                        {victim.countryName || victim.country || "-"}
                      </TableCell>
                      <TableCell className="px-3 py-3 leading-tight text-muted-foreground" title={victim.sector || ""}>
                        {victim.sector || "-"}
                      </TableCell>
                      <TableCell className="px-3 py-3 font-mono text-xs text-muted-foreground">
                        {fmtDate(victim.discovered || victim.published)}
                      </TableCell>
                      <TableCell className="px-3 py-3">
                        <EvidenceBadges victim={victim} />
                      </TableCell>
                      <TableCell className="px-3 py-3 text-right">
                        {victim.permalink ? (
                          <Button asChild variant="ghost" size="icon" className="h-7 w-7">
                            <a href={victim.permalink} target="_blank" rel="noreferrer" aria-label={pt ? "Fonte" : "Source"}>
                              <span className="sr-only">{pt ? "Fonte" : "Source"}</span>
                              <ExternalLink className="h-3.5 w-3.5" />
                            </a>
                          </Button>
                        ) : (
                          <span className="text-xs text-muted-foreground">-</span>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>

            <div className="divide-y divide-border md:hidden">
              {victims.slice(0, 40).map((victim) => (
                <div key={`${victim.id || victim.name}-${victim.discovered || victim.published}`} className="p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate font-semibold text-foreground">{victim.name}</div>
                      <div className="mt-1 truncate text-xs text-muted-foreground">
                        {victim.countryName || victim.country || "-"} | {victim.sector || "-"}
                      </div>
                    </div>
                    <Badge variant="secondary" className="max-w-[120px] shrink-0 truncate">
                      {victim.group || "-"}
                    </Badge>
                  </div>
                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs text-muted-foreground">
                      {fmtDate(victim.discovered || victim.published)}
                    </span>
                    <EvidenceBadges victim={victim} />
                    {victim.permalink && (
                      <a
                        href={victim.permalink}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 text-xs font-bold text-primary hover:underline"
                      >
                        {pt ? "Fonte" : "Source"}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </>
        ) : (
          <EmptyState
            bare
            title={pt ? "Nenhuma vítima neste filtro" : "No victims in this filter"}
            description={pt
              ? "Limpe o grupo, o país ou o setor para ver as reivindicações do período inteiro."
              : "Clear the group, country or sector to see the whole period's claims."}
          />
        )}
      </CardContent>
    </Card>
  );
}

function SituationPanel({
  pt,
  signal,
  priority,
  delta,
  deltaTone,
  generatedAt,
}: {
  pt: boolean;
  signal: SignalState;
  priority: PriorityItem[];
  delta: ThreatMapData["delta"];
  deltaTone: string;
  generatedAt: string;
}) {
  return (
    <Card>
      <CardContent className="p-5">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-primary" />
            <h2 className="text-lg font-black tracking-tight">{pt ? "Situação agora" : "Current situation"}</h2>
          </div>
          <Badge variant="outline" className={signal.tone}>
            {signal.label}
          </Badge>
        </div>

        <p className="mb-4 text-sm font-medium leading-6 text-muted-foreground">{signal.copy}</p>

        {/* EST-06: o delta só existe se a janela anterior tiver dado. A fonte
            (/v2/recentvictims) devolve uma fatia fixa de 100 vítimas dos últimos
            dias, então a janela anterior costuma vir vazia — e aí o delta saía
            "+100 (100%)" ao lado de "Claims 100", repetindo o total e não
            informando nada. Sem comparação, dizemos isso. */}
        <div className="grid gap-2 border-y border-border py-4 text-xs">
          {delta.previousVictims > 0 ? (
            <>
              <div className="flex items-center justify-between gap-3">
                <span className="text-muted-foreground">Delta</span>
                <span className={`font-mono font-bold ${deltaTone}`}>
                  {delta.victims > 0 ? "+" : ""}{compact(delta.victims)} ({compact(delta.percent)}%)
                </span>
              </div>
              <div className="flex items-center justify-between gap-3">
                <span className="text-muted-foreground">{pt ? "Janela anterior" : "Previous window"}</span>
                <span className="font-mono font-bold">{compact(delta.previousVictims)}</span>
              </div>
            </>
          ) : (
            <div className="flex items-start justify-between gap-3">
              <span className="text-muted-foreground">{pt ? "Comparação" : "Comparison"}</span>
              <span className="max-w-[62%] text-right font-medium text-muted-foreground">
                {pt
                  ? "A fonte só publica as vítimas mais recentes; não há janela anterior para comparar."
                  : "The source only publishes the most recent victims; there is no previous window to compare."}
              </span>
            </div>
          )}
          <div className="flex items-center justify-between gap-3">
            <span className="text-muted-foreground">{pt ? "Atualizado" : "Updated"}</span>
            <span className="font-mono font-bold">{fmtDate(generatedAt)}</span>
          </div>
        </div>

        <div className="mt-4 grid gap-3 text-sm">
          <div className="flex items-center gap-2">
            <Target className="h-4 w-4 text-primary" />
            <h3 className="text-xs font-black uppercase tracking-wide text-muted-foreground">
              {pt ? "Prioridade" : "Priority"}
            </h3>
          </div>
          {priority.map((item) => (
            <div key={item.label} className="flex items-center justify-between gap-3">
              <span className="text-muted-foreground">{item.label}</span>
              <span className={`max-w-[190px] truncate text-right font-semibold ${item.tone || "text-foreground"}`}>
                {item.value}
              </span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

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

const readScope = (): Scope => (localStorage.getItem(LS.scope) === "global" ? "global" : "focus");

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
      <PopoverContent align="start" className="w-80 p-0">
        <div className="flex items-center justify-between gap-2 border-b border-border p-3">
          <span className="text-xs font-black uppercase tracking-wide text-muted-foreground">
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
    <Card>
      <CardContent className="flex flex-col gap-4 p-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center gap-3">
          <div className="flex rounded-md border border-border bg-background p-1">
            <Button
              size="sm"
              variant={scope === "focus" ? "secondary" : "ghost"}
              className="h-8 gap-1.5 px-3 text-xs font-bold"
              onClick={() => setScope("focus")}
            >
              <Target className="h-3.5 w-3.5" />
              {pt ? "Prioridades" : "Priorities"}
            </Button>
            <Button
              size="sm"
              variant={scope === "global" ? "secondary" : "ghost"}
              className="h-8 gap-1.5 px-3 text-xs font-bold"
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
                  onClick={() => toggleRegion(region.key)}
                  className={`rounded-full border px-3 py-1 text-xs font-bold transition-colors ${
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
            {pt ? "Visão global — 100 claims mais recentes." : "Global view — 100 most recent claims."}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

const ThreatMap = () => {
  const { language } = useLanguage();
  const pt = language === "pt";
  const [data, setData] = useState<ThreatMapData | null>(null);
  const [windowDays, setWindowDays] = useState(3);
  const [loading, setLoading] = useState(true);
  const [victimSearch, setVictimSearch] = useState("");
  const [groupFilter, setGroupFilter] = useState("all");
  const [countryFilter, setCountryFilter] = useState("all");
  const [sectorFilter, setSectorFilter] = useState("all");

  const [scope, setScopeState] = useState<Scope>(readScope);
  const [sectorCatalog, setSectorCatalog] = useState<SectorOption[]>([]);
  const [regionCatalog, setRegionCatalog] = useState<RegionOption[]>([]);
  const [selectedSectors, setSelectedSectors] = useState<string[]>([]);
  const [selectedRegions, setSelectedRegions] = useState<string[]>([]);
  const [catalogLoaded, setCatalogLoaded] = useState(false);

  // Load the sector/region catalog once and seed selections from localStorage,
  // falling back to keyword-matched sector defaults and the server's default
  // region set. On failure, still let global scope work.
  useEffect(() => {
    let cancelled = false;
    fetchThreatSectors()
      .then((catalog) => {
        if (cancelled) return;
        setSectorCatalog(catalog.sectors);
        setRegionCatalog(catalog.regions);
        setSelectedSectors(readList(LS.sectors) ?? autoMatchSectors(catalog.sectors));
        setSelectedRegions(readList(LS.regions) ?? catalog.defaultRegions);
      })
      .catch(() => {
        /* focus mode degrades to global on the backend; nothing to surface here */
      })
      .finally(() => {
        if (!cancelled) setCatalogLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const setScope = useCallback((next: Scope) => {
    setScopeState(next);
    localStorage.setItem(LS.scope, next);
  }, []);

  const applySectors = useCallback((next: string[]) => {
    setSelectedSectors(next);
    localStorage.setItem(LS.sectors, JSON.stringify(next));
  }, []);

  const toggleRegion = useCallback((key: string) => {
    setSelectedRegions((prev) => {
      const next = prev.includes(key) ? prev.filter((k) => k !== key) : [...prev, key];
      localStorage.setItem(LS.regions, JSON.stringify(next));
      return next;
    });
  }, []);

  const loadWindow = useCallback(
    async (days: number, currentScope: Scope, sectors: string[], regions: string[]) => {
      setLoading(true);
      try {
        const focus = currentScope === "focus" ? { sectors, regions } : undefined;
        setData(await fetchThreatMap(days, focus));
      } catch (e) {
        toast.error(e instanceof Error ? e.message : "Failed to load threat map");
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  // Refetch whenever the window or the focus selection changes. Focus scope waits
  // for the catalog so it queries with the real sector selection, not an empty one.
  useEffect(() => {
    if (scope === "focus" && !catalogLoaded) return;
    void loadWindow(windowDays, scope, selectedSectors, selectedRegions);
  }, [loadWindow, windowDays, scope, catalogLoaded, selectedSectors, selectedRegions]);

  const filteredVictims = useMemo(() => {
    return (data?.victims || []).filter((victim) => (
      matchesVictimSearch(victim, victimSearch)
      && (groupFilter === "all" || victim.group === groupFilter)
      && (countryFilter === "all" || victim.countryName === countryFilter || victim.country === countryFilter)
      && (sectorFilter === "all" || victim.sector === sectorFilter)
    ));
  }, [countryFilter, data?.victims, groupFilter, sectorFilter, victimSearch]);

  const groupOptions = useMemo(() => uniqueValues(data?.victims.map((victim) => victim.group) || []), [data?.victims]);
  const countryOptions = useMemo(
    () => uniqueValues(data?.victims.map((victim) => victim.countryName || victim.country) || []),
    [data?.victims],
  );
  const sectorOptions = useMemo(() => uniqueValues(data?.victims.map((victim) => victim.sector) || []), [data?.victims]);

  const totalVictims = data?.totalVictims ?? data?.victims.length ?? 0;
  const topGroup = data?.groups[0] || null;
  const topSector = data?.sectors?.[0] || null;
  const latestVictim = data?.victims[0] || null;
  const delta = data?.delta;
  const deltaTone = delta?.direction === "up"
    ? "text-red-500"
    : delta?.direction === "down"
      ? "text-emerald-500"
      : "text-muted-foreground";

  const signal: SignalState | null = data
    ? totalVictims >= 20 || data.activeGroups >= 6
      ? {
        label: pt ? "Pressão alta" : "High pressure",
        tone: "text-red-500",
        copy: pt
          ? "Volume ou dispersão acima do normal. Priorize vítimas novas, grupos líderes e setores com repetição."
          : "Volume or spread is above normal. Prioritize new victims, leading crews, and repeated sectors.",
      }
      : totalVictims >= 8
        ? {
          label: pt ? "Pressão moderada" : "Moderate pressure",
          tone: "text-amber-500",
          copy: pt
            ? "Atividade relevante no recorte. Vale acompanhar claims com evidência e países recorrentes."
            : "Relevant activity in this window. Track claims with evidence and recurring countries.",
        }
        : {
          label: pt ? "Pressão baixa" : "Low pressure",
          tone: "text-emerald-500",
          copy: pt
            ? "Baixo volume no recorte atual. Mantenha observação da próxima janela."
            : "Low volume in the current window. Keep watching the next window.",
        }
    : null;

  const kpis = data ? [
    { label: pt ? "Claims" : "Claims", value: totalVictims, icon: AlertTriangle },
    {
      label: pt ? "Delta" : "Delta",
      value: `${delta?.victims && delta.victims > 0 ? "+" : ""}${compact(delta?.victims || 0)}`,
      icon: delta?.direction === "down" ? TrendingDown : TrendingUp,
      tone: deltaTone,
    },
    { label: pt ? "Países" : "Countries", value: data.countries.length, icon: Globe2 },
    { label: pt ? "Grupos" : "Crews", value: data.activeGroups, icon: Crosshair },
    { label: pt ? "Setores" : "Sectors", value: data.sectors?.length || 0, icon: Building2 },
  ] : [];

  const priority: PriorityItem[] = data ? [
    { label: pt ? "País mais atingido" : "Top country", value: data.topCountry?.countryName || data.topCountry?.name || "-" },
    { label: pt ? "Grupo mais ativo" : "Top crew", value: topGroup?.name || "-" },
    { label: pt ? "Setor mais atingido" : "Top sector", value: topSector?.name || "-" },
    { label: pt ? "LATAM" : "LATAM", value: `${compact(data.latam?.victims || 0)} ${pt ? "vítimas" : "victims"}` },
    { label: pt ? "Última vítima" : "Latest victim", value: latestVictim?.name || "-" },
  ] : [];

  return (
    <PageLayout width="max-w-7xl" showBackButton={false}>
      <div className="page-head">
        <div>
          <h1 className="page-title">
            {pt ? "Vítimas de Ransomware" : "Ransomware Victims"}
          </h1>
          <p className="page-lede max-w-2xl">
            {pt
              ? "Vítimas reivindicadas por grupo, país, setor e data, com a evidência de cada reivindicação."
              : "Victims claimed by group, country, sector and date, with the evidence behind each claim."}
          </p>
          <Badge variant="outline" className="mt-3 gap-1.5 font-normal">
            <RadioTower className="h-3.5 w-3.5" />
            {data?.source || "ransomware.live"}
          </Badge>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex rounded-md border border-border bg-background p-1">
            {WINDOW_OPTIONS.map((option) => (
              <Button
                key={option.days}
                size="sm"
                variant={windowDays === option.days ? "secondary" : "ghost"}
                className="h-8 px-3 font-mono text-xs"
                onClick={() => setWindowDays(option.days)}
              >
                {option.label}
              </Button>
            ))}
          </div>
          <Button
            variant="outline"
            onClick={() => loadWindow(windowDays, scope, selectedSectors, selectedRegions)}
            disabled={loading}
          >
            {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {pt ? "Atualizar" : "Refresh"}
          </Button>
        </div>
      </div>

      {loading && !data ? (
        <div className="flex items-center justify-center py-20 text-muted-foreground">
          <Loader2 className="mr-2 h-5 w-5 animate-spin" /> {pt ? "Carregando radar..." : "Loading radar..."}
        </div>
      ) : data && signal && delta ? (
        <div className="space-y-5">
          <FocusControls
            scope={scope}
            setScope={setScope}
            regionCatalog={regionCatalog}
            selectedRegions={selectedRegions}
            toggleRegion={toggleRegion}
            sectorCatalog={sectorCatalog}
            selectedSectors={selectedSectors}
            setSelectedSectors={applySectors}
            pt={pt}
          />

          <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
            {/* SIS-01: um desenho só de cartão de métrica, em três tamanhos. */}
            {kpis.map(({ label, value, icon: Icon, tone }) => (
              <MetricCard key={label} label={label} value={value} icon={Icon} tone={metricTone(tone)} />
            ))}
          </div>

          <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
            <VictimTable
              victims={filteredVictims}
              totalVictims={totalVictims}
              pt={pt}
              victimSearch={victimSearch}
              setVictimSearch={setVictimSearch}
              groupFilter={groupFilter}
              setGroupFilter={setGroupFilter}
              countryFilter={countryFilter}
              setCountryFilter={setCountryFilter}
              sectorFilter={sectorFilter}
              setSectorFilter={setSectorFilter}
              groupOptions={groupOptions}
              countryOptions={countryOptions}
              sectorOptions={sectorOptions}
            />
            <div className="space-y-5">
              <SituationPanel
                pt={pt}
                signal={signal}
                priority={priority}
                delta={delta}
                deltaTone={deltaTone}
                generatedAt={data.generatedAt}
              />
            </div>
          </div>
        </div>
      ) : (
        <Card>
          <CardContent className="p-8 text-center text-sm font-medium text-muted-foreground">
            {pt ? "Não foi possível carregar o mapa de ameaças." : "Threat map could not be loaded."}
          </CardContent>
        </Card>
      )}
    </PageLayout>
  );
};

export default ThreatMap;
