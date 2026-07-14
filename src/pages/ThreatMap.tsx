import { useCallback, useEffect, useMemo, useState, type ElementType } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Building2,
  Clock3,
  Crosshair,
  ExternalLink,
  Globe2,
  Loader2,
  MapPinned,
  RadioTower,
  Search,
  ShieldAlert,
  SlidersHorizontal,
  Target,
  TrendingDown,
  TrendingUp,
  Users,
  Zap,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageLayout } from "@/components/PageLayout";
import { ThreatWorldMap } from "@/components/ThreatWorldMap";
import { useLanguage } from "@/contexts/LanguageContext";
import { fetchThreatMap, type CountItem, type RansomwareVictim, type ThreatMapData } from "@/services/threatApi";
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

const windowLabel = (days: number) => {
  if (days === 1) return "24h";
  if (days === 3) return "72h";
  return `${days}d`;
};

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

type ThreatInsight = ThreatMapData["insights"][number];
type SignalState = { label: string; tone: string; copy: string };
type PriorityItem = { label: string; value: string; tone?: string };
type RankingRow = CountItem & { countryName?: string };

const insightText = (insight: ThreatInsight, pt: boolean) => {
  switch (insight.kind) {
    case "volume":
      return {
        title: pt ? "Ritmo da janela" : "Window pace",
        detail: pt
          ? `${compact(insight.value || 0)} reivindicacoes, ${insight.delta && insight.delta > 0 ? "+" : ""}${compact(insight.delta || 0)} vs. janela anterior.`
          : `${compact(insight.value || 0)} claims, ${insight.delta && insight.delta > 0 ? "+" : ""}${compact(insight.delta || 0)} vs. previous window.`,
        icon: insight.delta && insight.delta < 0 ? TrendingDown : TrendingUp,
      };
    case "top-group":
      return {
        title: pt ? "Grupo lider" : "Leading crew",
        detail: pt
          ? `${insight.name || "-"} concentra ${compact(insight.count || 0)} reivindicacoes no recorte.`
          : `${insight.name || "-"} accounts for ${compact(insight.count || 0)} claims in this window.`,
        icon: Crosshair,
      };
    case "sector":
      return {
        title: pt ? "Setor pressionado" : "Sector under pressure",
        detail: pt
          ? `${insight.name || "-"} aparece em ${compact(insight.count || 0)} reivindicacoes recentes.`
          : `${insight.name || "-"} appears in ${compact(insight.count || 0)} recent claims.`,
        icon: Building2,
      };
    case "new-countries":
      return {
        title: pt ? "Novos paises no recorte" : "New countries in window",
        detail: (insight.countries || []).map((c) => c.countryName || c.name).join(", "),
        icon: Globe2,
      };
    case "latam":
      return {
        title: pt ? "Sinal LATAM" : "LATAM signal",
        detail: pt
          ? `${compact(insight.count || 0)} reivindicacoes em ${compact(insight.countries?.length || 0)} paises da regiao.`
          : `${compact(insight.count || 0)} claims across ${compact(insight.countries?.length || 0)} regional countries.`,
        icon: RadioTower,
      };
    case "evidence":
      return {
        title: pt ? "Evidencia enriquecida" : "Enriched evidence",
        detail: pt
          ? `${compact(insight.count || 0)} vitimas com link, screenshot, press ou infostealer.`
          : `${compact(insight.count || 0)} victims include link, screenshot, press, or infostealer evidence.`,
        icon: Zap,
      };
    default:
      return {
        title: pt ? "Insight" : "Insight",
        detail: "",
        icon: Activity,
      };
  }
};

const severityClass = (severity: string) => ({
  high: "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-300",
  medium: "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-300",
  low: "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-300",
  context: "border-sky-500/30 bg-sky-500/10 text-sky-600 dark:text-sky-300",
}[severity] || "border-border bg-muted text-muted-foreground");

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
                <h2 className="text-xl font-black tracking-tight">{pt ? "Vitimas recentes" : "Recent victims"}</h2>
              </div>
              <p className="mt-1 text-sm font-medium text-muted-foreground">
                {pt
                  ? "Claims de ransomware ordenados para triagem rapida."
                  : "Ransomware claims ordered for fast triage."}
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="outline">{compact(victims.length)} / {compact(totalVictims)}</Badge>
              <Badge variant="secondary">{compact(evidenceCount)} {pt ? "com evidencia" : "with evidence"}</Badge>
            </div>
          </div>

          <div className="grid gap-2 lg:grid-cols-[minmax(260px,1fr)_160px_160px_160px]">
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={victimSearch}
                onChange={(event) => setVictimSearch(event.target.value)}
                placeholder={pt ? "Buscar vitima, grupo, pais ou setor" : "Search victim, crew, country, or sector"}
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
              allLabel={pt ? "Todos paises" : "All countries"}
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
              <Table className="table-fixed">
                <TableHeader>
                  <TableRow className="bg-muted/45 hover:bg-muted/45">
                    <TableHead className="w-[28%] px-3 text-[11px] font-black uppercase tracking-wide">
                      {pt ? "Vitima" : "Victim"}
                    </TableHead>
                    <TableHead className="w-[12%] px-3 text-[11px] font-black uppercase tracking-wide">
                      {pt ? "Grupo" : "Crew"}
                    </TableHead>
                    <TableHead className="w-[13%] px-3 text-[11px] font-black uppercase tracking-wide">
                      {pt ? "Pais" : "Country"}
                    </TableHead>
                    <TableHead className="w-[16%] px-3 text-[11px] font-black uppercase tracking-wide">
                      {pt ? "Setor" : "Sector"}
                    </TableHead>
                    <TableHead className="w-[12%] px-3 text-[11px] font-black uppercase tracking-wide">
                      {pt ? "Descoberto" : "Discovered"}
                    </TableHead>
                    <TableHead className="w-[12%] px-3 text-[11px] font-black uppercase tracking-wide">
                      {pt ? "Evidencia" : "Evidence"}
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
                        <Badge variant="secondary" className="max-w-full truncate">
                          {victim.group || "-"}
                        </Badge>
                      </TableCell>
                      <TableCell className="truncate px-3 py-3 font-medium">
                        {victim.countryName || victim.country || "-"}
                      </TableCell>
                      <TableCell className="truncate px-3 py-3 text-muted-foreground">
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
          <div className="p-8 text-center text-sm font-medium text-muted-foreground">
            {pt ? "Nenhuma vitima encontrada nesse filtro." : "No victims found for this filter."}
          </div>
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
            <h2 className="text-lg font-black tracking-tight">{pt ? "Situacao agora" : "Current situation"}</h2>
          </div>
          <Badge variant="outline" className={signal.tone}>
            {signal.label}
          </Badge>
        </div>

        <p className="mb-4 text-sm font-medium leading-6 text-muted-foreground">{signal.copy}</p>

        <div className="grid gap-2 border-y border-border py-4 text-xs">
          <div className="flex items-center justify-between gap-3">
            <span className="text-muted-foreground">{pt ? "Delta" : "Delta"}</span>
            <span className={`font-mono font-bold ${deltaTone}`}>
              {delta.victims > 0 ? "+" : ""}{compact(delta.victims)} ({compact(delta.percent)}%)
            </span>
          </div>
          <div className="flex items-center justify-between gap-3">
            <span className="text-muted-foreground">{pt ? "Janela anterior" : "Previous window"}</span>
            <span className="font-mono font-bold">{compact(delta.previousVictims)}</span>
          </div>
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

function ContextMapPanel({ data, pt }: { data: ThreatMapData; pt: boolean }) {
  return (
    <Card className="overflow-hidden">
      <CardContent className="p-0">
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <div className="flex items-center gap-2">
            <MapPinned className="h-4 w-4 text-primary" />
            <h2 className="text-sm font-black tracking-tight">{pt ? "Mapa contextual" : "Map context"}</h2>
          </div>
          <Badge variant="outline">{data.countries.length} {pt ? "paises" : "countries"}</Badge>
        </div>
        <div className="bg-[linear-gradient(180deg,#0a1120,#0d1a2f)] p-2">
          <ThreatWorldMap countries={data.countries} />
        </div>
      </CardContent>
    </Card>
  );
}

function RankingList({
  icon: Icon,
  title,
  rows,
}: {
  icon: ElementType;
  title: string;
  rows: RankingRow[];
}) {
  return (
    <Card>
      <CardContent className="p-5">
        <div className="mb-4 flex items-center gap-2">
          <Icon className="h-5 w-5 text-primary" />
          <h2 className="text-lg font-black tracking-tight">{title}</h2>
        </div>
        <div className="space-y-2">
          {rows.map((row) => (
            <div key={`${row.name}-${row.countryName || ""}`} className="flex items-center justify-between gap-3 rounded-md border border-border bg-background px-3 py-2">
              <span className="min-w-0 truncate font-semibold text-foreground">{row.countryName || row.name}</span>
              <span className="shrink-0 font-mono text-sm font-black text-primary">{compact(row.count)}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function TimelinePanel({
  data,
  maxTimeline,
  pt,
}: {
  data: ThreatMapData;
  maxTimeline: number;
  pt: boolean;
}) {
  return (
    <Card>
      <CardContent className="p-5">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <BarChart3 className="h-5 w-5 text-primary" />
            <h2 className="text-lg font-black tracking-tight">{pt ? "Evolucao recente" : "Recent evolution"}</h2>
          </div>
          <Badge variant="outline">{windowLabel(data.windowDays)}</Badge>
        </div>
        <div className="flex h-36 items-end gap-2">
          {(data.timeline || []).map((bucket, index) => (
            <div key={bucket.from} className="flex min-w-0 flex-1 flex-col items-center gap-2">
              <div className="flex h-28 w-full items-end rounded-md bg-muted/45 px-1">
                <div
                  className="w-full rounded-t-sm bg-primary transition-all"
                  style={{ height: `${Math.max(8, (bucket.count / maxTimeline) * 100)}%` }}
                  title={`${bucket.label}: ${bucket.count}`}
                />
              </div>
              <div className="w-full truncate text-center font-mono text-[10px] text-muted-foreground">
                {index % 2 === 0 || index === data.timeline.length - 1 ? bucket.label : ""}
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function InsightsPanel({ insights, pt }: { insights: ThreatInsight[]; pt: boolean }) {
  return (
    <Card>
      <CardContent className="p-5">
        <div className="mb-4 flex items-center gap-2">
          <Activity className="h-5 w-5 text-primary" />
          <h2 className="text-lg font-black tracking-tight">{pt ? "Sinais" : "Signals"}</h2>
        </div>
        <div className="space-y-3">
          {insights.slice(0, 5).map((insight) => {
            const rendered = insightText(insight, pt);
            const Icon = rendered.icon;
            return (
              <div
                key={`${insight.kind}-${insight.name || insight.count || insight.value || 0}`}
                className={`rounded-md border px-3 py-3 ${severityClass(insight.severity)}`}
              >
                <div className="flex items-start gap-3">
                  <Icon className="mt-0.5 h-4 w-4 shrink-0" />
                  <div className="min-w-0">
                    <div className="text-sm font-black text-foreground">{rendered.title}</div>
                    <div className="mt-1 text-xs font-medium leading-5 text-muted-foreground">{rendered.detail}</div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
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

  const loadWindow = useCallback(async (days: number) => {
    setLoading(true);
    try {
      setData(await fetchThreatMap(days));
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to load threat map");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadWindow(windowDays);
  }, [loadWindow, windowDays]);

  const maxTimeline = useMemo(
    () => Math.max(1, ...(data?.timeline || []).map((bucket) => bucket.count)),
    [data?.timeline],
  );

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
        label: pt ? "Pressao alta" : "High pressure",
        tone: "text-red-500",
        copy: pt
          ? "Volume ou dispersao acima do normal. Priorize vitimas novas, grupos lideres e setores com repeticao."
          : "Volume or spread is above normal. Prioritize new victims, leading crews, and repeated sectors.",
      }
      : totalVictims >= 8
        ? {
          label: pt ? "Pressao moderada" : "Moderate pressure",
          tone: "text-amber-500",
          copy: pt
            ? "Atividade relevante no recorte. Vale acompanhar claims com evidencia e paises recorrentes."
            : "Relevant activity in this window. Track claims with evidence and recurring countries.",
        }
        : {
          label: pt ? "Pressao baixa" : "Low pressure",
          tone: "text-emerald-500",
          copy: pt
            ? "Baixo volume no recorte atual. Mantenha observacao da proxima janela."
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
    { label: pt ? "Paises" : "Countries", value: data.countries.length, icon: Globe2 },
    { label: pt ? "Grupos" : "Crews", value: data.activeGroups, icon: Crosshair },
    { label: pt ? "Setores" : "Sectors", value: data.sectors?.length || 0, icon: Building2 },
  ] : [];

  const priority: PriorityItem[] = data ? [
    { label: pt ? "Pais mais atingido" : "Top country", value: data.topCountry?.countryName || data.topCountry?.name || "-" },
    { label: pt ? "Grupo mais ativo" : "Top crew", value: topGroup?.name || "-" },
    { label: pt ? "Setor mais atingido" : "Top sector", value: topSector?.name || "-" },
    { label: pt ? "LATAM" : "LATAM", value: `${compact(data.latam?.victims || 0)} ${pt ? "vitimas" : "victims"}` },
    { label: pt ? "Ultima vitima" : "Latest victim", value: latestVictim?.name || "-" },
  ] : [];

  const lists = data ? [
    {
      icon: Globe2,
      title: pt ? "Paises mais atingidos" : "Most affected countries",
      rows: data.countries.slice(0, 8).map((country) => ({ ...country, name: country.countryName || country.name })),
    },
    { icon: Users, title: pt ? "Grupos ativos" : "Active crews", rows: data.groups.slice(0, 8) },
    { icon: Building2, title: pt ? "Setores impactados" : "Impacted sectors", rows: (data.sectors || []).slice(0, 8) },
  ] : [];

  return (
    <PageLayout width="max-w-7xl" showBackButton={false}>
      <div className="mb-6 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <Badge variant="outline" className="mb-3 gap-1.5">
            <RadioTower className="h-3.5 w-3.5" />
            {data?.source || "ransomware.live"}
          </Badge>
          <h1 className="text-3xl font-black tracking-tight md:text-4xl">
            {pt ? "Mesa operacional de ransomware" : "Ransomware operation desk"}
          </h1>
          <p className="mt-2 max-w-2xl text-sm font-medium leading-6 text-muted-foreground">
            {pt
              ? "Veja quem foi reivindicado, por qual grupo, onde, em qual setor e com que evidencia."
              : "See who was claimed, by which crew, where, in what sector, and with what evidence."}
          </p>
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
          <Button variant="outline" onClick={() => loadWindow(windowDays)} disabled={loading}>
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
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
            {kpis.map(({ label, value, icon: Icon, tone }) => (
              <Card key={label}>
                <CardContent className="p-4">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-[11px] font-black uppercase tracking-wide text-muted-foreground">{label}</span>
                    <Icon className={`h-4 w-4 ${tone || "text-primary"}`} />
                  </div>
                  <div className={`mt-2 font-mono text-2xl font-black md:text-3xl ${tone || "text-foreground"}`}>
                    {value}
                  </div>
                </CardContent>
              </Card>
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
              <ContextMapPanel data={data} pt={pt} />
            </div>
          </div>

          <div className="grid gap-5 lg:grid-cols-3 lg:items-start">
            <div className="lg:col-span-2">
              <TimelinePanel data={data} maxTimeline={maxTimeline} pt={pt} />
            </div>
            <InsightsPanel insights={data.insights || []} pt={pt} />
          </div>

          <div className="grid gap-5 md:grid-cols-3">
            {lists.map(({ icon, title, rows }) => (
              <RankingList key={title} icon={icon} title={title} rows={rows} />
            ))}
          </div>
        </div>
      ) : (
        <Card>
          <CardContent className="p-8 text-center text-sm font-medium text-muted-foreground">
            {pt ? "Nao foi possivel carregar o mapa de ameacas." : "Threat map could not be loaded."}
          </CardContent>
        </Card>
      )}
    </PageLayout>
  );
};

export default ThreatMap;
