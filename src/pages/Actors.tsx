import { useCallback, useEffect, useMemo, useState, type ElementType } from "react";
import {
  AlertCircle,
  BookOpen,
  Crosshair,
  Database,
  ExternalLink,
  Filter,
  Globe2,
  Layers3,
  Loader2,
  MapPin,
  Radar,
  Search,
  Shield,
  Target,
  UsersRound,
} from "lucide-react";
import { PageLayout } from "@/components/PageLayout";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useLanguage } from "@/contexts/LanguageContext";
import { cn } from "@/lib/utils";
import { fetchHunts, type PrivateHunt } from "@/services/threatApi";
import { actorHuntCoverage, sortActors } from "./actorsView";

interface ActorListItem {
  id: string;
  name: string;
  aliases: string[];
  country: string;
  motivation: string;
  source: string;
  technique_count: number;
  techniques: string[];
}

interface Ref {
  name: string;
  url: string;
}

interface Technique {
  id: string;
  name: string;
  url: string;
}

interface Software {
  id: string;
  name: string;
  url: string;
}

interface ActorDetail extends Omit<ActorListItem, "techniques"> {
  description: string;
  attack_id: string;
  attack_url: string;
  techniques: Technique[];
  software: Software[];
  refs: Array<string | Ref>;
}

type SourceFilter = "all" | "attack" | "misp";
type SortMode = "techniques" | "name" | "country" | "hunts";

const ALL_COUNTRIES = "__all__";
const MAX_RESULTS = 180;

const formatNumber = (value: number) =>
  new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 }).format(value);

const hasAttackMapping = (source?: string) => source?.includes("attack") || false;

const sourceLabel = (source?: string) => {
  if (!source) return "Unknown";
  if (source.includes("attack") && source.includes("misp")) return "MITRE + MISP";
  if (source.includes("attack")) return "MITRE";
  if (source.includes("misp")) return "MISP";
  return source;
};

const sourceClassName = (source?: string) => {
  if (source?.includes("attack") && source?.includes("misp")) {
    return "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300";
  }
  if (source?.includes("attack")) {
    return "border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-300";
  }
  if (source?.includes("misp")) {
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300";
  }
  return "border-border bg-muted text-muted-foreground";
};

const getRefData = (ref: string | Ref) => {
  const url = typeof ref === "string" ? ref : ref.url;
  const label = typeof ref === "string" ? ref : ref.name || ref.url;
  let host = label;
  try {
    host = new URL(url).hostname.replace(/^www\./, "");
  } catch {
    host = label;
  }
  return { label, url, host };
};

const buildRanking = (values: string[]) => {
  const counts = new Map<string, number>();
  values
    .map((value) => value.trim())
    .filter(Boolean)
    .forEach((value) => counts.set(value, (counts.get(value) || 0) + 1));

  return Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 5)
    .map(([label, count]) => ({ label, count }));
};

function StatTile({
  icon: Icon,
  label,
  value,
  detail,
  tone = "text-primary",
}: {
  icon: ElementType;
  label: string;
  value: string;
  detail: string;
  tone?: string;
}) {
  return (
    <div className="soc-panel rounded-lg p-4">
      <div className="flex items-center justify-between gap-3">
        <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">{label}</span>
        <Icon className={cn("h-4 w-4", tone)} />
      </div>
      <div className="mt-3 text-2xl font-semibold tracking-tight">{value}</div>
      <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{detail}</p>
    </div>
  );
}

function SourceBadge({ source }: { source?: string }) {
  return (
    <Badge variant="outline" className={cn("h-6 rounded-md px-2 text-[10px] font-semibold uppercase tracking-wide", sourceClassName(source))}>
      {sourceLabel(source)}
    </Badge>
  );
}

function ActorRow({
  actor,
  huntCount,
  selected,
  onOpen,
  pt,
}: {
  actor: ActorListItem;
  huntCount: number | null;
  selected: boolean;
  onOpen: (id: string) => void;
  pt: boolean;
}) {
  const aliases = actor.aliases.slice(0, 4);

  return (
    <TableRow data-state={selected ? "selected" : undefined}>
      <TableCell className="min-w-0 px-2 py-2">
        <div className="flex min-w-0 items-center gap-2">
          <Avatar className="size-8" aria-hidden="true">
            <AvatarFallback className="text-[10px] font-semibold">
              {actor.name.split(/\s+/).map((part) => part[0]).slice(0, 2).join("").toUpperCase()}
            </AvatarFallback>
          </Avatar>
          <div className="min-w-0">
            <div className="truncate text-sm font-semibold text-foreground">{actor.name}</div>
            <p className="truncate text-xs text-muted-foreground">
              {aliases.length > 0
                ? `${aliases.join(", ")}${actor.aliases.length > aliases.length ? ` +${actor.aliases.length - aliases.length}` : ""}`
                : pt ? "Sem aliases conhecidos" : "No known aliases"}
            </p>
          </div>
        </div>
      </TableCell>
      <TableCell className="hidden truncate px-2 py-2 text-xs text-muted-foreground sm:table-cell">
        {actor.country || "—"}
      </TableCell>
      <TableCell className="hidden truncate px-2 py-2 text-xs text-muted-foreground lg:table-cell">
        {actor.motivation || "—"}
      </TableCell>
      <TableCell className="px-2 py-2 text-right font-mono text-xs font-semibold">
        {actor.technique_count || 0}
      </TableCell>
      <TableCell className="hidden px-2 py-2 text-right font-mono text-xs font-semibold sm:table-cell">
        {huntCount === null ? "—" : huntCount}
      </TableCell>
      <TableCell className="hidden px-2 py-2 lg:table-cell">
        <div className="whitespace-nowrap">
          <SourceBadge source={actor.source} />
        </div>
      </TableCell>
      <TableCell className="px-2 py-2 text-right">
        <Button
          variant="outline"
          size="sm"
          className="h-8 px-2 text-xs"
          aria-label={pt ? `Abrir ${actor.name}` : `Open ${actor.name}`}
          onClick={() => onOpen(actor.id)}
        >
          {pt ? "Abrir" : "Open"}
        </Button>
      </TableCell>
    </TableRow>
  );
}

function EmptyDetailState({
  pt,
  topActors,
  topCountries,
  topMotivations,
  onOpen,
}: {
  pt: boolean;
  topActors: ActorListItem[];
  topCountries: Array<{ label: string; count: number }>;
  topMotivations: Array<{ label: string; count: number }>;
  onOpen: (id: string) => void;
}) {
  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-dashed border-border bg-muted/25 p-5">
        <div className="flex items-center gap-2">
          <Radar className="h-5 w-5 text-primary" />
          <h2 className="text-base font-semibold">{pt ? "Selecione um ator" : "Select an actor"}</h2>
        </div>
        <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
          {pt
            ? "Use o painel para priorizar grupos por TTPs, origem, motivação ou fonte. O perfil completo aparece aqui sem perder a lista."
            : "Use the catalog to prioritize groups by TTPs, origin, motivation, or source. Full profiles open here without losing the list."}
        </p>
      </div>

      {topActors.length > 0 && (
        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            {pt ? "Maior cobertura MITRE" : "Highest MITRE coverage"}
          </h3>
          <div className="space-y-2">
            {topActors.map((actor) => (
              <button
                key={actor.id}
                type="button"
                onClick={() => onOpen(actor.id)}
                className="flex w-full items-center justify-between gap-3 rounded-lg border border-border/80 bg-card px-3 py-2 text-left text-sm transition-colors hover:border-primary/30 hover:bg-muted/40"
              >
                <span className="min-w-0 truncate font-medium">{actor.name}</span>
                <Badge variant="secondary" className="h-5 shrink-0 rounded-md px-1.5 text-[10px]">
                  {actor.technique_count} TTP
                </Badge>
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-1">
        <RankingBlock title={pt ? "Países mais comuns" : "Top countries"} rows={topCountries} />
        <RankingBlock title={pt ? "Motivações" : "Motivations"} rows={topMotivations} />
      </div>
    </div>
  );
}

function RankingBlock({
  title,
  rows,
}: {
  title: string;
  rows: Array<{ label: string; count: number }>;
}) {
  if (!rows.length) return null;

  return (
    <div className="rounded-lg border border-border/80 bg-card p-3">
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">{title}</h3>
      <div className="space-y-2">
        {rows.map((row) => (
          <div key={row.label} className="flex items-center justify-between gap-3 text-xs">
            <span className="min-w-0 truncate text-muted-foreground">{row.label}</span>
            <span className="font-mono text-foreground">{formatNumber(row.count)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ActorDetailPanel({
  selected,
  selectedSummary,
  loading,
  error,
  pt,
  onRetry,
}: {
  selected: ActorDetail | null;
  selectedSummary: ActorListItem | undefined;
  loading: boolean;
  error: boolean;
  pt: boolean;
  onRetry: () => void;
}) {
  if (loading) {
    return (
      <div className="flex min-h-[340px] items-center justify-center rounded-lg border border-border bg-card">
        <div className="text-center">
          <Loader2 className="mx-auto h-5 w-5 animate-spin text-muted-foreground" />
          <p className="mt-3 text-sm text-muted-foreground">
            {selectedSummary?.name || (pt ? "Carregando ator..." : "Loading actor...")}
          </p>
        </div>
      </div>
    );
  }

  if (error || !selected) {
    return (
      <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-5">
        <div className="flex items-start gap-3">
          <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-red-500" />
          <div>
            <h2 className="text-base font-semibold">{pt ? "Falha ao carregar" : "Could not load actor"}</h2>
            <p className="mt-1 text-sm text-muted-foreground">
              {pt ? "A API não retornou o perfil completo deste ator." : "The API did not return this actor profile."}
            </p>
            <Button variant="outline" size="sm" className="mt-4" onClick={onRetry}>
              {pt ? "Tentar novamente" : "Retry"}
            </Button>
          </div>
        </div>
      </div>
    );
  }

  const visibleTechniques = selected.techniques.slice(0, 32);
  const hiddenTechniques = selected.techniques.length - visibleTechniques.length;
  const visibleSoftware = selected.software.slice(0, 18);
  const hiddenSoftware = selected.software.length - visibleSoftware.length;
  const visibleRefs = selected.refs.slice(0, 8);
  const hiddenRefs = selected.refs.length - visibleRefs.length;

  return (
    <div className="space-y-5">
      <div className="border-b border-border pb-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="truncate text-2xl font-semibold tracking-tight">{selected.name}</h2>
              <SourceBadge source={selected.source} />
            </div>
            {selected.aliases.length > 0 && (
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                {pt ? "Também conhecido como " : "Also known as "}
                {selected.aliases.slice(0, 8).join(", ")}
                {selected.aliases.length > 8 ? ` +${selected.aliases.length - 8}` : ""}
              </p>
            )}
          </div>
          {selected.attack_url && (
            <a href={selected.attack_url} target="_blank" rel="noopener noreferrer">
              <Button variant="outline" size="sm" className="gap-2">
                {selected.attack_id || "ATT&CK"}
                <ExternalLink className="h-3.5 w-3.5" />
              </Button>
            </a>
          )}
        </div>

        <div className="mt-4 grid gap-2 sm:grid-cols-3">
          <Fact icon={MapPin} label={pt ? "Origem" : "Origin"} value={selected.country || "-"} />
          <Fact icon={Target} label={pt ? "Motivação" : "Motivation"} value={selected.motivation || "-"} />
          <Fact icon={Crosshair} label="TTPs" value={String(selected.techniques.length)} />
        </div>
      </div>

      {selected.description && (
        <section>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            {pt ? "Contexto" : "Context"}
          </h3>
          <p className="max-h-44 overflow-auto pr-1 text-sm leading-relaxed text-foreground/90">
            {selected.description}
          </p>
        </section>
      )}

      {selected.techniques.length > 0 && (
        <section>
          <div className="mb-2 flex items-center justify-between gap-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              MITRE ATT&CK
            </h3>
            {hiddenTechniques > 0 && <span className="text-xs text-muted-foreground">+{hiddenTechniques}</span>}
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            {visibleTechniques.map((technique) => (
              <a
                key={`${technique.id}-${technique.name}`}
                href={technique.url}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded-lg border border-border/80 bg-muted/25 px-3 py-2 text-xs transition-colors hover:border-primary/30 hover:bg-muted/50"
              >
                <span className="font-mono font-semibold text-primary">{technique.id}</span>
                <span className="ml-2 text-muted-foreground">{technique.name}</span>
              </a>
            ))}
          </div>
        </section>
      )}

      {selected.software.length > 0 && (
        <section>
          <div className="mb-2 flex items-center justify-between gap-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              {pt ? "Malware e ferramentas" : "Malware and tools"}
            </h3>
            {hiddenSoftware > 0 && <span className="text-xs text-muted-foreground">+{hiddenSoftware}</span>}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {visibleSoftware.map((software) => (
              <a key={`${software.id}-${software.name}`} href={software.url} target="_blank" rel="noopener noreferrer">
                <Badge variant="secondary" className="rounded-md bg-muted/60 font-normal">
                  {software.name}
                </Badge>
              </a>
            ))}
          </div>
        </section>
      )}

      {selected.refs.length > 0 && (
        <section>
          <div className="mb-2 flex items-center justify-between gap-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              {pt ? "Referências" : "References"}
            </h3>
            {hiddenRefs > 0 && <span className="text-xs text-muted-foreground">+{hiddenRefs}</span>}
          </div>
          <div className="space-y-2">
            {visibleRefs.map((ref, index) => {
              const data = getRefData(ref);
              return (
                <a
                  key={`${data.url}-${index}`}
                  href={data.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  title={data.label}
                  className="flex items-center gap-2 rounded-lg border border-border/80 bg-card px-3 py-2 text-xs text-muted-foreground transition-colors hover:border-primary/30 hover:text-foreground"
                >
                  <BookOpen className="h-3.5 w-3.5 shrink-0" />
                  <span className="min-w-0 truncate">{data.host}</span>
                  <ExternalLink className="ml-auto h-3 w-3 shrink-0" />
                </a>
              );
            })}
          </div>
        </section>
      )}
    </div>
  );
}

function Fact({
  icon: Icon,
  label,
  value,
}: {
  icon: ElementType;
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-lg border border-border/80 bg-muted/25 p-3">
      <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
        <Icon className="h-3 w-3" />
        {label}
      </div>
      <div className="mt-1 truncate text-sm font-medium">{value}</div>
    </div>
  );
}

const Actors = () => {
  const { language } = useLanguage();
  const pt = language === "pt";

  const [list, setList] = useState<ActorListItem[]>([]);
  const [countries, setCountries] = useState<string[]>([]);
  const [privateHunts, setPrivateHunts] = useState<PrivateHunt[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const [query, setQuery] = useState("");
  const [country, setCountry] = useState<string>(ALL_COUNTRIES);
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>("all");
  const [sortMode, setSortMode] = useState<SortMode>("techniques");

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<ActorDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState(false);

  useEffect(() => {
    let alive = true;

    (async () => {
      try {
        const [actorsResult, huntsResult] = await Promise.allSettled([
          fetch("/api/actors").then(async (response) => {
            if (!response.ok) throw new Error(String(response.status));
            return response.json();
          }),
          fetchHunts(),
        ]);
        if (!alive) return;
        setPrivateHunts(huntsResult.status === "fulfilled" ? huntsResult.value : null);
        if (actorsResult.status === "rejected") {
          setError(true);
          return;
        }
        setList(actorsResult.value.actors || []);
        setCountries(actorsResult.value.countries || []);
        setError(false);
      } finally {
        if (alive) setLoading(false);
      }
    })();

    return () => {
      alive = false;
    };
  }, []);

  const coverage = useMemo(
    () => privateHunts === null ? {} : actorHuntCoverage(list, privateHunts),
    [list, privateHunts],
  );

  const openActor = useCallback(async (id: string) => {
    setSelectedId(id);
    setDetailLoading(true);
    setDetailError(false);
    setSelected(null);

    try {
      const response = await fetch(`/api/actors/${encodeURIComponent(id)}`);
      if (!response.ok) throw new Error(String(response.status));
      setSelected(await response.json());
    } catch {
      setDetailError(true);
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();

    const matches = list.filter((actor) => {
      if (country !== ALL_COUNTRIES && actor.country !== country) return false;
      if (sourceFilter === "attack" && !hasAttackMapping(actor.source)) return false;
      if (sourceFilter === "misp" && hasAttackMapping(actor.source)) return false;

      if (!needle) return true;
      return [
        actor.name,
        ...actor.aliases,
        actor.country,
        actor.motivation,
        sourceLabel(actor.source),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(needle);
    });

    return sortActors(matches, sortMode, coverage);
  }, [country, coverage, list, query, sortMode, sourceFilter]);

  const shown = filtered.slice(0, MAX_RESULTS);
  const selectedSummary = useMemo(() => list.find((actor) => actor.id === selectedId), [list, selectedId]);

  const catalog = useMemo(() => {
    const actorsWithTtp = list.filter((actor) => actor.technique_count > 0).length;
    const mappedActors = list.filter((actor) => hasAttackMapping(actor.source)).length;
    const countryCount = new Set(list.map((actor) => actor.country).filter(Boolean)).size;
    const topCountries = buildRanking(list.map((actor) => actor.country));
    const topMotivations = buildRanking(list.map((actor) => actor.motivation));
    const topActors = [...list]
      .filter((actor) => actor.technique_count > 0)
      .sort((a, b) => b.technique_count - a.technique_count || a.name.localeCompare(b.name))
      .slice(0, 5);

    return {
      actorsWithTtp,
      mappedActors,
      countryCount,
      topCountries,
      topMotivations,
      topActors,
      leadingMotivation: topMotivations[0],
    };
  }, [list]);

  const retrySelected = () => {
    if (selectedId) void openActor(selectedId);
  };

  return (
    <PageLayout width="max-w-7xl" className="py-8">
      <header className="mb-6">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-3xl">
            <div className="mb-3 flex flex-wrap gap-2">
              <span className="soc-chip">
                <Shield className="h-3.5 w-3.5 text-primary" />
                {pt ? "Catálogo CTI" : "CTI catalog"}
              </span>
              <span className="soc-chip">
                <Database className="h-3.5 w-3.5 text-emerald-500" />
                MITRE + MISP
              </span>
            </div>
            <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">
              {pt ? "Grupos de Ataque" : "Threat actors"}
            </h1>
            <p className="mt-3 max-w-2xl text-sm leading-relaxed text-muted-foreground sm:text-base">
              {pt
                ? "Diretório operacional para comparar grupos por aliases, origem, motivação, TTPs mapeadas e referências de pesquisa."
                : "Operational directory for comparing groups by aliases, origin, motivation, mapped TTPs, and research references."}
            </p>
          </div>

          <div className="soc-panel rounded-lg px-4 py-3">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              <Layers3 className="h-4 w-4 text-primary" />
              {pt ? "Fonte de dados" : "Data source"}
            </div>
            <div className="mt-2 flex flex-wrap gap-2">
              <SourceBadge source="attack+misp" />
              <SourceBadge source="misp" />
            </div>
          </div>
        </div>
      </header>

      <section className="mb-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile
          icon={UsersRound}
          label={pt ? "Atores indexados" : "Indexed actors"}
          value={loading ? "-" : formatNumber(list.length)}
          detail={pt ? "Perfis normalizados para consulta rápida." : "Normalized profiles for fast lookup."}
        />
        <StatTile
          icon={Crosshair}
          label={pt ? "Com TTPs" : "With TTPs"}
          value={loading ? "-" : formatNumber(catalog.actorsWithTtp)}
          detail={pt ? `${formatNumber(catalog.mappedActors)} com mapeamento ATT&CK.` : `${formatNumber(catalog.mappedActors)} mapped to ATT&CK.`}
          tone="text-sky-500"
        />
        <StatTile
          icon={Globe2}
          label={pt ? "Origens" : "Origins"}
          value={loading ? "-" : formatNumber(catalog.countryCount)}
          detail={pt ? "Países ou regiões atribuídas no catálogo." : "Attributed countries or regions in the catalog."}
          tone="text-emerald-500"
        />
        <StatTile
          icon={Target}
          label={pt ? "Motivação líder" : "Leading motivation"}
          value={loading ? "-" : catalog.leadingMotivation?.label || "-"}
          detail={
            catalog.leadingMotivation
              ? `${formatNumber(catalog.leadingMotivation.count)} ${pt ? "perfis" : "profiles"}`
              : pt
                ? "Sem classificação suficiente."
                : "Not enough classification."
          }
          tone="text-amber-500"
        />
      </section>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_440px]">
        <section className="soc-panel rounded-lg">
          <div className="border-b border-border p-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <Filter className="h-5 w-5 text-primary" />
                  <h2 className="text-lg font-semibold">{pt ? "Catálogo filtrado" : "Filtered catalog"}</h2>
                </div>
                <p className="mt-1 text-sm text-muted-foreground">
                  {pt
                    ? `${formatNumber(filtered.length)} resultado(s) encontrados`
                    : `${formatNumber(filtered.length)} result(s) found`}
                  {filtered.length > shown.length ? `, ${pt ? "mostrando" : "showing"} ${shown.length}` : ""}
                </p>
              </div>

              <div className="grid gap-2 sm:grid-cols-2 lg:w-[520px]">
                <Select value={sourceFilter} onValueChange={(value) => setSourceFilter(value as SourceFilter)}>
                  <SelectTrigger className="h-9 text-xs font-semibold">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">{pt ? "Todas as fontes" : "All sources"}</SelectItem>
                    <SelectItem value="attack">{pt ? "MITRE mapeado" : "MITRE mapped"}</SelectItem>
                    <SelectItem value="misp">{pt ? "Só MISP" : "MISP only"}</SelectItem>
                  </SelectContent>
                </Select>

                <Select value={sortMode} onValueChange={(value) => setSortMode(value as SortMode)}>
                  <SelectTrigger className="h-9 text-xs font-semibold">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="techniques">{pt ? "Mais TTPs primeiro" : "Most TTPs first"}</SelectItem>
                    <SelectItem value="hunts" disabled={privateHunts === null}>
                      {pt ? "Mais hunts primeiro" : "Most hunts first"}
                    </SelectItem>
                    <SelectItem value="name">{pt ? "Nome A-Z" : "Name A-Z"}</SelectItem>
                    <SelectItem value="country">{pt ? "Origem A-Z" : "Origin A-Z"}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="mt-4 grid gap-2 lg:grid-cols-[minmax(240px,1fr)_220px]">
              <div className="relative">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder={pt ? "Buscar ator, alias ou país" : "Search actor, alias, or country"}
                  className="h-10 pl-9"
                />
              </div>
              <Select value={country} onValueChange={setCountry}>
                <SelectTrigger className="h-10">
                  <SelectValue placeholder={pt ? "País" : "Country"} />
                </SelectTrigger>
                <SelectContent className="max-h-72">
                  <SelectItem value={ALL_COUNTRIES}>{pt ? "Todos os países" : "All countries"}</SelectItem>
                  {countries.map((item) => (
                    <SelectItem key={item} value={item}>
                      {item}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="p-3">
            {loading ? (
              <div className="flex min-h-[360px] items-center justify-center">
                <div className="text-center">
                  <Loader2 className="mx-auto h-6 w-6 animate-spin text-muted-foreground" />
                  <p className="mt-3 text-sm text-muted-foreground">{pt ? "Carregando catálogo..." : "Loading catalog..."}</p>
                </div>
              </div>
            ) : error ? (
              <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-5 text-sm text-muted-foreground">
                {pt ? "Não foi possível carregar os atores." : "Could not load actors."}
              </div>
            ) : shown.length === 0 ? (
              <div className="rounded-lg border border-dashed border-border p-8 text-center text-sm text-muted-foreground">
                {pt ? "Nenhum ator encontrado com estes filtros." : "No actor matches these filters."}
              </div>
            ) : (
              <div className="overflow-hidden rounded-lg border border-border">
                <Table className="table-fixed">
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="h-9 w-[34%] px-2 text-[10px] font-semibold uppercase tracking-wide">
                        {pt ? "Ator" : "Actor"}
                      </TableHead>
                      <TableHead className="hidden h-9 w-[17%] px-2 text-[10px] font-semibold uppercase tracking-wide sm:table-cell">
                        {pt ? "País" : "Country"}
                      </TableHead>
                      <TableHead className="hidden h-9 w-[17%] px-2 text-[10px] font-semibold uppercase tracking-wide lg:table-cell">
                        {pt ? "Motivação" : "Motivation"}
                      </TableHead>
                      <TableHead className="h-9 w-[9%] px-0 text-right">
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="h-8 px-2 text-[10px] font-semibold uppercase tracking-wide"
                          aria-pressed={sortMode === "techniques"}
                          onClick={() => setSortMode("techniques")}
                        >
                          TTPs
                        </Button>
                      </TableHead>
                      <TableHead className="hidden h-9 w-[9%] px-0 text-right sm:table-cell">
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="h-8 px-2 text-[10px] font-semibold uppercase tracking-wide"
                          aria-pressed={sortMode === "hunts"}
                          disabled={privateHunts === null}
                          onClick={() => setSortMode("hunts")}
                        >
                          Hunts
                        </Button>
                      </TableHead>
                      <TableHead className="hidden h-9 w-[14%] px-2 text-[10px] font-semibold uppercase tracking-wide lg:table-cell">
                        {pt ? "Fonte" : "Source"}
                      </TableHead>
                      <TableHead className="h-9 w-[11%] px-2 text-right text-[10px] font-semibold uppercase tracking-wide">
                        {pt ? "Ação" : "Action"}
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {shown.map((actor) => (
                      <ActorRow
                        key={actor.id}
                        actor={actor}
                        huntCount={privateHunts === null ? null : coverage[actor.id] || 0}
                        selected={actor.id === selectedId}
                        onOpen={openActor}
                        pt={pt}
                      />
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </div>
        </section>

        <aside className="soc-panel rounded-lg p-5 xl:sticky xl:top-24 xl:max-h-[calc(100vh-7rem)] xl:overflow-auto">
          {!selectedId ? (
            <EmptyDetailState
              pt={pt}
              topActors={catalog.topActors}
              topCountries={catalog.topCountries}
              topMotivations={catalog.topMotivations}
              onOpen={openActor}
            />
          ) : (
            <ActorDetailPanel
              selected={selected}
              selectedSummary={selectedSummary}
              loading={detailLoading}
              error={detailError}
              pt={pt}
              onRetry={retrySelected}
            />
          )}
        </aside>
      </div>
    </PageLayout>
  );
};

export default Actors;
