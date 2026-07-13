import { useCallback, useEffect, useMemo, useState } from "react";
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
  ShieldAlert,
  Target,
  TrendingDown,
  TrendingUp,
  Users,
  Zap,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { PageLayout } from "@/components/PageLayout";
import { ThreatWorldMap } from "@/components/ThreatWorldMap";
import { useLanguage } from "@/contexts/LanguageContext";
import { fetchThreatMap, type ThreatMapData } from "@/services/threatApi";
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

type ThreatInsight = ThreatMapData["insights"][number];

const insightText = (insight: ThreatInsight, pt: boolean) => {
  switch (insight.kind) {
    case "volume":
      return {
        title: pt ? "Ritmo da janela" : "Window pace",
        detail: pt
          ? `${compact(insight.value || 0)} reivindicações, ${insight.delta && insight.delta > 0 ? "+" : ""}${compact(insight.delta || 0)} vs. janela anterior.`
          : `${compact(insight.value || 0)} claims, ${insight.delta && insight.delta > 0 ? "+" : ""}${compact(insight.delta || 0)} vs. previous window.`,
        icon: insight.delta && insight.delta < 0 ? TrendingDown : TrendingUp,
      };
    case "top-group":
      return {
        title: pt ? "Grupo em destaque" : "Leading crew",
        detail: pt
          ? `${insight.name || "-"} concentra ${compact(insight.count || 0)} reivindicações no recorte.`
          : `${insight.name || "-"} accounts for ${compact(insight.count || 0)} claims in this window.`,
        icon: Crosshair,
      };
    case "sector":
      return {
        title: pt ? "Setor sob pressão" : "Sector under pressure",
        detail: pt
          ? `${insight.name || "-"} aparece em ${compact(insight.count || 0)} reivindicações recentes.`
          : `${insight.name || "-"} appears in ${compact(insight.count || 0)} recent claims.`,
        icon: Building2,
      };
    case "new-countries":
      return {
        title: pt ? "Novos países no recorte" : "New countries in window",
        detail: (insight.countries || []).map((c) => c.countryName || c.name).join(", "),
        icon: Globe2,
      };
    case "latam":
      return {
        title: pt ? "Sinal LATAM" : "LATAM signal",
        detail: pt
          ? `${compact(insight.count || 0)} reivindicações em ${compact(insight.countries?.length || 0)} países da região.`
          : `${compact(insight.count || 0)} claims across ${compact(insight.countries?.length || 0)} regional countries.`,
        icon: RadioTower,
      };
    case "evidence":
      return {
        title: pt ? "Evidência enriquecida" : "Enriched evidence",
        detail: pt
          ? `${compact(insight.count || 0)} vítimas com link, screenshot, press ou infostealer.`
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

const ThreatMap = () => {
  const { language } = useLanguage();
  const pt = language === "pt";
  const [data, setData] = useState<ThreatMapData | null>(null);
  const [windowDays, setWindowDays] = useState(3);
  const [loading, setLoading] = useState(true);

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
  const selectedWindow = data?.windows?.find((w) => w.days === data.windowDays) || null;
  const topGroup = data?.groups[0] || null;
  const latestVictim = data?.victims[0] || null;
  const totalVictims = data?.totalVictims ?? data?.victims.length ?? 0;
  const delta = data?.delta;
  const deltaTone = delta?.direction === "up"
    ? "text-red-500"
    : delta?.direction === "down"
      ? "text-emerald-500"
      : "text-muted-foreground";
  const signal = data
    ? totalVictims >= 20 || data.activeGroups >= 6
      ? {
        label: pt ? "Pressão alta" : "High pressure",
        tone: "text-red-500",
        copy: pt
          ? "Janela curta com volume ou dispersão acima do normal; vale priorizar grupos, setores e países líderes."
          : "Short window shows elevated volume or spread; prioritize the leading crews, sectors, and countries.",
      }
      : totalVictims >= 8
        ? {
          label: pt ? "Pressão moderada" : "Moderate pressure",
          tone: "text-amber-500",
          copy: pt
            ? "Atividade relevante, com sinais suficientes para acompanhamento operacional."
            : "Relevant activity with enough signal for operational monitoring.",
        }
        : {
          label: pt ? "Pressão baixa" : "Low pressure",
          tone: "text-emerald-500",
          copy: pt
            ? "Baixo volume no recorte atual; manter observação dos próximos buckets."
            : "Low volume in the current window; keep watching the next buckets.",
        }
    : null;

  const kpis = data ? [
    { label: pt ? "Reivindicações" : "Claims", value: totalVictims, icon: AlertTriangle },
    { label: pt ? "Delta" : "Delta", value: `${delta?.victims && delta.victims > 0 ? "+" : ""}${compact(delta?.victims || 0)}`, icon: delta?.direction === "down" ? TrendingDown : TrendingUp, tone: deltaTone },
    { label: pt ? "Países" : "Countries", value: data.countries.length, icon: Globe2 },
    { label: pt ? "Grupos ativos" : "Active crews", value: data.activeGroups, icon: Crosshair },
    { label: pt ? "Setores" : "Sectors", value: data.sectors?.length || 0, icon: Building2 },
  ] : [];

  const priority = data ? [
    { label: pt ? "País mais atingido" : "Top country", value: data.topCountry?.countryName || data.topCountry?.name || "-" },
    { label: pt ? "Grupo mais ativo" : "Top crew", value: topGroup?.name || "-" },
    { label: pt ? "Última vítima" : "Latest victim", value: latestVictim?.name || "-" },
    { label: pt ? "LATAM" : "LATAM", value: `${compact(data.latam?.victims || 0)} ${pt ? "vítimas" : "victims"}` },
  ] : [];

  const lists = data ? [
    { icon: Globe2, title: pt ? "Países mais atingidos" : "Most affected countries", rows: data.countries.slice(0, 8).map((c) => ({ name: c.countryName || c.name, count: c.count })) },
    { icon: Users, title: pt ? "Grupos ativos" : "Active crews", rows: data.groups.slice(0, 8).map((g) => ({ name: g.name, count: g.count })) },
    { icon: Building2, title: pt ? "Setores impactados" : "Impacted sectors", rows: (data.sectors || []).slice(0, 8) },
  ] : [];

  return (
    <PageLayout width="max-w-7xl" showBackButton={false}>
      <div className="mb-8 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <Badge variant="outline" className="mb-3 gap-1.5">
            <RadioTower className="h-3.5 w-3.5" />
            {data?.source || "ransomware.live"}
          </Badge>
          <h1 className="text-4xl font-black tracking-tight">{pt ? "Pulso de ameaças" : "Threat pulse"}</h1>
          <p className="mt-2 max-w-2xl text-sm font-medium leading-6 text-muted-foreground">
            {pt
              ? "Radar de ransomware com janela curta, comparação contra o período anterior e evolução por buckets recentes."
              : "Ransomware radar with a short window, previous-period comparison, and recent bucket evolution."}
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
      ) : data ? (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
            {kpis.map(({ label, value, icon: Icon, tone }) => (
              <Card key={label}>
                <CardContent className="p-5">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-black uppercase tracking-wide text-muted-foreground">{label}</span>
                    <Icon className={`h-4 w-4 ${tone || "text-primary"}`} />
                  </div>
                  <div className={`mt-3 font-mono text-3xl font-black ${tone || "text-foreground"}`}>{value}</div>
                </CardContent>
              </Card>
            ))}
          </div>

          <div className="grid gap-6 lg:grid-cols-3">
            <Card className="overflow-hidden lg:col-span-2">
              <CardContent className="flex h-full flex-col p-0">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border p-5">
                  <div className="flex items-center gap-2">
                    <MapPinned className="h-5 w-5 text-primary" />
                    <h2 className="text-xl font-black tracking-tight">{pt ? "Mapa operacional" : "Operational map"}</h2>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary">{windowLabel(data.windowDays)}</Badge>
                    <Badge variant="outline">{selectedWindow?.totalVictims ?? totalVictims} {pt ? "reivind." : "claims"}</Badge>
                  </div>
                </div>
                <div className="relative flex-1 bg-[radial-gradient(circle_at_50%_32%,rgba(251,113,133,0.12),transparent_55%),linear-gradient(180deg,#0a1120,#0d1a2f)] p-3">
                  <ThreatWorldMap countries={data.countries} />
                  <div className="pointer-events-none absolute left-4 top-4 flex flex-col gap-1.5 rounded-md border border-white/10 bg-black/40 px-3 py-2 text-[10px] font-semibold text-slate-300 backdrop-blur">
                    <span className="flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-rose-400" />{pt ? "País-vítima (tamanho = volume)" : "Victim country (size = volume)"}</span>
                    <span className="flex items-center gap-2"><span className="h-2 w-2 rounded-full border border-amber-400" />{pt ? "Origem (ilustrativa)" : "Origin (illustrative)"}</span>
                    <span className="flex items-center gap-2"><span className="h-[2px] w-3 rounded bg-rose-400" />{pt ? "Feixe de ataque" : "Attack beam"}</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="flex h-full flex-col gap-5 p-5">
                <div>
                  <div className="mb-3 flex items-center gap-2">
                    <ShieldAlert className="h-5 w-5 text-primary" />
                    <h2 className="text-lg font-black tracking-tight">{pt ? "Sinal CTI" : "CTI signal"}</h2>
                  </div>
                  <div className={`font-mono text-3xl font-black ${signal?.tone}`}>{signal?.label}</div>
                  <p className="mt-2 text-sm font-medium leading-6 text-muted-foreground">{signal?.copy}</p>
                </div>

                <div className="border-t border-border pt-4">
                  <div className="mb-3 flex items-center gap-2">
                    <Target className="h-4 w-4 text-primary" />
                    <h3 className="text-xs font-black uppercase tracking-wide text-muted-foreground">{pt ? "Prioridade agora" : "Priority now"}</h3>
                  </div>
                  <div className="grid gap-3 text-sm">
                    {priority.map((p) => (
                      <div key={p.label} className="flex items-center justify-between gap-3">
                        <span className="text-muted-foreground">{p.label}</span>
                        <span className="max-w-[160px] truncate text-right font-semibold text-foreground">{p.value}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="mt-auto grid gap-2 border-t border-border pt-4 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">{pt ? "Comparativo" : "Comparison"}</span>
                    <span className={`font-mono font-bold ${deltaTone}`}>
                      {delta?.victims && delta.victims > 0 ? "+" : ""}{compact(delta?.victims || 0)} ({compact(delta?.percent || 0)}%)
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">{pt ? "Janela anterior" : "Previous window"}</span>
                    <span className="font-mono font-bold text-foreground">{compact(delta?.previousVictims || 0)}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">{pt ? "Atualizado" : "Updated"}</span>
                    <span className="font-mono font-bold text-foreground">{fmtDate(data.generatedAt)}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="grid gap-6 lg:grid-cols-3 lg:items-start">
            <Card className="lg:col-span-2">
              <CardContent className="p-5">
                <div className="mb-4 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <BarChart3 className="h-5 w-5 text-primary" />
                    <h2 className="text-lg font-black tracking-tight">{pt ? "Evolução recente" : "Recent evolution"}</h2>
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

            <Card>
              <CardContent className="p-5">
                <div className="mb-4 flex items-center gap-2">
                  <Activity className="h-5 w-5 text-primary" />
                  <h2 className="text-lg font-black tracking-tight">{pt ? "Insights" : "Insights"}</h2>
                </div>
                <div className="space-y-3">
                  {(data.insights || []).slice(0, 5).map((insight) => {
                    const rendered = insightText(insight, pt);
                    const Icon = rendered.icon;
                    return (
                      <div key={`${insight.kind}-${insight.name || insight.count || insight.value || 0}`} className={`rounded-md border px-3 py-3 ${severityClass(insight.severity)}`}>
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
          </div>

          <div className="grid gap-6 md:grid-cols-3">
            {lists.map(({ icon: Icon, title, rows }) => (
              <Card key={title}>
                <CardContent className="p-5">
                  <div className="mb-4 flex items-center gap-2">
                    <Icon className="h-5 w-5 text-primary" />
                    <h2 className="text-lg font-black tracking-tight">{title}</h2>
                  </div>
                  <div className="space-y-2.5">
                    {rows.map((row) => (
                      <div key={row.name} className="flex items-center justify-between gap-3 rounded-md border border-border bg-background px-3 py-2">
                        <span className="min-w-0 truncate font-semibold text-foreground">{row.name}</span>
                        <span className="shrink-0 font-mono text-sm font-black text-primary">{row.count}</span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          <Card>
            <CardContent className="p-5">
              <div className="mb-4 flex items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <Clock3 className="h-5 w-5 text-primary" />
                  <h2 className="text-xl font-black tracking-tight">{pt ? "Reivindicações recentes" : "Recent claims"}</h2>
                </div>
                <Badge variant="outline">{compact(totalVictims)} {pt ? "vítimas" : "victims"}</Badge>
              </div>
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                {data.victims.slice(0, 12).map((victim) => (
                  <div key={`${victim.id || victim.name}-${victim.discovered}`} className="rounded-md border border-border bg-background p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="truncate font-semibold text-foreground">{victim.name}</div>
                        <div className="mt-1 truncate text-xs text-muted-foreground">{victim.countryName} · {victim.sector}</div>
                      </div>
                      <Badge variant="secondary" className="max-w-[120px] shrink-0 truncate">{victim.group}</Badge>
                    </div>
                    <div className="mt-3 flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs text-muted-foreground">{fmtDate(victim.discovered)}</span>
                      {victim.screenshot && <Badge variant="outline" className="text-[10px]">screenshot</Badge>}
                      {victim.press?.length ? <Badge variant="outline" className="text-[10px]">press</Badge> : null}
                      {victim.infostealer ? <Badge variant="outline" className="text-[10px]">infostealer</Badge> : null}
                    </div>
                    {victim.permalink && (
                      <a
                        href={victim.permalink}
                        target="_blank"
                        rel="noreferrer"
                        className="mt-3 inline-flex items-center gap-1 text-xs font-bold text-primary hover:underline"
                      >
                        {pt ? "Abrir fonte" : "Open source"}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      ) : null}
    </PageLayout>
  );
};

export default ThreatMap;
