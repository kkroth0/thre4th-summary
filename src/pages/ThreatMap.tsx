import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, Building2, Clock, Crosshair, Globe2, Loader2, MapPinned, RadioTower, ShieldAlert, Target, Users } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { PageLayout } from "@/components/PageLayout";
import { useLanguage } from "@/contexts/LanguageContext";
import { fetchThreatMap, type ThreatMapData } from "@/services/threatApi";
import { toast } from "sonner";

const COUNTRY_POINTS: Record<string, { x: number; y: number }> = {
  US: { x: 20, y: 38 }, CA: { x: 18, y: 25 }, MX: { x: 18, y: 49 },
  BR: { x: 34, y: 70 }, AR: { x: 31, y: 84 }, CL: { x: 28, y: 82 }, CO: { x: 29, y: 62 },
  PE: { x: 27, y: 69 }, UY: { x: 33, y: 82 }, EC: { x: 26, y: 63 },
  GB: { x: 46, y: 32 }, FR: { x: 48, y: 38 }, ES: { x: 46, y: 43 }, IT: { x: 51, y: 43 },
  DE: { x: 50, y: 35 }, PL: { x: 54, y: 34 }, NL: { x: 49, y: 34 }, BE: { x: 49, y: 36 },
  UA: { x: 58, y: 38 }, RU: { x: 66, y: 28 }, TR: { x: 58, y: 47 },
  ZA: { x: 54, y: 82 }, EG: { x: 55, y: 55 }, NG: { x: 49, y: 62 }, GH: { x: 47, y: 61 },
  IN: { x: 70, y: 55 }, CN: { x: 76, y: 45 }, JP: { x: 86, y: 45 }, KR: { x: 83, y: 45 },
  AU: { x: 82, y: 80 }, SG: { x: 73, y: 67 }, ID: { x: 76, y: 72 },
};

const fmtDate = (iso?: string | null) => {
  if (!iso) return "-";
  const d = new Date(iso);
  return Number.isNaN(+d) ? "-" : d.toLocaleDateString(undefined, { day: "2-digit", month: "short" });
};

const countBy = (items: string[]) => {
  const map = new Map<string, number>();
  items.forEach((item) => {
    const key = item || "Unknown";
    map.set(key, (map.get(key) || 0) + 1);
  });
  return Array.from(map.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);
};

const ThreatMap = () => {
  const { language } = useLanguage();
  const pt = language === "pt";
  const [data, setData] = useState<ThreatMapData | null>(null);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      setData(await fetchThreatMap(90));
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to load threat map");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const plotted = useMemo(() => {
    const max = Math.max(1, ...(data?.countries.map((c) => c.count) || [1]));
    return (data?.countries || [])
      .map((c) => ({ ...c, point: COUNTRY_POINTS[c.name], radius: 6 + (c.count / max) * 24 }))
      .filter((c) => c.point);
  }, [data]);
  const sectors = useMemo(() => countBy((data?.victims || []).map((v) => v.sector || "Unknown")), [data]);
  const topGroup = data?.groups[0] || null;
  const latestVictim = data?.victims[0] || null;
  const signal = data
    ? data.victims.length >= 60 || data.activeGroups >= 8
      ? { label: pt ? "Pressão alta" : "High pressure", tone: "text-red-500", copy: pt ? "Volume e dispersão indicam atividade relevante para acompanhamento diário." : "Volume and spread indicate activity worth daily tracking." }
      : data.victims.length >= 25
        ? { label: pt ? "Pressão moderada" : "Moderate pressure", tone: "text-amber-500", copy: pt ? "Atividade constante, com prioridade para países e grupos no topo." : "Steady activity, prioritize top countries and crews." }
        : { label: pt ? "Pressão baixa" : "Low pressure", tone: "text-emerald-500", copy: pt ? "Baixo volume no recorte, manter monitoramento." : "Low volume in this window, keep monitoring." }
    : null;
  const stats = data ? [
    { label: pt ? "Vitimas recentes" : "Recent victims", value: data.victims.length, icon: AlertTriangle },
    { label: pt ? "Paises" : "Countries", value: data.countries.length, icon: Globe2 },
    { label: pt ? "Grupos ativos" : "Active groups", value: data.activeGroups, icon: Crosshair },
    { label: pt ? "Mais atingido" : "Top country", value: data.topCountry?.name || "-", icon: MapPinned },
  ] : [];

  return (
    <PageLayout width="max-w-7xl" showBackButton={false}>
      <div className="mb-8 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <Badge variant="outline" className="mb-3 gap-1.5">
            <RadioTower className="h-3.5 w-3.5" />
            ransomware.live
          </Badge>
          <h1 className="text-4xl font-black tracking-tight">{pt ? "Mapa de ameaças" : "Threat map"}</h1>
          <p className="mt-2 max-w-2xl text-sm font-medium leading-6 text-muted-foreground">
            {pt
              ? "Vitimas de ransomware reivindicadas publicamente, agregadas por pais nos ultimos 90 dias."
              : "Publicly claimed ransomware victims, aggregated by country over the last 90 days."}
          </p>
        </div>
        <Button variant="outline" onClick={load} disabled={loading}>
          {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          {pt ? "Atualizar" : "Refresh"}
        </Button>
      </div>

      {loading && !data ? (
        <div className="flex items-center justify-center py-20 text-muted-foreground">
          <Loader2 className="mr-2 h-5 w-5 animate-spin" /> {pt ? "Carregando mapa..." : "Loading map..."}
        </div>
      ) : data ? (
        <div className="space-y-6">
          <div className="grid gap-4 lg:grid-cols-3">
            <Card>
              <CardContent className="p-5">
                <div className="mb-4 flex items-center gap-2">
                  <ShieldAlert className="h-5 w-5 text-primary" />
                  <h2 className="text-lg font-black tracking-tight">{pt ? "Sinal CTI" : "CTI signal"}</h2>
                </div>
                <div className={`font-mono text-3xl font-black ${signal?.tone}`}>{signal?.label}</div>
                <p className="mt-3 text-sm font-medium leading-6 text-muted-foreground">{signal?.copy}</p>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-5">
                <div className="mb-4 flex items-center gap-2">
                  <Target className="h-5 w-5 text-primary" />
                  <h2 className="text-lg font-black tracking-tight">{pt ? "Prioridade de monitoramento" : "Monitoring priority"}</h2>
                </div>
                <div className="grid gap-3 text-sm">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-muted-foreground">{pt ? "País mais atingido" : "Top country"}</span>
                    <span className="font-mono font-black text-foreground">{data.topCountry?.countryName || data.topCountry?.name || "-"}</span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-muted-foreground">{pt ? "Grupo mais ativo" : "Top crew"}</span>
                    <span className="font-mono font-black text-foreground">{topGroup?.name || "-"}</span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-muted-foreground">{pt ? "Última vítima" : "Latest victim"}</span>
                    <span className="max-w-[160px] truncate font-semibold text-foreground">{latestVictim?.name || "-"}</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-5">
                <div className="mb-4 flex items-center gap-2">
                  <Clock className="h-5 w-5 text-primary" />
                  <h2 className="text-lg font-black tracking-tight">{pt ? "Fonte e recorte" : "Source and window"}</h2>
                </div>
                <div className="grid gap-3 text-sm">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-muted-foreground">Source</span>
                    <span className="font-mono font-black text-foreground">{data.source}</span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-muted-foreground">{pt ? "Janela" : "Window"}</span>
                    <span className="font-mono font-black text-foreground">{data.windowDays} {pt ? "dias" : "days"}</span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-muted-foreground">{pt ? "Atualizado" : "Updated"}</span>
                    <span className="font-mono font-black text-foreground">{fmtDate(data.generatedAt)}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="grid gap-6 xl:grid-cols-[1.55fr_0.85fr]">
            <Card className="overflow-hidden">
              <CardContent className="p-0">
                <div className="border-b border-border p-5">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-center gap-2">
                      <MapPinned className="h-5 w-5 text-primary" />
                      <h2 className="text-xl font-black tracking-tight">{pt ? "Ransomware no mundo" : "Global ransomware"}</h2>
                    </div>
                    <Badge variant="secondary">{data.windowDays} {pt ? "dias" : "days"}</Badge>
                  </div>
                </div>
                <div className="relative min-h-[520px] bg-[radial-gradient(circle_at_50%_45%,hsl(var(--primary)/0.10),transparent_38%),linear-gradient(180deg,hsl(var(--secondary)/0.45),transparent)] p-5">
                  <svg viewBox="0 0 100 58" className="absolute inset-x-5 top-8 h-[420px] w-[calc(100%-2.5rem)] text-border">
                    <path d="M8 26c8-8 18-8 29-5 8 2 13 0 20-3 11-5 23-4 34 3" fill="none" stroke="currentColor" strokeWidth="0.4" opacity="0.7" />
                    <path d="M10 36c13 5 23 2 34 4 17 3 27 8 45 2" fill="none" stroke="currentColor" strokeWidth="0.4" opacity="0.7" />
                    <path d="M21 18l7 5-5 6-10-1-3-5 5-5zM43 22l8-5 8 3-2 9-9 3-7-3zM59 18l19-3 10 7-6 11-17 2-8-7zM26 58l7-15 9 5-3 10zM49 43l7 2 2 11-8 2-5-9zM75 43l12 5-3 8-12-3z" fill="hsl(var(--muted))" opacity="0.38" />
                    {plotted.map((c) => (
                      <g key={c.name}>
                        <circle cx={c.point.x} cy={c.point.y * 0.58} r={c.radius / 3} fill="hsl(var(--primary))" opacity="0.18" />
                        <circle cx={c.point.x} cy={c.point.y * 0.58} r={Math.max(1.8, c.radius / 8)} fill="hsl(var(--primary))" />
                      </g>
                    ))}
                  </svg>
                  <div className="absolute bottom-5 left-5 right-5 grid gap-3 md:grid-cols-4">
                    {stats.map(({ label, value, icon: Icon }) => (
                      <div key={label} className="rounded-lg border border-border bg-background/90 p-4 backdrop-blur">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] font-black uppercase tracking-wide text-muted-foreground">{label}</span>
                          <Icon className="h-4 w-4 text-primary" />
                        </div>
                        <div className="mt-3 truncate font-mono text-2xl font-black text-foreground">{value}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>

            <div className="grid gap-6">
              <Card>
                <CardContent className="p-5">
                  <div className="mb-4 flex items-center gap-2">
                    <Globe2 className="h-5 w-5 text-primary" />
                    <h2 className="text-lg font-black tracking-tight">{pt ? "Paises mais atingidos" : "Most affected countries"}</h2>
                  </div>
                  <div className="space-y-3">
                    {data.countries.slice(0, 8).map((c) => (
                      <div key={c.name} className="flex items-center justify-between gap-3 rounded-md border border-border bg-background px-3 py-2">
                        <span className="font-semibold text-foreground">{c.countryName || c.name}</span>
                        <span className="font-mono text-sm font-black text-primary">{c.count}</span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-5">
                  <div className="mb-4 flex items-center gap-2">
                    <Users className="h-5 w-5 text-primary" />
                    <h2 className="text-lg font-black tracking-tight">{pt ? "Grupos ativos" : "Active groups"}</h2>
                  </div>
                  <div className="space-y-3">
                    {data.groups.slice(0, 8).map((g) => (
                      <div key={g.name} className="flex items-center justify-between gap-3 rounded-md border border-border bg-background px-3 py-2">
                        <span className="font-semibold text-foreground">{g.name}</span>
                        <span className="font-mono text-sm font-black text-primary">{g.count}</span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-5">
                  <div className="mb-4 flex items-center gap-2">
                    <Building2 className="h-5 w-5 text-primary" />
                    <h2 className="text-lg font-black tracking-tight">{pt ? "Setores impactados" : "Impacted sectors"}</h2>
                  </div>
                  <div className="space-y-3">
                    {sectors.slice(0, 6).map((s) => (
                      <div key={s.name} className="flex items-center justify-between gap-3 rounded-md border border-border bg-background px-3 py-2">
                        <span className="min-w-0 truncate font-semibold text-foreground">{s.name}</span>
                        <span className="font-mono text-sm font-black text-primary">{s.count}</span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>

          <Card>
            <CardContent className="p-5">
              <div className="mb-4 flex items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-primary" />
                  <h2 className="text-xl font-black tracking-tight">{pt ? "Últimas reivindicações" : "Latest claims"}</h2>
                </div>
                <Badge variant="outline">{data.victims.length} {pt ? "vítimas" : "victims"}</Badge>
              </div>
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                {data.victims.slice(0, 12).map((v) => (
                  <div key={`${v.name}-${v.discovered}`} className="rounded-lg border border-border bg-background p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="truncate font-semibold text-foreground">{v.name}</div>
                        <div className="mt-1 text-xs text-muted-foreground">{v.countryName} · {v.sector}</div>
                      </div>
                      <Badge variant="secondary" className="shrink-0">{v.group}</Badge>
                    </div>
                    <div className="mt-3 font-mono text-xs text-muted-foreground">{fmtDate(v.discovered)}</div>
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
