import { useEffect, useState } from "react";
import { Activity, AlertTriangle, Crosshair, Database, Globe2, Loader2, RadioTower } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { PageLayout } from "@/components/PageLayout";
import { useLanguage } from "@/contexts/LanguageContext";
import { fetchLatamThreats, type LatamThreats as LatamThreatsData } from "@/services/threatApi";
import { toast } from "sonner";

const fmtDate = (iso?: string | null) => {
  if (!iso) return "-";
  const d = new Date(iso);
  return Number.isNaN(+d) ? "-" : d.toLocaleDateString(undefined, { day: "2-digit", month: "short" });
};

const Bar = ({ label, value, max }: { label: string; value: number; max: number }) => (
  <div className="space-y-1.5">
    <div className="flex items-center justify-between gap-3 text-sm">
      <span className="truncate font-semibold text-foreground">{label}</span>
      <span className="font-mono text-xs font-bold text-muted-foreground">{value}</span>
    </div>
    <div className="h-2 overflow-hidden rounded-full bg-secondary">
      <div className="h-full rounded-full bg-primary" style={{ width: `${Math.max(8, (value / Math.max(1, max)) * 100)}%` }} />
    </div>
  </div>
);

const LatamThreats = () => {
  const { language } = useLanguage();
  const pt = language === "pt";
  const [data, setData] = useState<LatamThreatsData | null>(null);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      setData(await fetchLatamThreats());
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to load Latam threats");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const maxGroup = Math.max(1, ...(data?.groups.map((g) => g.count) || [1]));
  const maxSector = Math.max(1, ...(data?.sectors.map((g) => g.count) || [1]));
  const stats = data ? [
    { label: pt ? "Vitimas Latam" : "Latam victims", value: data.victims.length, icon: AlertTriangle },
    { label: pt ? "Grupos" : "Groups", value: data.groups.length, icon: Crosshair },
    { label: pt ? "Setores" : "Sectors", value: data.sectors.length, icon: Database },
    { label: "ThreatFox IOCs", value: data.threatFox.count, icon: Activity },
  ] : [];

  return (
    <PageLayout width="max-w-6xl" showBackButton={false}>
      <div className="mb-8 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <Badge variant="outline" className="mb-3 gap-1.5">
            <RadioTower className="h-3.5 w-3.5" />
            {pt ? "Ransomware.live + ThreatFox" : "Ransomware.live + ThreatFox"}
          </Badge>
          <h1 className="text-4xl font-black tracking-tight">
            {pt ? "Latam Threats" : "Latam Threats"}
          </h1>
          <p className="mt-2 max-w-2xl text-sm font-medium leading-6 text-muted-foreground">
            {pt
              ? "Radar operacional para vitimas, grupos, setores e IOCs recentes que ajudam a entender pressao de ransomware e malware na America Latina."
              : "Operational radar for victims, groups, sectors and recent IOCs that help explain ransomware and malware pressure across Latin America."}
          </p>
        </div>
        <Button variant="outline" onClick={load} disabled={loading}>
          {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          {pt ? "Atualizar" : "Refresh"}
        </Button>
      </div>

      {loading && !data ? (
        <div className="flex items-center justify-center py-20 text-muted-foreground">
          <Loader2 className="mr-2 h-5 w-5 animate-spin" /> {pt ? "Carregando sinais..." : "Loading signals..."}
        </div>
      ) : data ? (
        <div className="space-y-6">
          <div className="grid gap-4 md:grid-cols-4">
            {stats.map(({ label, value, icon: Icon }) => (
              <Card key={label}>
                <CardContent className="p-5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-black uppercase tracking-wide text-muted-foreground">{label}</span>
                    <Icon className="h-4 w-4 text-primary" />
                  </div>
                  <div className="mt-4 font-mono text-3xl font-black text-foreground">{value}</div>
                </CardContent>
              </Card>
            ))}
          </div>

          <div className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
            <Card>
              <CardContent className="p-5">
                <div className="mb-4 flex items-center justify-between">
                  <h2 className="text-xl font-black tracking-tight">{pt ? "Ataques recentes na Latam" : "Recent Latam attacks"}</h2>
                  <Badge variant="secondary">{data.sources.join(" + ")}</Badge>
                </div>
                <div className="divide-y divide-border">
                  {data.victims.slice(0, 12).map((v) => (
                    <div key={`${v.name}-${v.discovered}`} className="grid gap-2 py-3 md:grid-cols-[96px_1fr_auto] md:items-center">
                      <span className="font-mono text-xs font-bold text-muted-foreground">{fmtDate(v.discovered)}</span>
                      <div className="min-w-0">
                        <div className="truncate font-semibold text-foreground">{v.name}</div>
                        <div className="truncate text-xs text-muted-foreground">{v.countryName} · {v.sector}</div>
                      </div>
                      <Badge variant="outline" className="w-fit">{v.group}</Badge>
                    </div>
                  ))}
                  {data.victims.length === 0 && (
                    <div className="py-10 text-center text-sm text-muted-foreground">
                      {pt ? "Nenhuma vitima Latam no recorte recente." : "No Latam victims in the recent window."}
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            <div className="grid gap-6">
              <Card>
                <CardContent className="p-5">
                  <h2 className="mb-4 text-lg font-black tracking-tight">{pt ? "Grupos mais ativos" : "Most active groups"}</h2>
                  <div className="space-y-4">
                    {data.groups.slice(0, 8).map((g) => <Bar key={g.name} label={g.name} value={g.count} max={maxGroup} />)}
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-5">
                  <h2 className="mb-4 text-lg font-black tracking-tight">{pt ? "Setores mais visados" : "Most targeted sectors"}</h2>
                  <div className="space-y-4">
                    {data.sectors.slice(0, 8).map((g) => <Bar key={g.name} label={g.name} value={g.count} max={maxSector} />)}
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>

          <Card>
            <CardContent className="p-5">
              <div className="mb-4 flex items-center gap-2">
                <Globe2 className="h-5 w-5 text-primary" />
                <h2 className="text-xl font-black tracking-tight">{pt ? "IOCs recentes do ThreatFox" : "Recent ThreatFox IOCs"}</h2>
              </div>
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                {data.threatFox.iocs.slice(0, 12).map((ioc) => (
                  <div key={`${ioc.value}-${ioc.firstSeen}`} className="rounded-lg border border-border bg-background p-4">
                    <div className="flex items-center justify-between gap-3">
                      <Badge variant="secondary">{ioc.type || "ioc"}</Badge>
                      <span className="font-mono text-xs text-muted-foreground">{ioc.confidence}%</span>
                    </div>
                    <div className="mt-3 truncate font-mono text-sm font-black text-foreground" title={ioc.value}>{ioc.value}</div>
                    <div className="mt-2 text-xs text-muted-foreground">{ioc.malware} · {fmtDate(ioc.firstSeen)}</div>
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

export default LatamThreats;
