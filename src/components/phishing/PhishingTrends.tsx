// Tendências de phishing: volume diário + quebra por técnica, a partir do
// arquivo permanente (/api/news/archive), categoria Phishing. Componente
// próprio pelo mesmo motivo de BrandHunt/PhishTickets — o PhishingAnalyzer já
// é grande, e isto não pertence ao fluxo de análise de um e-mail.
import { useEffect, useMemo, useState } from "react";
import { Download, Loader2, TrendingUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { EmptyState } from "@/components/EmptyState";
import { useLanguage } from "@/contexts/LanguageContext";
import { toast } from "sonner";
import { fetchNewsArchive, type NewsArchiveRow } from "@/services/threatApi";
import { exportPhishingTrendsExcel } from "@/utils/phishingTrendsExport";

const PERIODS = ["30d", "90d", "all"] as const;
type Period = (typeof PERIODS)[number];
const PERIOD_DAYS: Record<Exclude<Period, "all">, number> = { "30d": 30, "90d": 90 };

const PERIOD_LABEL: Record<Period, { pt: string; en: string }> = {
  "30d": { pt: "30 dias", en: "30 days" },
  "90d": { pt: "90 dias", en: "90 days" },
  all: { pt: "Tudo", en: "All time" },
};

/** YYYY-MM-DD local ao pubDate, pra agrupar por dia sem depender de timezone do navegador. */
const dayKey = (iso: string) => String(iso || "").slice(0, 10);

function dailyCounts(rows: NewsArchiveRow[]): { day: string; count: number }[] {
  const byDay = new Map<string, number>();
  for (const row of rows) {
    const key = dayKey(row.pubDate);
    if (!key) continue;
    byDay.set(key, (byDay.get(key) || 0) + 1);
  }
  return [...byDay.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([day, count]) => ({ day, count }));
}

function techniqueCounts(rows: NewsArchiveRow[]): { technique: string; count: number }[] {
  const byTechnique = new Map<string, number>();
  for (const row of rows) for (const t of row.phishingTechniques) byTechnique.set(t, (byTechnique.get(t) || 0) + 1);
  return [...byTechnique.entries()].sort((a, b) => b[1] - a[1]).map(([technique, count]) => ({ technique, count }));
}

// Linha + área, uma série só (contagem diária) — um hue só (o primary do
// tema), sem paleta categórica: identidade não é o trabalho aqui, magnitude é.
function DailyVolumeChart({ data, pt }: { data: { day: string; count: number }[]; pt: boolean }) {
  const [hover, setHover] = useState<number | null>(null);
  const width = 760;
  const height = 220;
  const padding = { top: 16, right: 16, bottom: 28, left: 36 };
  const plotW = width - padding.left - padding.right;
  const plotH = height - padding.top - padding.bottom;

  if (data.length === 0) return null;
  const maxCount = Math.max(1, ...data.map((d) => d.count));
  const x = (i: number) => padding.left + (data.length === 1 ? plotW / 2 : (i / (data.length - 1)) * plotW);
  const y = (count: number) => padding.top + plotH - (count / maxCount) * plotH;

  const linePath = data.map((d, i) => `${i === 0 ? "M" : "L"} ${x(i)} ${y(d.count)}`).join(" ");
  const areaPath = `${linePath} L ${x(data.length - 1)} ${padding.top + plotH} L ${x(0)} ${padding.top + plotH} Z`;

  // 4 linhas de referência horizontais, recessivas — não é grade pesada.
  const gridLines = [0, 0.25, 0.5, 0.75, 1].map((fraction) => ({
    y: padding.top + plotH * (1 - fraction),
    value: Math.round(maxCount * fraction),
  }));

  // ~6 rótulos de data, nunca um por dia — a legibilidade some com mais que isso.
  const labelEvery = Math.max(1, Math.ceil(data.length / 6));
  const fmtDay = (day: string) => {
    const d = new Date(`${day}T00:00:00Z`);
    return isNaN(d.getTime()) ? day : d.toLocaleDateString(pt ? "pt-BR" : "en-US", { day: "2-digit", month: "2-digit" });
  };

  return (
    <div className="relative">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-[220px] w-full"
        onMouseLeave={() => setHover(null)}
        onMouseMove={(e) => {
          const rect = e.currentTarget.getBoundingClientRect();
          const relX = ((e.clientX - rect.left) / rect.width) * width;
          let nearest = 0;
          let best = Infinity;
          for (let i = 0; i < data.length; i++) {
            const d = Math.abs(x(i) - relX);
            if (d < best) { best = d; nearest = i; }
          }
          setHover(nearest);
        }}
      >
        {gridLines.map((line, i) => (
          <g key={i}>
            <line x1={padding.left} x2={width - padding.right} y1={line.y} y2={line.y} className="stroke-border/50" strokeWidth={1} />
            <text x={padding.left - 8} y={line.y} textAnchor="end" dominantBaseline="middle" className="fill-muted-foreground text-[9px]">
              {line.value}
            </text>
          </g>
        ))}
        {data.map((d, i) => (
          i % labelEvery === 0 && (
            <text key={d.day} x={x(i)} y={height - 8} textAnchor="middle" className="fill-muted-foreground text-[9px]">
              {fmtDay(d.day)}
            </text>
          )
        ))}
        <path d={areaPath} fill="hsl(var(--primary))" opacity={0.12} stroke="none" />
        <path d={linePath} fill="none" stroke="hsl(var(--primary))" strokeWidth={2} />
        {hover !== null && (
          <>
            <line x1={x(hover)} x2={x(hover)} y1={padding.top} y2={padding.top + plotH} className="stroke-foreground/20" strokeWidth={1} />
            <circle cx={x(hover)} cy={y(data[hover].count)} r={4} fill="hsl(var(--primary))" />
          </>
        )}
        {/* Camada de hover: um alvo por ponto, maior que a marca, pra não exigir mira. */}
        {data.map((d, i) => (
          <rect
            key={d.day}
            x={x(i) - plotW / Math.max(1, data.length) / 2}
            y={padding.top}
            width={plotW / Math.max(1, data.length)}
            height={plotH}
            fill="transparent"
            onMouseEnter={() => setHover(i)}
          />
        ))}
      </svg>
      {hover !== null && (
        <div
          className="pointer-events-none absolute rounded border bg-popover px-2 py-1 text-[11px] shadow-sm"
          style={{ left: `${(x(hover) / width) * 100}%`, top: 4, transform: "translateX(-50%)" }}
        >
          <div className="font-semibold text-foreground">{data[hover].count} reports</div>
          <div className="text-muted-foreground">{fmtDay(data[hover].day)}</div>
        </div>
      )}
    </div>
  );
}

// Barras horizontais, mesmo hue único — ranking de magnitude por categoria
// (técnica), não identidade entre séries, então uma cor só é a escolha certa.
function TechniqueBarChart({ data, pt }: { data: { technique: string; count: number }[]; pt: boolean }) {
  const top = data.slice(0, 10);
  if (top.length === 0) {
    return <p className="py-6 text-center text-xs text-muted-foreground">{pt ? "Nenhuma técnica identificada no período." : "No technique identified in this period."}</p>;
  }
  const maxCount = Math.max(1, ...top.map((d) => d.count));
  return (
    <div className="space-y-2">
      {top.map((d) => (
        <div key={d.technique} className="flex items-center gap-2 text-xs">
          <span className="w-44 shrink-0 truncate text-muted-foreground" title={d.technique}>{d.technique}</span>
          <div className="relative h-5 flex-1 rounded bg-muted/40">
            <div
              className="absolute inset-y-0 left-0 rounded bg-primary/70"
              style={{ width: `${Math.max(4, (d.count / maxCount) * 100)}%` }}
            />
          </div>
          <span className="w-8 shrink-0 text-right font-mono font-semibold text-foreground">{d.count}</span>
        </div>
      ))}
    </div>
  );
}

export function PhishingTrends() {
  const { language } = useLanguage();
  const pt = language === "pt";
  const [period, setPeriod] = useState<Period>("90d");
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [rows, setRows] = useState<NewsArchiveRow[]>([]);
  const [total, setTotal] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    const from = period === "all" ? undefined : new Date(Date.now() - PERIOD_DAYS[period] * 86400000).toISOString();
    fetchNewsArchive({ category: "Phishing", from, limit: 20000 })
      .then((res) => { if (!cancelled) { setRows(res.rows); setTotal(res.total); } })
      .catch(() => { if (!cancelled) toast.error(pt ? "Falha ao carregar o arquivo de notícias" : "Failed to load the news archive"); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [period]);

  const daily = useMemo(() => dailyCounts(rows), [rows]);
  const techniques = useMemo(() => techniqueCounts(rows), [rows]);

  const onExport = async () => {
    setExporting(true);
    try {
      await exportPhishingTrendsExcel(rows);
    } catch {
      toast.error(pt ? "Falha ao exportar" : "Export failed");
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-1 rounded-md border border-border/60 bg-background p-0.5">
          {PERIODS.map((value) => (
            <button
              key={value}
              type="button"
              onClick={() => setPeriod(value)}
              aria-pressed={period === value}
              className={`rounded px-2.5 py-1.5 text-xs font-semibold transition-colors ${period === value ? "bg-foreground text-background" : "text-muted-foreground hover:text-foreground"}`}
            >
              {PERIOD_LABEL[value][pt ? "pt" : "en"]}
            </button>
          ))}
        </div>
        <Button variant="outline" size="sm" className="gap-1.5" onClick={onExport} disabled={exporting || rows.length === 0}>
          {exporting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Download className="h-3.5 w-3.5" />}
          {pt ? "Exportar" : "Export"}
        </Button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center gap-2 py-16 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          {pt ? "Carregando arquivo…" : "Loading archive…"}
        </div>
      ) : rows.length === 0 ? (
        <EmptyState
          icon={TrendingUp}
          title={pt ? "Nenhum report de phishing no arquivo ainda" : "No phishing report archived yet"}
          description={pt
            ? "O arquivo é alimentado a cada atualização do boletim — volte depois que o feed coletar notícias categorizadas como Phishing."
            : "The archive fills up on every feed refresh — check back once the feed collects items categorized as Phishing."}
        />
      ) : (
        <>
          <Card>
            <CardContent className="p-4">
              <div className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-muted-foreground">
                <TrendingUp className="h-3.5 w-3.5" />
                {pt ? `Volume diário · ${total} no total arquivado` : `Daily volume · ${total} archived in total`}
              </div>
              <DailyVolumeChart data={daily} pt={pt} />
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="mb-3 text-xs font-semibold text-muted-foreground">
                {pt ? "Por técnica (top 10 no período)" : "By technique (top 10 in period)"}
              </div>
              <TechniqueBarChart data={techniques} pt={pt} />
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
