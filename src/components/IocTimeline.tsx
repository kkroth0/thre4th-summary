import { useMemo } from "react";
import { Clock, Flag, Activity, FileWarning, History, CircleDot } from "lucide-react";
import { VendorData, TimelineEvent } from "@/types/threat-intelligence";
import { cn } from "@/lib/utils";

// Correlated detection timeline: merges the dated observations every feed
// reported about the searched IOC (first/last seen, last analysis, abuse
// reports) into a single chronological view. Renders nothing when no feed
// returned a usable timestamp.

const KIND_STYLE: Record<TimelineEvent["kind"], { color: string; icon: typeof Flag; label: string }> = {
  first_seen: { color: "text-emerald-500 border-emerald-500/30 bg-emerald-500/10", icon: Flag, label: "First seen" },
  last_seen: { color: "text-blue-500 border-blue-500/30 bg-blue-500/10", icon: History, label: "Last seen" },
  analysis: { color: "text-violet-500 border-violet-500/30 bg-violet-500/10", icon: Activity, label: "Analysis" },
  report: { color: "text-amber-600 border-amber-500/30 bg-amber-500/10", icon: FileWarning, label: "Report" },
  other: { color: "text-slate-400 border-slate-400/30 bg-slate-400/10", icon: CircleDot, label: "Event" },
};

const relativeTime = (iso: string): string => {
  const diff = Date.now() - new Date(iso).getTime();
  const day = 86400000;
  const abs = Math.abs(diff);
  if (abs < day) return "today";
  const days = Math.round(abs / day);
  if (days < 30) return `${days}d ago`;
  const months = Math.round(days / 30);
  if (months < 12) return `${months}mo ago`;
  return `${Math.round(months / 12)}y ago`;
};

const fmt = (iso: string) =>
  new Date(iso).toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });

interface Props {
  vendorData: VendorData[];
}

export const IocTimeline = ({ vendorData }: Props) => {
  const events = useMemo(() => {
    const all = vendorData.flatMap((v) => v.timeline ?? []);
    // De-duplicate identical (vendor,label,minute) events, then sort newest first.
    const seen = new Set<string>();
    const deduped = all.filter((e) => {
      const key = `${e.vendor}|${e.label}|${e.date.slice(0, 16)}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    return deduped.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
  }, [vendorData]);

  if (events.length === 0) return null;

  const earliest = events[events.length - 1];
  const latest = events[0];
  const feedCount = new Set(events.map((e) => e.vendor)).size;

  return (
    <div className="rounded-xl border border-border/60 bg-card/40 p-5 animate-fade-in">
      <div className="flex flex-wrap items-center justify-between gap-3 mb-5">
        <div className="flex items-center gap-2">
          <Clock className="h-5 w-5 text-primary" />
          <h3 className="text-lg font-bold">Detection Timeline</h3>
        </div>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span><span className="text-emerald-500 font-semibold">First observed</span> {fmt(earliest.date)}</span>
          <span><span className="text-blue-500 font-semibold">Last activity</span> {fmt(latest.date)}</span>
          <span>{events.length} events · {feedCount} feeds</span>
        </div>
      </div>

      <ol className="relative border-l border-border/60 ml-2 space-y-4">
        {events.map((e, i) => {
          const style = KIND_STYLE[e.kind];
          const Icon = style.icon;
          return (
            <li key={`${e.vendor}-${e.label}-${i}`} className="ml-5">
              <span className={cn("absolute -left-[11px] flex h-5 w-5 items-center justify-center rounded-full border", style.color)}>
                <Icon className="h-2.5 w-2.5" />
              </span>
              <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                <span className="text-sm font-semibold text-foreground">{e.vendor}</span>
                <span className="text-xs text-muted-foreground">{e.label}</span>
                <span className="ml-auto text-[11px] font-mono text-muted-foreground/80" title={fmt(e.date)}>
                  {fmt(e.date)} · {relativeTime(e.date)}
                </span>
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
};
