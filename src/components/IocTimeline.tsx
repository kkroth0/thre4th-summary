import { useMemo, useState } from "react";
import { Clock, Flag, Activity, FileWarning, History, CircleDot, ChevronDown } from "lucide-react";
import { VendorData, TimelineEvent } from "@/types/threat-intelligence";
import { useLanguage } from "@/contexts/LanguageContext";
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
  const { language } = useLanguage();
  const pt = language === "pt";
  const [open, setOpen] = useState(false);
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

  const days = useMemo(() => {
    const map = new Map<string, TimelineEvent[]>();
    events.forEach((event) => {
      const key = event.date.slice(0, 10);
      map.set(key, [...(map.get(key) || []), event]);
    });
    return Array.from(map.entries()).map(([day, dayEvents]) => ({
      day,
      events: dayEvents,
      vendors: Array.from(new Set(dayEvents.map((event) => event.vendor))),
    }));
  }, [events]);

  if (events.length === 0) return null;

  const earliest = events[events.length - 1];
  const latest = events[0];
  const feedCount = new Set(events.map((e) => e.vendor)).size;

  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card animate-fade-in">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className={cn(
          "w-full border-border bg-secondary/30 px-5 py-4 text-left transition-colors hover:bg-secondary/50",
          open && "border-b"
        )}
        aria-expanded={open}
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Clock className="h-5 w-5 text-primary" />
            <h3 className="text-lg font-black tracking-tight">
              {pt ? "Timeline do IOC nas bases" : "IOC source timeline"}
            </h3>
            <ChevronDown className={cn("h-4 w-4 text-muted-foreground transition-transform", open && "rotate-180")} />
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {[
              [pt ? "Primeiro" : "First", fmt(earliest.date)],
              [pt ? "Ultimo" : "Latest", fmt(latest.date)],
              [pt ? "Bases" : "Sources", String(feedCount)],
              [pt ? "Eventos" : "Events", String(events.length)],
            ].map(([label, value]) => (
              <span key={label} className="inline-flex max-w-[220px] items-center gap-1.5 rounded-full border border-border bg-background px-2.5 py-1">
                <span className="font-bold uppercase tracking-wide text-muted-foreground">{label}</span>
                <span className="truncate font-mono font-black text-foreground" title={value}>{value}</span>
              </span>
            ))}
          </div>
        </div>
      </button>

      {open && (
        <div className="p-5">
          <ol className="relative ml-2 space-y-5 border-l border-border">
            {days.map((bucket) => (
              <li key={bucket.day} className="ml-6">
                <span className="absolute -left-[7px] mt-1 h-3 w-3 rounded-full border border-primary bg-background" />
                <div className="mb-3 flex flex-wrap items-center gap-2">
                  <span className="font-mono text-sm font-black text-foreground">
                    {new Date(`${bucket.day}T00:00:00Z`).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "2-digit" })}
                  </span>
                  <span className="text-xs font-medium text-muted-foreground">
                    {bucket.vendors.length} {pt ? "base(s)" : "source(s)"} · {bucket.events.length} {pt ? "evento(s)" : "event(s)"}
                  </span>
                </div>
                <div className="grid gap-2">
                  {bucket.events.map((e, i) => {
                    const style = KIND_STYLE[e.kind];
                    const Icon = style.icon;
                    return (
                      <div key={`${e.vendor}-${e.label}-${i}`} className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-background px-3 py-2">
                        <span className={cn("flex h-7 w-7 items-center justify-center rounded-md border", style.color)}>
                          <Icon className="h-3.5 w-3.5" />
                        </span>
                        <span className="font-semibold text-foreground">{e.vendor}</span>
                        <span className="min-w-0 flex-1 truncate text-sm text-muted-foreground">{e.label}</span>
                        <span className="font-mono text-[11px] text-muted-foreground" title={fmt(e.date)}>
                          {fmt(e.date)} · {relativeTime(e.date)}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}
    </section>
  );
};
