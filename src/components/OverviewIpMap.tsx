import { useEffect, useMemo, useRef, useState } from "react";
import { MapPinned, Server } from "lucide-react";
import { ThreatIntelligenceResult } from "@/types/threat-intelligence";
import { useLanguage } from "@/contexts/LanguageContext";
import { cn } from "@/lib/utils";

type IpPoint = {
  query: string;
  lat: number;
  lon: number;
  country: string;
  city: string;
  isp: string;
  score: number;
  detections: number;
  totalVendors: number;
  threatLevel: ThreatIntelligenceResult["threatLevel"];
};

const numberFrom = (value: unknown) => {
  if (value === null || value === undefined || value === "") return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
};

const threatColor = (level: IpPoint["threatLevel"]) => {
  if (level === "malicious") return "#ef4444";
  if (level === "suspicious") return "#f59e0b";
  if (level === "unknown") return "#94a3b8";
  return "#10b981";
};

const getIpPoints = (results: ThreatIntelligenceResult[]): IpPoint[] => {
  return results.flatMap((result) => {
    const geo = result.vendorData.find((v) => v.name === "IP Geolocation")?.data;
    const abuse = result.vendorData.find((v) => v.name === "AbuseIPDB")?.data;
    const lat = numberFrom(geo?.["Latitude"] ?? geo?.latitude ?? geo?.lat);
    const lon = numberFrom(geo?.["Longitude"] ?? geo?.longitude ?? geo?.lon);

    if (lat === null || lon === null) return [];

    return [{
      query: result.query,
      lat,
      lon,
      country: geo?.["Country"] || abuse?.["Country"] || "-",
      city: geo?.["City"] || "-",
      isp: geo?.["ISP"] || abuse?.["ISP"] || "-",
      score: result.overallScore || 0,
      detections: result.detections || 0,
      totalVendors: result.totalVendors || 0,
      threatLevel: result.threatLevel,
    }];
  });
};

const LeafletOverviewMap = ({ points }: { points: IpPoint[] }) => {
  const mapRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<any>(null);
  const [leafletLoaded, setLeafletLoaded] = useState(false);

  useEffect(() => {
    if ((window as any).L) {
      setLeafletLoaded(true);
      return;
    }

    const existingCss = document.querySelector('link[href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"]');
    if (!existingCss) {
      const link = document.createElement("link");
      link.rel = "stylesheet";
      link.href = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css";
      link.crossOrigin = "";
      document.head.appendChild(link);
    }

    const existingScript = document.querySelector('script[src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"]') as HTMLScriptElement | null;
    if (existingScript) {
      existingScript.addEventListener("load", () => setLeafletLoaded(true), { once: true });
      return;
    }

    const script = document.createElement("script");
    script.src = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js";
    script.crossOrigin = "";
    script.async = true;
    script.onload = () => setLeafletLoaded(true);
    document.body.appendChild(script);
  }, []);

  useEffect(() => {
    if (!leafletLoaded || !mapRef.current || !(window as any).L || points.length === 0) return;

    const L = (window as any).L;

    if (mapInstanceRef.current) {
      mapInstanceRef.current.remove();
      mapInstanceRef.current = null;
    }

    try {
      const map = L.map(mapRef.current, {
        center: [20, 0],
        zoom: 2,
        minZoom: 1.5,
        zoomSnap: 0.25,
        zoomDelta: 0.5,
        zoomControl: false,
        attributionControl: false,
        scrollWheelZoom: false,
      });

      L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
        maxZoom: 19,
      }).addTo(map);

      const bounds: [number, number][] = [];

      points.forEach((point) => {
        bounds.push([point.lat, point.lon]);
        const color = threatColor(point.threatLevel);
        const size = Math.max(16, Math.min(28, 14 + point.score / 5));
        const icon = L.divIcon({
          className: "overview-ip-dot",
          html: `<div style="width:${size}px;height:${size}px;border-radius:999px;background:${color};border:2px solid white;box-shadow:0 0 0 8px ${color}22,0 12px 28px ${color}55;"></div>`,
          iconSize: [size, size],
          iconAnchor: [size / 2, size / 2],
        });

        L.marker([point.lat, point.lon], { icon })
          .bindPopup(`
            <div style="min-width:180px">
              <div style="font-weight:800;font-family:monospace;margin-bottom:4px">${point.query}</div>
              <div>${point.city}, ${point.country}</div>
              <div style="margin-top:4px;color:#64748b">${point.isp}</div>
              <div style="margin-top:6px;font-weight:700">${point.score}/100 · ${point.detections}/${point.totalVendors}</div>
            </div>
          `)
          .addTo(map);
      });

      if (bounds.length === 1) {
        map.setView(bounds[0], 2);
      } else if (bounds.length > 1) {
        map.fitBounds(bounds, { padding: [48, 48], maxZoom: 2.75 });
      }

      mapInstanceRef.current = map;
    } catch (e) {
      console.error("Overview IP map initialization failed:", e);
    }

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, [leafletLoaded, points]);

  return (
    <div className="relative h-full w-full">
      {!leafletLoaded && (
        <div className="absolute inset-0 z-10 flex items-center justify-center bg-muted/40">
          <div className="h-6 w-6 animate-spin rounded-full border-b-2 border-primary" />
        </div>
      )}
      <div ref={mapRef} className="leaflet-dark-map z-0 h-full w-full" />
    </div>
  );
};

interface OverviewIpMapProps {
  results: ThreatIntelligenceResult[];
  onViewDetails: (query: string) => void;
}

export const OverviewIpMap = ({ results, onViewDetails }: OverviewIpMapProps) => {
  const { language } = useLanguage();
  const pt = language === "pt";
  const points = useMemo(() => getIpPoints(results), [results]);

  if (points.length === 0) return null;

  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card">
      <div className="grid lg:grid-cols-[1.4fr_0.6fr]">
        <div className="relative min-h-[420px] border-b border-border lg:border-b-0 lg:border-r">
          <LeafletOverviewMap points={points} />
          <div className="pointer-events-none absolute left-4 top-4 rounded-lg border border-border bg-background/90 px-4 py-3 shadow-sm backdrop-blur">
            <div className="flex items-center gap-2">
              <MapPinned className="h-4 w-4 text-primary" />
              <h3 className="font-black tracking-tight">{pt ? "Mapa dos alvos" : "Target map"}</h3>
            </div>
            <p className="mt-1 text-xs font-medium text-muted-foreground">
              {pt ? "IPs geolocalizados nesta busca" : "Geolocated IPs in this scan"}
            </p>
          </div>
        </div>

        <aside className="flex min-h-[420px] flex-col p-5">
          <div className="mb-4">
            <h4 className="text-sm font-black uppercase tracking-wide text-foreground">
              {pt ? "Alvos no mapa" : "Mapped targets"}
            </h4>
            <p className="mt-1 text-xs font-medium leading-5 text-muted-foreground">
              {pt
                ? "Clique em um alvo para abrir a análise detalhada. As métricas gerais ficam no resumo acima."
                : "Click a target to open detailed analysis. Global metrics stay in the summary above."}
            </p>
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto pr-1">
            <div className="space-y-2">
              {points.map((point) => {
                const colorClass = point.threatLevel === "malicious"
                  ? "bg-red-500"
                  : point.threatLevel === "suspicious"
                    ? "bg-amber-500"
                    : point.threatLevel === "unknown"
                      ? "bg-slate-400"
                      : "bg-emerald-500";

                return (
                  <button
                    key={point.query}
                    type="button"
                    onClick={() => onViewDetails(point.query)}
                    className="w-full rounded-md border border-border bg-background p-3 text-left transition-colors hover:border-primary/40 hover:bg-secondary/40"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="truncate font-mono text-sm font-black text-foreground">{point.query}</div>
                        <div className="mt-1 flex items-center gap-1.5 text-xs text-muted-foreground">
                          <Server className="h-3.5 w-3.5 shrink-0" />
                          <span className="truncate">{point.isp}</span>
                        </div>
                        <div className="mt-1 truncate text-xs text-muted-foreground">{point.city}, {point.country}</div>
                      </div>
                      <span className="flex shrink-0 items-center gap-1 rounded-full border border-border bg-secondary/50 px-2 py-1 font-mono text-[11px] font-black">
                        <span className={cn("h-1.5 w-1.5 rounded-full", colorClass)} />
                        {point.score}
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </aside>
      </div>
    </section>
  );
};
