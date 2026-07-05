import { useState, useEffect, useRef } from "react";
import { Card } from "@/components/ui/card";
import { VendorData } from "@/types/threat-intelligence";
import { useLanguage } from "@/contexts/LanguageContext";
import { Shield, Globe, Server, MapPin, Radio, Key, ShieldAlert, Clock, ChevronLeft, ChevronRight } from "lucide-react";

interface ThreatChartsProps {
  vendorData: VendorData[];
  detections: number;
  totalVendors: number;
}

const LeafletMap = ({ lat, lon }: { lat: number; lon: number }) => {
  const mapRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<any>(null);
  const [leafletLoaded, setLeafletLoaded] = useState(false);

  useEffect(() => {
    if ((window as any).L) {
      setLeafletLoaded(true);
      return;
    }

    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css";
    link.crossOrigin = "";
    document.head.appendChild(link);

    const script = document.createElement("script");
    script.src = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js";
    script.crossOrigin = "";
    script.async = true;
    script.onload = () => {
      setLeafletLoaded(true);
    };
    document.body.appendChild(script);
  }, []);

  useEffect(() => {
    if (!leafletLoaded || !mapRef.current || !(window as any).L) return;

    const L = (window as any).L;

    if (mapInstanceRef.current) {
      mapInstanceRef.current.remove();
      mapInstanceRef.current = null;
    }

    try {
      const map = L.map(mapRef.current, {
        center: [lat, lon],
        zoom: 4,
        zoomControl: false,
        attributionControl: false,
      });

      L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
        maxZoom: 19,
      }).addTo(map);

      const redDotIcon = L.divIcon({
        className: "custom-red-dot",
        html: `<div class="w-4.5 h-4.5 bg-rose-500 rounded-full border-2 border-white  animate-pulse" style="box-shadow: 0 0 12px rgba(244, 63, 94, 0.9); width: 18px; height: 18px;"></div>`,
        iconSize: [18, 18],
        iconAnchor: [9, 9],
      });

      L.marker([lat, lon], { icon: redDotIcon }).addTo(map);

      mapInstanceRef.current = map;
    } catch (e) {
      console.error("Leaflet map initialization failed:", e);
    }

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, [leafletLoaded, lat, lon]);

  return (
    <div className="w-full h-full relative">
      {!leafletLoaded && (
        <div className="absolute inset-0 flex items-center justify-center bg-muted/40  z-10">
          <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary"></div>
        </div>
      )}
      <div ref={mapRef} className="w-full h-full z-0 leaflet-dark-map" />
    </div>
  );
};

export const ThreatCharts = ({ vendorData, detections, totalVendors }: ThreatChartsProps) => {
  const { t } = useLanguage();
  const [currentPage, setCurrentPage] = useState(1);

  // Reset page when vendor data changes
  useEffect(() => {
    setCurrentPage(1);
  }, [vendorData]);

  // Key Indicators (Vendor Specific)
  const getKeyIndicators = () => {
    const indicators: { type: string, value: string, source: string }[] = [];
    
    // Explicit VT Insights
    const vt = vendorData.find(v => v.name === "VirusTotal")?.data;
    if (vt && !vt.error && vt["Detection Rate"]) {
      indicators.push({ type: "Detection Engine Hits", value: vt["Detection Rate"], source: "VirusTotal" });
    }

    // Explicit AbuseIPDB Insights
    const abuse = vendorData.find(v => v.name === "AbuseIPDB")?.data;
    if (abuse && !abuse.error) {
      if (abuse["Abuse Confidence Score"]) indicators.push({ type: "Confidence Score", value: `${abuse["Abuse Confidence Score"]}%`, source: "AbuseIPDB" });
      if (abuse["Total Reports"] && abuse["Total Reports"] > 0) indicators.push({ type: "Crowdsourced Reports", value: `${abuse["Total Reports"]} reports`, source: "AbuseIPDB" });
      if (abuse["Tags"] && abuse["Tags"] !== "None") indicators.push({ type: "Behavior Tags", value: abuse["Tags"], source: "AbuseIPDB" });
    }

    // Explicit OTX Insights
    const otx = vendorData.find(v => v.name === "AlienVault OTX")?.data;
    if (otx && !otx.error && otx["Pulse Count"] && parseInt(otx["Pulse Count"]) > 0) {
      indicators.push({ type: "Threat Intelligence Pulses", value: `${otx["Pulse Count"]} pulses active`, source: "AlienVault OTX" });
    }

    // VPN/Proxy and Hosting status from IP Geolocation
    const geo = vendorData.find(v => v.name === "IP Geolocation")?.data;
    if (geo && !geo.error) {
      if (geo["Proxy/VPN"] === "Yes ⚠️" || geo["Proxy/VPN"] === "Yes") {
        indicators.push({ type: "VPN / Proxy Alert", value: "Active VPN/Proxy Detected", source: "IP Geolocation" });
      }
      if (geo["Hosting"] === "Yes") {
        indicators.push({ type: "Hosting Status", value: "Hosted on Datacenter / Cloud", source: "IP Geolocation" });
      }
    }

    // WHOIS Insights
    const whois = vendorData.find(v => v.name === "WHOIS")?.data;
    if (whois && !whois.error) {
      if (whois["Registrar"] && whois["Registrar"] !== "Unknown") {
        indicators.push({ type: "Domain Registrar", value: whois["Registrar"], source: "WHOIS" });
      }
      if (whois["Created"] && whois["Created"] !== "Unknown") {
        try {
          const createdDate = new Date(whois["Created"]).toLocaleDateString();
          indicators.push({ type: "Domain Created Date", value: createdDate, source: "WHOIS" });
        } catch {
          indicators.push({ type: "Domain Created Date", value: whois["Created"], source: "WHOIS" });
        }
      }
    }

    // Shodan Insights
    const shodan = vendorData.find(v => v.name === "Shodan")?.data;
    if (shodan && !shodan.error) {
      if (shodan["Vulnerabilities"] && shodan["Vulnerabilities"] !== "0 CVEs") {
        indicators.push({ type: "Vulnerabilities Found", value: shodan["Vulnerabilities"], source: "Shodan" });
      }
      if (shodan["Services"] && shodan["Services"] !== "Unknown" && shodan["Services"] !== "") {
        indicators.push({ type: "Detected Services", value: shodan["Services"], source: "Shodan" });
      }
    }
    
    // Fallback Prominent Open Ports
    const ports = new Set<string>();
    vendorData.forEach(vendor => {
      if (vendor.data && vendor.data["Open Ports"] && vendor.data["Open Ports"] !== "None") {
        vendor.data["Open Ports"].split(", ").forEach((p: string) => ports.add(p));
      }
    });

    if (ports.size > 0 && indicators.length < 5) {
      indicators.push({ type: "Open Ports Found", value: Array.from(ports).slice(0, 5).join(", "), source: "Multiple" });
    }

    return indicators;
  };

  // Geographic & Network Data
  const getNetworkData = () => {
    const data: Record<string, string> = {};
    const ipGeo = vendorData.find(v => v.name === "IP Geolocation")?.data;
    const vt = vendorData.find(v => v.name === "VirusTotal")?.data;

    if (ipGeo && !ipGeo.error) {
      if (ipGeo["ISP"] && ipGeo["ISP"] !== "Unknown") data["ISP"] = ipGeo["ISP"];
      if (ipGeo["Organization"] && ipGeo["Organization"] !== "Unknown") data["Organization"] = ipGeo["Organization"];
      if (ipGeo["Country"] && ipGeo["Country"] !== "Unknown") data["Country"] = ipGeo["Country"];
      if (ipGeo["Region"] && ipGeo["Region"] !== "Unknown") data["Region"] = ipGeo["Region"];
      if (ipGeo["City"] && ipGeo["City"] !== "Unknown") data["City"] = ipGeo["City"];
      if (ipGeo["Timezone"] && ipGeo["Timezone"] !== "Unknown") data["Timezone"] = ipGeo["Timezone"];
      if (ipGeo["AS"] && ipGeo["AS"] !== "Unknown") data["ASN/AS"] = ipGeo["AS"];
      if (ipGeo["Proxy/VPN"] && ipGeo["Proxy/VPN"] !== "No") data["Proxy/VPN"] = ipGeo["Proxy/VPN"];
      if (ipGeo["Hosting"] && ipGeo["Hosting"] !== "No") data["Hosting"] = ipGeo["Hosting"];
    }

    if (vt && !vt.error) {
      if (!data["ASN/AS"] && vt["ASN"] && vt["ASN"] !== "Unknown") data["ASN/AS"] = vt["ASN"];
      if (!data["Network"] && vt["Network"] && vt["Network"] !== "Unknown") data["Network"] = vt["Network"];
    }

    return data;
  };

  // Vendor Threat Scores
  const getVendorScore = (vendor: VendorData): { score: number, status: string } => {
    const data = vendor.data;
    if (!data || Object.keys(data).length === 0 || vendor.error) return { score: 0, status: "No Data" };

    // VirusTotal
    if (data["Detection Rate"]) {
      const parts = data["Detection Rate"].split("/");
      if (parts.length === 2) {
        return {
          score: Math.round((parseInt(parts[0]) / parseInt(parts[1])) * 100),
          status: data["Status"] || t('unknown')
        };
      }
    }

    // AbuseIPDB
    if (data["Abuse Confidence Score"]) {
      return {
        score: parseInt(data["Abuse Confidence Score"]),
        status: `Confidence: ${data["Abuse Confidence Score"]}%`
      };
    }

    // IPQualityScore
    if (data["Fraud Score"]) {
      return {
        score: parseInt(data["Fraud Score"]),
        status: data["Status"] || t('unknown')
      };
    }

    // Hybrid Analysis
    if (data["Threat Score"]) {
      return {
        score: parseInt(data["Threat Score"]),
        status: `Score: ${data["Threat Score"]}`
      };
    }

    // Fallback based on Status string
    const status = (data["Status"] || "").toLowerCase();
    if (status.includes("malicious") || status.includes("unsafe") || status.includes("phishing") || status.includes("high risk")) {
      return { score: 100, status: data["Status"] };
    }
    if (status.includes("suspicious") || status.includes("moderate risk")) {
      return { score: 60, status: data["Status"] };
    }
    if (status.includes("low risk")) {
      return { score: 30, status: data["Status"] };
    }

    return { score: 0, status: data["Status"] || t('clean') };
  };

  const vendorScores = vendorData
    .map(vendor => {
      const { score, status } = getVendorScore(vendor);
      return {
        name: vendor.name,
        score,
        status,
        fill: score > 70 ? "hsl(var(--destructive))" : score > 30 ? "#eab308" : "#10b981"
      };
    })
    .sort((a, b) => b.score - a.score)
    .slice(0, 10);

  const ITEMS_PER_PAGE = 5;
  const totalPages = Math.ceil(vendorScores.length / ITEMS_PER_PAGE);
  const startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
  const paginatedScores = vendorScores.slice(startIndex, startIndex + ITEMS_PER_PAGE);

  const getGeoDetails = () => {
    const geo = vendorData.find(v => v.name === "IP Geolocation")?.data;
    if (geo && !geo.error) {
      const country = geo["Country"] || "Unknown";
      const city = geo["City"] || "Unknown";
      const latVal = geo["Latitude"] ? parseFloat(geo["Latitude"]) : null;
      const lonVal = geo["Longitude"] ? parseFloat(geo["Longitude"]) : null;
      return {
        country,
        city,
        lat: latVal !== null && !isNaN(latVal) ? latVal : 0,
        lon: lonVal !== null && !isNaN(lonVal) ? lonVal : 0,
        hasCoordinates: latVal !== null && lonVal !== null && !isNaN(latVal) && !isNaN(lonVal)
      };
    }
    return {
      country: "Unknown",
      city: "Unknown",
      lat: 0,
      lon: 0,
      hasCoordinates: false
    };
  };

  const geoDetails = getGeoDetails();
  const networkData = getNetworkData();
  const hasNetworkData = Object.keys(networkData).length > 0;

  return (
    <div className="grid gap-6 md:grid-cols-3 animate-fade-in">
      {/* Geolocation Card */}
      <Card className="p-6 border border-border/50 bg-muted/40  shadow-md shadow-primary/5 flex flex-col min-h-[340px]">
        <h3 className="text-sm font-bold tracking-wider uppercase text-muted-foreground mb-4">Geolocation</h3>
        {geoDetails.hasCoordinates ? (
          <div className="flex-1 flex flex-col gap-4">
            {/* Map Area */}
            <div className="relative w-full h-[150px] rounded-xl overflow-hidden border border-border/50 bg-background/50">
              <LeafletMap lat={geoDetails.lat} lon={geoDetails.lon} />
            </div>
            
            {/* Geolocation details */}
            <div className="grid grid-cols-2 gap-x-4 gap-y-2.5">
              <div>
                <p className="text-[9px] text-muted-foreground uppercase tracking-wider font-semibold">Country</p>
                <p className="text-xs font-bold text-foreground truncate" title={geoDetails.country}>{geoDetails.country}</p>
              </div>
              <div>
                <p className="text-[9px] text-muted-foreground uppercase tracking-wider font-semibold">City</p>
                <p className="text-xs font-bold text-foreground truncate" title={geoDetails.city}>{geoDetails.city}</p>
              </div>
              <div>
                <p className="text-[9px] text-muted-foreground uppercase tracking-wider font-semibold">Latitude</p>
                <p className="text-xs font-mono font-bold text-foreground">{geoDetails.lat}</p>
              </div>
              <div>
                <p className="text-[9px] text-muted-foreground uppercase tracking-wider font-semibold">Longitude</p>
                <p className="text-xs font-mono font-bold text-foreground">{geoDetails.lon}</p>
              </div>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center py-12 text-center border border-dashed border-border/60 rounded-xl bg-muted/10">
            <Globe className="h-7 w-7 text-muted-foreground/50 mb-2.5" />
            <p className="text-xs font-semibold text-muted-foreground">No geolocation data</p>
            <p className="text-[10px] text-muted-foreground/50 max-w-[180px] mt-1 leading-normal">
              Map and location coordinates are only available for IP targets.
            </p>
          </div>
        )}
      </Card>

      {/* Geographic & Network Data Card */}
      <Card className="p-6 border border-border/50 bg-muted/40  shadow-md shadow-primary/5 flex flex-col">
        <h3 className="text-sm font-bold tracking-wider uppercase text-muted-foreground mb-4">Geographic & Network Data</h3>
        <div className="flex-1 flex flex-col text-sm justify-center">
          {hasNetworkData ? (
            <div className="divide-y divide-border/40 w-full">
              {Object.entries(networkData).map(([key, value]) => {
                let Icon = Globe;
                if (key === "Country" || key === "Region" || key === "City") Icon = MapPin;
                else if (key === "ISP") Icon = Radio;
                else if (key === "Organization") Icon = Globe;
                else if (key === "ASN/AS" || key === "ASN") Icon = Key;
                else if (key === "Network" || key === "Hosting") Icon = Server;
                else if (key === "Timezone") Icon = Clock;
                else if (key === "Proxy/VPN") Icon = ShieldAlert;
                return (
                  <div key={key} className="flex items-center justify-between py-2.5 first:pt-0 last:pb-0">
                    <div className="flex items-center gap-2">
                      <Icon className="h-4 w-4 text-primary/70 shrink-0" />
                      <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{key}</span>
                    </div>
                    <span className="text-xs font-mono font-bold text-foreground max-w-[170px] truncate" title={value}>
                      {value}
                    </span>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-center border border-dashed border-border/60 rounded-xl bg-muted/10">
              <Globe className="h-7 w-7 text-muted-foreground/50 mb-2.5" />
              <p className="text-xs font-semibold text-muted-foreground">No network data</p>
              <p className="text-[10px] text-muted-foreground/50 max-w-[180px] mt-1 leading-normal">
                Could not retrieve ISP, Country, or ASN geolocation info.
              </p>
            </div>
          )}
        </div>
      </Card>

      {/* Vendor Threat Scores Card */}
      <Card className="p-6 border border-border/50 bg-muted/40  shadow-md shadow-primary/5 flex flex-col justify-between h-full">
        <div className="flex-1 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold tracking-wider uppercase text-muted-foreground mb-4">{t('vendorThreatScores')}</h3>
            <div className="space-y-4">
              {paginatedScores.length > 0 ? (
                paginatedScores.map((vendor, idx) => {
                  const statusBadgeColor = vendor.score > 70 ? "bg-destructive/10 text-destructive border-destructive/20" :
                                           vendor.score > 30 ? "bg-amber-500/10 text-amber-500 border-amber-500/20" :
                                           "bg-emerald-500/10 text-emerald-500 border-emerald-500/20";
                  return (
                    <div key={idx} className="space-y-1.5 border-b border-border/40 pb-3 last:border-0 last:pb-0">
                      <div className="flex justify-between items-center text-xs">
                        <div className="flex items-center gap-2">
                          <img
                            src={`https://www.google.com/s2/favicons?sz=32&domain=${
                              vendor.name === "VirusTotal" ? "virustotal.com" :
                              vendor.name === "AbuseIPDB" ? "abuseipdb.com" :
                              vendor.name === "AlienVault OTX" ? "alienvault.com" :
                              vendor.name === "Shodan" ? "shodan.io" :
                              vendor.name === "Censys" ? "censys.io" :
                              vendor.name === "WHOIS" ? "who.is" :
                              vendor.name === "IP Geolocation" ? "ip-api.com" :
                              vendor.name === "URLhaus" ? "abuse.ch" :
                              vendor.name === "MalwareBazaar" ? "abuse.ch" :
                              vendor.name === "Google Safe Browsing" ? "google.com" :
                              vendor.name === "PhishTank" ? "phishtank.com" :
                              vendor.name === "Pulsedive" ? "pulsedive.com" :
                              vendor.name === "Hybrid Analysis" ? "hybrid-analysis.com" :
                              vendor.name === "CIRCL hashlookup" ? "circl.lu" :
                              vendor.name === "Criminal IP" ? "criminalip.io" :
                              vendor.name === "MetaDefender" ? "opswat.com" :
                              vendor.name === "PhishStats" ? "phishstats.info" :
                              vendor.name === "Ransomware.live" ? "ransomware.live" :
                              vendor.name === "OpenPhish" ? "openphish.com" :
                              "team-cymru.com"
                            }`}
                            alt=""
                            className="w-3.5 h-3.5 rounded-sm object-contain shrink-0"
                            onError={(e) => {
                              (e.target as HTMLElement).style.display = "none";
                            }}
                          />
                          <span className="font-semibold text-foreground">{vendor.name}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={`text-[9px] px-1.5 py-0.5 rounded border uppercase font-mono font-semibold tracking-wider ${statusBadgeColor}`}>
                            {vendor.status}
                          </span>
                          <div className="flex items-center gap-0.5">
                            <span className={`font-bold ${
                              vendor.score > 70 ? "text-destructive" :
                              vendor.score > 30 ? "text-amber-500" : "text-emerald-500"
                            }`}>{vendor.score}</span>
                            <span className="text-muted-foreground/60 text-[10px]">/100</span>
                          </div>
                        </div>
                      </div>
                      <div className="w-full bg-muted/40 h-2 rounded-full overflow-hidden border border-muted/20 relative shadow-inner">
                        <div
                          className="h-full rounded-full transition-all duration-1000 ease-out"
                          style={{
                            width: `${vendor.score}%`,
                            backgroundColor: vendor.fill,
                            boxShadow: `0 0 6px ${vendor.fill}80`
                          }}
                        />
                      </div>
                    </div>
                  );
                })
              ) : (
                <p className="text-xs text-muted-foreground">No vendor scores recorded.</p>
              )}
            </div>
          </div>
          {totalPages > 1 && (
            <div className="flex items-center justify-between pt-4 mt-6 border-t border-border/40 text-xs text-muted-foreground">
              <div>
                {t('page')} <span className="font-semibold text-foreground">{currentPage}</span> {t('of')}{" "}
                <span className="font-semibold text-foreground">{totalPages}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                  disabled={currentPage === 1}
                  className="p-1 rounded-md border border-border bg-muted/20 hover:bg-muted/50 disabled:opacity-30 disabled:hover:bg-muted/20 transition-all duration-200"
                  aria-label="Previous page"
                >
                  <ChevronLeft className="h-4 w-4" />
                </button>
                <button
                  type="button"
                  onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
                  disabled={currentPage === totalPages}
                  className="p-1 rounded-md border border-border bg-muted/20 hover:bg-muted/50 disabled:opacity-30 disabled:hover:bg-muted/20 transition-all duration-200"
                  aria-label="Next page"
                >
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
};
