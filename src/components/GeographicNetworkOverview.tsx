import { Building2, Globe2, MapPin, Network, RadioTower, Server } from "lucide-react";
import { useLanguage } from "@/contexts/LanguageContext";
import type { VendorData } from "@/types/threat-intelligence";
import { buildNetworkOverview, type NetworkOverviewItem } from "@/utils/networkOverview";

const icons: Record<NetworkOverviewItem["key"], typeof Globe2> = {
  isp: RadioTower, organization: Building2, country: Globe2, region: MapPin,
  city: MapPin, asn: Server, network: Network,
};

export const GeographicNetworkOverview = ({ vendorData }: { vendorData: VendorData[] }) => {
  const { language } = useLanguage();
  const items = buildNetworkOverview(vendorData);
  if (!items.length) return null;

  return <section className="overflow-hidden rounded-lg border border-border bg-card" aria-labelledby="network-overview-title">
    <div className="border-b border-border px-5 py-4">
      <h2 id="network-overview-title" className="font-bold">{language === "pt" ? "Dados geográficos e de rede" : "Geographic & Network Data"}</h2>
    </div>
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4">
      {items.map((item) => {
        const Icon = icons[item.key];
        const mono = item.key === "asn" || item.key === "network";
        return <div key={item.key} className="min-w-0 border-b border-r border-border p-5 last:border-b-0">
          <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground"><Icon className="h-4 w-4 text-primary" />{item.label}</div>
          <p className={`mt-2 break-words text-sm font-semibold ${mono ? "font-mono" : ""}`}>{item.value}</p>
        </div>;
      })}
    </div>
  </section>;
};
