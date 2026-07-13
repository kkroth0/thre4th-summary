import type { VendorData } from "@/types/threat-intelligence";

export type NetworkOverviewItem = {
  key: "isp" | "organization" | "country" | "region" | "city" | "asn" | "network";
  label: string;
  value: string;
};

const EMPTY_VALUES = new Set(["", "unknown", "n/a", "none", "not available", "-"]);
const usable = (value: unknown): value is string | number =>
  (typeof value === "string" || typeof value === "number") && !EMPTY_VALUES.has(String(value).trim().toLowerCase());
const first = (...values: unknown[]) => values.find(usable);

export const buildNetworkOverview = (vendors: VendorData[]): NetworkOverviewItem[] => {
  const data = (name: string) => vendors.find((vendor) => vendor.name === name && !vendor.error)?.data ?? {};
  const geo = data("IP Geolocation");
  const abuse = data("AbuseIPDB");
  const vt = data("VirusTotal");
  const shodan = data("Shodan");
  const censys = data("Censys");
  const candidates = [
    ["isp", "ISP", first(geo.ISP, abuse.ISP, shodan.ISP)],
    ["organization", "Organization", first(geo.Organization, shodan.Organization, vt["AS Owner"])],
    ["country", "Country", first(geo.Country, abuse.Country, vt.Country)],
    ["region", "Region", first(geo.Region)],
    ["city", "City", first(geo.City)],
    ["asn", "ASN/AS", first(geo.AS, abuse.ASN, shodan.ASN, censys.ASN, vt.ASN)],
    ["network", "Network", first(abuse["CIDR/Network"], vt.Network, censys["BGP Prefix"])],
  ] as const;
  return candidates.filter((entry) => usable(entry[2])).map(([key, label, value]) => ({ key, label, value: String(value) }));
};
