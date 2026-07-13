export const SUPPORTED_VENDORS = Object.freeze([
  "IP Geolocation", "WHOIS", "VirusTotal", "AbuseIPDB", "AlienVault OTX",
  "Shodan", "URLhaus", "MalwareBazaar", "ThreatFox", "Google Safe Browsing",
  "PhishTank", "Pulsedive", "Hybrid Analysis", "CIRCL hashlookup",
  "MetaDefender", "PhishStats", "Ransomware.live", "OpenPhish", "Team Cymru", "Censys",
] as const);

export const normalizeVendorSelection = (saved: unknown): string[] => {
  if (!Array.isArray(saved)) return [...SUPPORTED_VENDORS];
  const allowed = new Set<string>(SUPPORTED_VENDORS);
  return saved.filter((name): name is string => typeof name === "string" && allowed.has(name));
};
