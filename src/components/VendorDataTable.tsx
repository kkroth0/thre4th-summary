import { useState } from "react";
import { VendorData } from "@/types/threat-intelligence";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ArrowUpDown, Search, ExternalLink, ShieldAlert, Network, Globe, Activity, Cpu } from "lucide-react";

// ── Category Mapping ──
// Each vendor data field is mapped to a logical category for grouped rendering.
export const FIELD_CATEGORIES: Record<string, { label: string; icon: typeof ShieldAlert; iconColor: string }> = {
  "Threat / Heuristics": { label: "Threat / Heuristics", icon: ShieldAlert, iconColor: "text-destructive" },
  "Network / IT": { label: "Network / IT", icon: Network, iconColor: "text-primary" },
  "Geo / Location": { label: "Geo / Location", icon: Globe, iconColor: "text-primary/70" },
  "Reputation / Intel": { label: "Reputation / Intel", icon: Activity, iconColor: "text-primary/80" },
  "Network Providers": { label: "Network Providers", icon: Cpu, iconColor: "text-primary/60" },
};

const THREAT_FIELDS = new Set([
  "Detection Rate", "Malicious", "Suspicious", "Undetected", "Harmless",
  "Top Detections", "Abuse Confidence Score", "Total Reports", "Distinct Reporters",
  "Risk", "Verdict", "Threat Score", "AV Detect", "Score", "Issues",
  "Detected AVs", "Latest Score", "Pulse Count", "Records Found", "Matches",
  "URL Count", "Threat Type",
]);

const NETWORK_FIELDS = new Set([
  "Open Ports", "Total Ports", "Services", "ASN", "CIDR", "CIDR/Network",
  "Domain", "Hostnames", "Domains", "Organization", "Registrar",
  "Tags", "Feeds", "Sections", "OS", "File Name", "File Size",
  "File Type", "Signature",
]);

const GEO_FIELDS = new Set([
  "Country", "Region", "City", "ZIP Code", "Timezone",
  "Proxy/VPN", "Hosting", "Mobile", "Is Public", "Is Whitelisted", "Usage Type",
]);

const REPUTATION_FIELDS = new Set([
  "Reputation", "Pulses", "Status", "Verified",
  "Last Report", "Last Analysis", "Last Update",
  "Created", "Expires", "Discovered", "Group",
]);

const PROVIDER_FIELDS = new Set([
  "ISP", "AS Owner", "AS", "Network",
]);

export const getFieldCategory = (key: string): string => {
  if (THREAT_FIELDS.has(key)) return "Threat / Heuristics";
  if (NETWORK_FIELDS.has(key)) return "Network / IT";
  if (GEO_FIELDS.has(key)) return "Geo / Location";
  if (REPUTATION_FIELDS.has(key)) return "Reputation / Intel";
  if (PROVIDER_FIELDS.has(key)) return "Network Providers";
  return "Reputation / Intel"; // Default fallback
};

// ── Risk-aware value coloring ──
const RISK_POSITIVE_KEYWORDS = ["malicious", "unsafe", "phishing", "suspicious", "found", "yes ⚠️", "verified phishing"];
const CLEAN_KEYWORDS = ["clean", "safe", "no", "none", "0", "0 cves", "0 pulses", "not found", "no data"];

const getValueColor = (key: string, value: string): string => {
  const lower = value.toLowerCase().trim();

  // Threat fields with positive detections → red
  if (THREAT_FIELDS.has(key)) {
    // Detection rates like "5/92" → red if numerator > 0
    const rateMatch = lower.match(/^(\d+)\s*\/\s*\d+/);
    if (rateMatch && parseInt(rateMatch[1]) > 0) return "text-destructive font-semibold";

    // Percentage scores > 50
    const pctMatch = lower.match(/^(\d+)%/);
    if (pctMatch && parseInt(pctMatch[1]) > 50) return "text-destructive font-semibold";

    // Numeric scores > 0 for pure numbers
    if (/^\d+$/.test(lower) && parseInt(lower) > 0 && key !== "Harmless" && key !== "Undetected") return "text-destructive font-semibold";

    if (RISK_POSITIVE_KEYWORDS.some(kw => lower.includes(kw))) return "text-destructive font-semibold";
    if (CLEAN_KEYWORDS.some(kw => lower === kw)) return "text-green-600 dark:text-green-400";
  }

  // Status field special handling
  if (key === "Status") {
    if (RISK_POSITIVE_KEYWORDS.some(kw => lower.includes(kw))) return "text-destructive font-semibold";
    if (lower === "clean" || lower === "safe") return "text-green-600 dark:text-green-400";
  }

  // Proxy/VPN "Yes" = warning
  if (key === "Proxy/VPN" && lower.includes("yes")) return "text-destructive font-semibold";

  return "text-foreground";
};

interface VendorDataTableProps {
  vendorData: VendorData[];
  getVendorLink?: (name: string) => string | undefined;
}

type SortField = "name" | "status" | "dataCount";
type SortOrder = "asc" | "desc";

export const VendorDataTable = ({ vendorData, getVendorLink }: VendorDataTableProps) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [sortField, setSortField] = useState<SortField>("name");
  const [sortOrder, setSortOrder] = useState<SortOrder>("asc");

  const getStatus = (vendor: VendorData) => {
    if (vendor.error) return "error";
    if (Object.keys(vendor.data).length === 0) return "no-data";
    const status = vendor.data["Status"];
    if (typeof status === "string") {
      if (status.toLowerCase().includes("malicious")) return "malicious";
      if (status.toLowerCase().includes("suspicious")) return "suspicious";
    }
    return "clean";
  };

  const getStatusBadge = (status: string) => {
    const variants = {
      error: { variant: "destructive" as const, label: "Error" },
      "no-data": { variant: "secondary" as const, label: "No Data" },
      malicious: { variant: "destructive" as const, label: "Malicious" },
      suspicious: { variant: "outline" as const, label: "Suspicious" },
      clean: { variant: "default" as const, label: "Clean" },
    };
    const config = variants[status as keyof typeof variants] || variants.clean;
    return <Badge variant={config.variant}>{config.label}</Badge>;
  };

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortOrder("asc");
    }
  };

  const filteredAndSorted = vendorData
    .filter(vendor => 
      vendor.name.toLowerCase().includes(searchTerm.toLowerCase())
    )
    .sort((a, b) => {
      let compareValue = 0;
      if (sortField === "name") {
        compareValue = a.name.localeCompare(b.name);
      } else if (sortField === "status") {
        compareValue = getStatus(a).localeCompare(getStatus(b));
      } else if (sortField === "dataCount") {
        compareValue = Object.keys(a.data).length - Object.keys(b.data).length;
      }
      return sortOrder === "asc" ? compareValue : -compareValue;
    });

  const HIDDEN_KEYS = new Set(["Status", "Reports", "All Vendors", "Hostnames"]);

  const renderCategorizedFields = (vendor: VendorData) => {
    if (vendor.error) return <span className="text-destructive font-medium">{vendor.error}</span>;
    if (!vendor.data || Object.keys(vendor.data).length === 0) return <span className="text-muted-foreground">No data available</span>;

    const renderValue = (val: any): string => {
      if (Array.isArray(val)) return val.slice(0, 5).map(v => typeof v === 'object' ? v.engine || v.name || JSON.stringify(v) : v).join(", ");
      if (typeof val === 'object') return JSON.stringify(val).substring(0, 80);
      return String(val);
    };

    // Group fields by category
    const grouped: Record<string, { key: string; value: string }[]> = {};
    const categoryOrder = ["Threat / Heuristics", "Network / IT", "Geo / Location", "Network Providers", "Reputation / Intel"];

    Object.entries(vendor.data)
      .filter(([k]) => !HIDDEN_KEYS.has(k))
      .forEach(([key, val]) => {
        const valueStr = renderValue(val);
        if (!valueStr || valueStr === "None" || valueStr === "Unknown" || valueStr === "0" || valueStr === "N/A") return;

        const category = getFieldCategory(key);
        if (!grouped[category]) grouped[category] = [];
        grouped[category].push({ key, value: valueStr });
      });

    // Filter to only categories with data
    const activeCategories = categoryOrder.filter(cat => grouped[cat]?.length > 0);

    if (activeCategories.length === 0) return <span className="text-muted-foreground">No notable findings</span>;

    return (
      <div className="flex flex-col gap-3 w-full">
        {activeCategories.map(catName => {
          const config = FIELD_CATEGORIES[catName];
          const Icon = config.icon;
          const fields = grouped[catName];

          return (
            <div key={catName} className="rounded-lg border border-border/40 overflow-hidden">
              {/* Category header */}
              <div className="flex items-center gap-1.5 px-2.5 py-1 bg-muted/30 border-b border-border/20">
                <Icon className={`h-3 w-3 ${config.iconColor} opacity-70 flex-shrink-0`} />
                <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                  {config.label}
                </span>
              </div>
              {/* Category fields */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-0.5 px-2.5 py-1.5">
                {fields.map((field, idx) => (
                  <div key={idx} className="flex items-baseline gap-1.5 py-0.5 min-w-0">
                    <span className="text-[10px] font-medium text-muted-foreground/80 uppercase tracking-wider whitespace-nowrap flex-shrink-0">
                      {field.key}:
                    </span>
                    <span
                      className={`text-xs font-medium break-words line-clamp-1 ${getValueColor(field.key, field.value)}`}
                      title={field.value}
                    >
                      {field.value}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    );
  };

  return (
    <Card className="p-6 animate-fade-in">
      <div className="mb-4 flex items-center gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search vendors..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-9"
          />
        </div>
        <Badge variant="outline">{filteredAndSorted.length} vendors</Badge>
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>
                <Button variant="ghost" onClick={() => handleSort("name")} className="h-8 px-2 hover:bg-muted/50">
                  Vendor
                  <ArrowUpDown className="ml-2 h-4 w-4" />
                </Button>
              </TableHead>
              <TableHead>
                <Button variant="ghost" onClick={() => handleSort("status")} className="h-8 px-2 hover:bg-muted/50">
                  Status
                  <ArrowUpDown className="ml-2 h-4 w-4" />
                </Button>
              </TableHead>
              <TableHead>
                <Button variant="ghost" onClick={() => handleSort("dataCount")} className="h-8 px-2 hover:bg-muted/50">
                  Data Points
                  <ArrowUpDown className="ml-2 h-4 w-4" />
                </Button>
              </TableHead>
              <TableHead className="w-full">Detailed Analysis</TableHead>
              <TableHead className="text-right">Link</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredAndSorted.map((vendor) => {
              const status = getStatus(vendor);
              const link = getVendorLink?.(vendor.name);
              return (
                <TableRow key={vendor.name} className="hover:bg-muted/50 transition-colors align-top">
                  <TableCell className="font-medium">{vendor.name}</TableCell>
                  <TableCell>{getStatusBadge(status)}</TableCell>
                  <TableCell>
                    <Badge variant="secondary">{Object.keys(vendor.data).length}</Badge>
                  </TableCell>
                  <TableCell className="w-full py-4">
                    {renderCategorizedFields(vendor)}
                  </TableCell>
                  <TableCell>
                    {link && (
                      <Button variant="ghost" size="sm" asChild>
                        <a href={link} target="_blank" rel="noopener noreferrer">
                          <ExternalLink className="h-4 w-4" />
                        </a>
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
    </Card>
  );
};
