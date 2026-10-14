import { useState, useEffect } from "react";
import { Check, Filter, X, Sparkles, Key, ShieldCheck, Lock } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog";
import { Checkbox } from "@/components/ui/checkbox";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { SUPPORTED_VENDORS } from "@/config/vendorCatalog";

interface VendorConfig {
    name: string;
    free: boolean;
    supportsIP: boolean;
    supportsDomain: boolean;
    supportsHash: boolean;
}

const VENDOR_OPTIONS: VendorConfig[] = [
    { name: "IP Geolocation", free: true, supportsIP: true, supportsDomain: false, supportsHash: false },
    { name: "WHOIS", free: true, supportsIP: false, supportsDomain: true, supportsHash: false },
    { name: "VirusTotal", free: false, supportsIP: true, supportsDomain: true, supportsHash: true },
    { name: "AbuseIPDB", free: false, supportsIP: true, supportsDomain: false, supportsHash: false },
    { name: "AlienVault OTX", free: true, supportsIP: true, supportsDomain: true, supportsHash: true },
    { name: "Shodan", free: false, supportsIP: true, supportsDomain: true, supportsHash: false },
    { name: "URLhaus", free: true, supportsIP: true, supportsDomain: true, supportsHash: true },
    { name: "ThreatFox", free: true, supportsIP: true, supportsDomain: true, supportsHash: true },
    { name: "MalwareBazaar", free: true, supportsIP: false, supportsDomain: false, supportsHash: true },
    { name: "PhishTank", free: true, supportsIP: false, supportsDomain: true, supportsHash: false },
    { name: "ThreatCrowd", free: true, supportsIP: true, supportsDomain: true, supportsHash: false },
    { name: "PhishStats", free: true, supportsIP: false, supportsDomain: true, supportsHash: false },
    { name: "Spamhaus", free: true, supportsIP: true, supportsDomain: true, supportsHash: false },
    { name: "Blocklist.de", free: true, supportsIP: true, supportsDomain: false, supportsHash: false },
    { name: "OpenPhish", free: true, supportsIP: false, supportsDomain: true, supportsHash: false },
];

const VENDOR_LIST = VENDOR_OPTIONS.filter((vendor) => (SUPPORTED_VENDORS as readonly string[]).includes(vendor.name));

interface VendorFilterProps {
    selectedVendors: string[];
    onVendorsChange: (vendors: string[]) => void;
    className?: string;
}

export function VendorFilter({ selectedVendors, onVendorsChange, className }: VendorFilterProps) {
    const [tempSelected, setTempSelected] = useState<string[]>(selectedVendors);
    const [open, setOpen] = useState(false);

    // Sync tempSelected with selectedVendors when dialog opens
    useEffect(() => {
        if (open) {
            setTempSelected(selectedVendors);
        }
    }, [open, selectedVendors]);

    const handleToggle = (vendorName: string) => {
        setTempSelected(prev =>
            prev.includes(vendorName)
                ? prev.filter(v => v !== vendorName)
                : [...prev, vendorName]
        );
    };

    const handleSelectAll = () => {
        setTempSelected(VENDOR_LIST.map(v => v.name));
    };

    const handleDeselectAll = () => {
        setTempSelected([]);
    };

    const handleSelectFree = () => {
        setTempSelected(VENDOR_LIST.filter(v => v.free).map(v => v.name));
    };

    const handleSelectPaid = () => {
        setTempSelected(VENDOR_LIST.filter(v => !v.free).map(v => v.name));
    };

    const handleApply = (e?: React.MouseEvent) => {
        if (e) {
            e.preventDefault();
            e.stopPropagation();
        }
        onVendorsChange(tempSelected);
        localStorage.setItem("selectedVendors", JSON.stringify(tempSelected));
        setOpen(false);
    };

    const freeVendors = VENDOR_LIST.filter(v => v.free);
    const paidVendors = VENDOR_LIST.filter(v => !v.free);

    return (
        <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
                <Button 
                    variant="ghost" 
                    size="sm" 
                    className={cn(
                        "h-9 rounded-full hover:bg-white/5 transition-all px-3 group text-slate-400 hover:text-white shadow-none border-0", 
                        className
                    )}
                >
                    <Filter className="h-3.5 w-3.5 mr-1.5 text-slate-400 group-hover:text-white transition-colors" />
                    <span className="text-xs font-semibold">Filter Vendors</span>
                    <span className="text-[10px] bg-slate-900 text-slate-200 px-2 py-0.5 rounded-full ml-2 font-bold border border-slate-800 font-mono shadow-inner">
                        {selectedVendors.length}
                    </span>
                </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl bg-background/95  border-border/50 shadow-2xl rounded-lg p-4 sm:p-5">
                <DialogHeader className="space-y-0.5">
                    <DialogTitle className="text-lg sm:text-xl font-bold tracking-tight flex items-center gap-2">
                        <span>Select Threat Intelligence Vendors</span>
                        <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-primary/10 text-primary border border-border/50 font-mono">
                            {tempSelected.length} / {VENDOR_LIST.length} active
                        </span>
                    </DialogTitle>
                    <DialogDescription className="text-xs text-muted-foreground/90">
                        Choose which vendors to query. Selected vendors are saved automatically.
                    </DialogDescription>
                </DialogHeader>

                <div className="bg-muted/10 border border-border/50 p-3.5 rounded-lg space-y-2 mt-1.5 animate-fade-in">
                    <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground/80">Quick Selection Tools</p>
                    <div className="flex flex-wrap gap-2">
                        <Button 
                            type="button" 
                            onClick={handleSelectAll} 
                            variant="outline" 
                            size="sm"
                            className="rounded-full h-8.5 text-xs px-3.5 border-border/50 hover:bg-primary/5 hover:text-foreground transition-all"
                        >
                            <Check className="mr-1.5 h-3.5 w-3.5" /> Select All
                        </Button>
                        <Button 
                            type="button" 
                            onClick={handleDeselectAll} 
                            variant="outline" 
                            size="sm"
                            className="rounded-full h-8.5 text-xs px-3.5 border-border/50 hover:bg-primary/5 hover:text-foreground transition-all"
                        >
                            <X className="mr-1.5 h-3.5 w-3.5" /> Deselect All
                        </Button>
                        <Button 
                            type="button" 
                            onClick={handleSelectFree} 
                            variant="outline" 
                            size="sm" 
                            className="rounded-full h-8.5 text-xs px-3.5 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/20 transition-all font-semibold"
                        >
                            <Sparkles className="mr-1.5 h-3.5 w-3.5" /> Only Free ({freeVendors.length})
                        </Button>
                        <Button 
                            type="button" 
                            onClick={handleSelectPaid} 
                            variant="outline" 
                            size="sm" 
                            className="rounded-full h-8.5 text-xs px-3.5 bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 border border-amber-500/20 transition-all font-semibold"
                        >
                            <Key className="mr-1.5 h-3.5 w-3.5" /> Only Paid ({paidVendors.length})
                        </Button>
                    </div>
                </div>

                <ScrollArea className="h-[40vh] max-h-[300px] min-h-[160px] pr-3 my-3.5 border-y border-border/50 py-4">
                    <div className="space-y-6">
                        <div>
                            <div className="flex items-center gap-2 mb-4 border-b border-border/50 pb-2.5">
                                <ShieldCheck className="h-4.5 w-4.5 text-emerald-400" />
                                <span className="text-sm font-semibold tracking-wide uppercase text-emerald-400">Free APIs</span>
                                <span className="text-xs text-muted-foreground ml-auto bg-emerald-500/10 border border-emerald-500/20 px-2.5 py-0.5 rounded-full font-mono font-medium">{freeVendors.length} sources</span>
                            </div>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 sm:gap-2.5">
                                {freeVendors.map((vendor) => (
                                    <div
                                        key={vendor.name}
                                        role="checkbox"
                                        aria-checked={tempSelected.includes(vendor.name)}
                                        tabIndex={0}
                                        className={cn(
                                            "flex items-center justify-between py-2 px-3 rounded-lg border transition-all duration-200 cursor-pointer select-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50",
                                            tempSelected.includes(vendor.name)
                                                ? "bg-primary/10 border-border/50 hover:border-border/50 text-foreground shadow-sm shadow-primary/5"
                                                : "bg-muted/10 border-border/30 hover:border-border/60 hover:bg-muted/20 text-muted-foreground"
                                        )}
                                        onClick={() => handleToggle(vendor.name)}
                                        onKeyDown={(e) => {
                                            if (e.key === " " || e.key === "Enter") {
                                                e.preventDefault();
                                                handleToggle(vendor.name);
                                            }
                                        }}
                                    >
                                        <div className="flex items-center space-x-2.5 min-w-0 pointer-events-none">
                                            <Checkbox
                                                id={`vendor-${vendor.name}`}
                                                checked={tempSelected.includes(vendor.name)}
                                                className="h-4 w-4 border-muted-foreground/35 data-[state=checked]:bg-primary data-[state=checked]:border-primary"
                                            />
                                            <span className="text-xs font-semibold tracking-tight truncate">
                                                {vendor.name}
                                            </span>
                                        </div>
                                        <div className="flex items-center gap-1 shrink-0 ml-2 pointer-events-none">
                                            {vendor.supportsIP && (
                                                <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/10 font-semibold tracking-wider">IP</span>
                                            )}
                                            {vendor.supportsDomain && (
                                                <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/10 font-semibold tracking-wider font-mono">Domain</span>
                                            )}
                                            {vendor.supportsHash && (
                                                <span className="text-[9px] px-1.5 py-0.5 rounded bg-teal-500/10 text-teal-400 border border-teal-500/10 font-semibold tracking-wider font-mono">Hash</span>
                                            )}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div>
                            <div className="flex items-center gap-2 mb-4 border-b border-border/50 pb-2.5">
                                <Lock className="h-4.5 w-4.5 text-amber-400" />
                                <span className="text-sm font-semibold tracking-wide uppercase text-amber-400 font-medium">Requires API Key</span>
                                <span className="text-xs text-muted-foreground ml-auto bg-amber-500/10 border border-amber-500/20 px-2.5 py-0.5 rounded-full font-mono font-medium">{paidVendors.length} sources</span>
                            </div>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 sm:gap-2.5">
                                {paidVendors.map((vendor) => (
                                    <div
                                        key={vendor.name}
                                        role="checkbox"
                                        aria-checked={tempSelected.includes(vendor.name)}
                                        tabIndex={0}
                                        className={cn(
                                            "flex items-center justify-between py-2 px-3 rounded-lg border transition-all duration-200 cursor-pointer select-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50",
                                            tempSelected.includes(vendor.name)
                                                ? "bg-primary/10 border-border/50 hover:border-border/50 text-foreground shadow-sm shadow-primary/5"
                                                : "bg-muted/10 border-border/30 hover:border-border/60 hover:bg-muted/20 text-muted-foreground"
                                        )}
                                        onClick={() => handleToggle(vendor.name)}
                                        onKeyDown={(e) => {
                                            if (e.key === " " || e.key === "Enter") {
                                                e.preventDefault();
                                                handleToggle(vendor.name);
                                            }
                                        }}
                                    >
                                        <div className="flex items-center space-x-2.5 min-w-0 pointer-events-none">
                                            <Checkbox
                                                id={`vendor-${vendor.name}`}
                                                checked={tempSelected.includes(vendor.name)}
                                                className="h-4 w-4 border-muted-foreground/35 data-[state=checked]:bg-primary data-[state=checked]:border-primary"
                                            />
                                            <span className="text-xs font-semibold tracking-tight truncate">
                                                {vendor.name}
                                            </span>
                                        </div>
                                        <div className="flex items-center gap-1 shrink-0 ml-2 pointer-events-none">
                                            {vendor.supportsIP && (
                                                <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/10 font-semibold tracking-wider">IP</span>
                                            )}
                                            {vendor.supportsDomain && (
                                                <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/10 font-semibold tracking-wider font-mono">Domain</span>
                                            )}
                                            {vendor.supportsHash && (
                                                <span className="text-[9px] px-1.5 py-0.5 rounded bg-teal-500/10 text-teal-400 border border-teal-500/10 font-semibold tracking-wider font-mono">Hash</span>
                                            )}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </ScrollArea>

                <div className="flex justify-end gap-3 pt-4 border-t border-border/50">
                    <Button 
                        type="button" 
                        variant="ghost" 
                        onClick={() => setOpen(false)}
                        className="rounded-full px-5 hover:bg-primary/5 text-muted-foreground hover:text-foreground"
                    >
                        Cancel
                    </Button>
                    <Button 
                        type="button" 
                        onClick={handleApply}
                        className="rounded-full px-6 font-semibold bg-gradient-to-r from-primary to-primary/80 text-primary-foreground shadow-md hover: transition-all"
                    >
                        Apply Selection ({tempSelected.length})
                    </Button>
                </div>
            </DialogContent>
        </Dialog>
    );
}
