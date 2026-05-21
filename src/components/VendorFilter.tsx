import { useState } from "react";
import { Check, Filter, X, Sparkles, Key } from "lucide-react";
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

interface VendorConfig {
    name: string;
    free: boolean;
    supportsIP: boolean;
    supportsDomain: boolean;
    supportsHash: boolean;
}

const VENDOR_LIST: VendorConfig[] = [
    { name: "IP Geolocation", free: true, supportsIP: true, supportsDomain: false, supportsHash: false },
    { name: "WHOIS", free: true, supportsIP: false, supportsDomain: true, supportsHash: false },
    { name: "VirusTotal", free: false, supportsIP: true, supportsDomain: true, supportsHash: true },
    { name: "AbuseIPDB", free: false, supportsIP: true, supportsDomain: false, supportsHash: false },
    { name: "AlienVault OTX", free: true, supportsIP: true, supportsDomain: true, supportsHash: true },
    { name: "Shodan", free: false, supportsIP: true, supportsDomain: false, supportsHash: false },
    { name: "URLhaus", free: true, supportsIP: false, supportsDomain: true, supportsHash: false },
    { name: "ThreatFox", free: true, supportsIP: true, supportsDomain: true, supportsHash: true },
    { name: "MalwareBazaar", free: true, supportsIP: false, supportsDomain: false, supportsHash: true },
    { name: "Google Safe Browsing", free: false, supportsIP: true, supportsDomain: true, supportsHash: false },
    { name: "PhishTank", free: true, supportsIP: false, supportsDomain: true, supportsHash: false },
    { name: "Pulsedive", free: true, supportsIP: true, supportsDomain: true, supportsHash: true },
    { name: "ThreatCrowd", free: true, supportsIP: true, supportsDomain: true, supportsHash: false },
    { name: "Censys", free: false, supportsIP: true, supportsDomain: false, supportsHash: false },
    { name: "Hybrid Analysis", free: false, supportsIP: false, supportsDomain: false, supportsHash: true },
    { name: "CIRCL hashlookup", free: true, supportsIP: false, supportsDomain: false, supportsHash: true },
    { name: "Criminal IP", free: false, supportsIP: true, supportsDomain: true, supportsHash: false },
    { name: "MetaDefender", free: false, supportsIP: true, supportsDomain: false, supportsHash: true },
    { name: "PhishStats", free: true, supportsIP: false, supportsDomain: true, supportsHash: false },
    { name: "Ransomware.live", free: true, supportsIP: false, supportsDomain: true, supportsHash: false },
    { name: "Spamhaus", free: true, supportsIP: true, supportsDomain: true, supportsHash: false },
    { name: "Blocklist.de", free: true, supportsIP: true, supportsDomain: false, supportsHash: false },
    { name: "OpenPhish", free: true, supportsIP: false, supportsDomain: true, supportsHash: false },
    { name: "DShield", free: true, supportsIP: true, supportsDomain: false, supportsHash: false },
    { name: "Team Cymru", free: true, supportsIP: true, supportsDomain: false, supportsHash: true },
];

interface VendorFilterProps {
    selectedVendors: string[];
    onVendorsChange: (vendors: string[]) => void;
}

export function VendorFilter({ selectedVendors, onVendorsChange }: VendorFilterProps) {
    const [tempSelected, setTempSelected] = useState<string[]>(selectedVendors);
    const [open, setOpen] = useState(false);

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
                <Button variant="outline" size="sm" className="h-8 rounded-full border border-primary/20 hover:bg-primary/10 shadow-sm transition-colors px-3">
                    <Filter className="h-4 w-4 sm:mr-2" />
                    <span className="hidden sm:inline">Filter Vendors </span>
                    <span className="text-[10px] bg-primary/10 text-primary px-1.5 py-0.5 rounded-full ml-1 sm:ml-0 font-bold border border-primary/15 font-mono">
                        {selectedVendors.length}
                    </span>
                </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl">
                <DialogHeader>
                    <DialogTitle>Select Threat Intelligence Vendors</DialogTitle>
                    <DialogDescription>
                        Choose which vendors to query. Selected vendors are saved automatically.
                    </DialogDescription>
                </DialogHeader>

                <div className="space-y-3">
                    <div>
                        <p className="text-sm font-medium mb-2">Quick Select:</p>
                        <div className="flex flex-wrap gap-2">
                            <Button type="button" onClick={handleSelectAll} variant="outline" size="sm">
                                <Check className="mr-2 h-4 w-4" /> Select All
                            </Button>
                            <Button type="button" onClick={handleDeselectAll} variant="outline" size="sm">
                                <X className="mr-2 h-4 w-4" /> Deselect All
                            </Button>
                            <Button type="button" onClick={handleSelectFree} variant="outline" size="sm" className="text-green-600">
                                <Sparkles className="mr-2 h-4 w-4" /> Only Free ({freeVendors.length})
                            </Button>
                            <Button type="button" onClick={handleSelectPaid} variant="outline" size="sm" className="text-orange-600">
                                <Key className="mr-2 h-4 w-4" /> Only Paid ({paidVendors.length})
                            </Button>
                        </div>
                    </div>
                </div>

                <ScrollArea className="h-[300px] pr-4 my-4">
                    <div className="space-y-6">
                        <div>
                            <h3 className="font-semibold mb-3 text-green-600">✓ Free APIs ({freeVendors.length})</h3>
                            <div className="grid grid-cols-2 gap-3">
                                {freeVendors.map((vendor) => (
                                    <div key={vendor.name} className="flex items-start space-x-2">
                                        <Checkbox
                                            id={vendor.name}
                                            checked={tempSelected.includes(vendor.name)}
                                            onCheckedChange={() => handleToggle(vendor.name)}
                                        />
                                        <div className="flex flex-col">
                                            <label
                                                htmlFor={vendor.name}
                                                className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 cursor-pointer"
                                            >
                                                {vendor.name}
                                            </label>
                                            <span className="text-xs text-muted-foreground">
                                                {[
                                                    vendor.supportsIP && "IP",
                                                    vendor.supportsDomain && "Domain",
                                                    vendor.supportsHash && "Hash"
                                                ].filter(Boolean).join(", ")}
                                            </span>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div>
                            <h3 className="font-semibold mb-3 text-orange-600">🔑 Requires API Key ({paidVendors.length})</h3>
                            <div className="grid grid-cols-2 gap-3">
                                {paidVendors.map((vendor) => (
                                    <div key={vendor.name} className="flex items-start space-x-2">
                                        <Checkbox
                                            id={vendor.name}
                                            checked={tempSelected.includes(vendor.name)}
                                            onCheckedChange={() => handleToggle(vendor.name)}
                                        />
                                        <div className="flex flex-col">
                                            <label
                                                htmlFor={vendor.name}
                                                className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 cursor-pointer"
                                            >
                                                {vendor.name}
                                            </label>
                                            <span className="text-xs text-muted-foreground">
                                                {[
                                                    vendor.supportsIP && "IP",
                                                    vendor.supportsDomain && "Domain",
                                                    vendor.supportsHash && "Hash"
                                                ].filter(Boolean).join(", ")}
                                            </span>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </ScrollArea>

                <div className="flex justify-end gap-2 pt-4">
                    <Button type="button" variant="outline" onClick={() => setOpen(false)}>
                        Cancel
                    </Button>
                    <Button type="button" onClick={handleApply}>
                        Apply ({tempSelected.length} selected)
                    </Button>
                </div>
            </DialogContent>
        </Dialog>
    );
}
