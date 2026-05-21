import { Clock, Trash2, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
    Sheet,
    SheetContent,
    SheetHeader,
    SheetTitle,
    SheetTrigger,
} from "@/components/ui/sheet";

interface HistoryItem {
    query: string;
    timestamp: number;
    threatLevel: "safe" | "suspicious" | "malicious" | "unknown";
}

interface HistorySidebarProps {
    history: HistoryItem[];
    onSelect: (query: string) => void;
    onClear: () => void;
}

export function HistorySidebar({ history, onSelect, onClear }: HistorySidebarProps) {
    const formatDate = (timestamp: number) => {
        return new Date(timestamp).toLocaleString();
    };

    const getLevelColor = (level: string) => {
        switch (level) {
            case "malicious": return "text-destructive";
            case "suspicious": return "text-orange-500";
            case "safe": return "text-green-500";
            default: return "text-muted-foreground";
        }
    };

    return (
        <Sheet>
            <SheetTrigger asChild>
                <Button variant="outline" className="h-8 w-8 rounded-full border border-primary/20 hover:bg-primary/10 px-0 shadow-sm transition-colors" title="History">
                    <Clock className="h-4 w-4" />
                </Button>
            </SheetTrigger>
            <SheetContent>
                <SheetHeader>
                    <SheetTitle className="flex items-center justify-between">
                        <span>Recent Searches</span>
                        {history.length > 0 && (
                            <Button variant="ghost" size="sm" onClick={onClear} className="h-8 px-2 text-muted-foreground hover:text-destructive">
                                <Trash2 className="h-4 w-4 mr-1" /> Clear
                            </Button>
                        )}
                    </SheetTitle>
                </SheetHeader>

                <ScrollArea className="h-[calc(100vh-100px)] mt-4 pr-4">
                    {history.length === 0 ? (
                        <div className="text-center text-muted-foreground py-8">
                            <Clock className="h-8 w-8 mx-auto mb-2 opacity-50" />
                            <p>No recent searches</p>
                        </div>
                    ) : (
                        <div className="space-y-2">
                            {history.map((item, index) => (
                                <button
                                    key={index}
                                    onClick={() => onSelect(item.query)}
                                    className="w-full flex flex-col items-start p-3 rounded-lg hover:bg-muted transition-colors border text-left group"
                                >
                                    <div className="flex items-center justify-between w-full mb-1">
                                        <span className="font-medium truncate max-w-[180px]">{item.query}</span>
                                        <span className={`text-xs capitalize ${getLevelColor(item.threatLevel)}`}>
                                            {item.threatLevel}
                                        </span>
                                    </div>
                                    <span className="text-xs text-muted-foreground flex items-center">
                                        {formatDate(item.timestamp)}
                                        <Search className="h-3 w-3 ml-2 opacity-0 group-hover:opacity-100 transition-opacity" />
                                    </span>
                                </button>
                            ))}
                        </div>
                    )}
                </ScrollArea>
            </SheetContent>
        </Sheet>
    );
}
