import { Button } from "@/components/ui/button";
import { LayoutGrid, Share2 } from "lucide-react";

interface ViewToggleProps {
  view: "graph" | "cards";
  onViewChange: (view: "graph" | "cards") => void;
}

export const ViewToggle = ({ view, onViewChange }: ViewToggleProps) => {
  return (
    <div className="flex items-center gap-1 border rounded-lg p-1 bg-muted/50">
      <Button
        variant={view === "cards" ? "default" : "ghost"}
        size="sm"
        onClick={() => onViewChange("cards")}
        className="gap-2 h-8"
      >
        <LayoutGrid className="h-4 w-4" />
        Cards
      </Button>
      <Button
        variant={view === "graph" ? "default" : "ghost"}
        size="sm"
        onClick={() => onViewChange("graph")}
        className="gap-2 h-8"
      >
        <Share2 className="h-4 w-4" />
        Graph
      </Button>
    </div>
  );
};
