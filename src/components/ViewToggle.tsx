import { Button } from "@/components/ui/button";
import { LayoutGrid, Table, Share2 } from "lucide-react";

interface ViewToggleProps {
  view: "graph" | "cards" | "table";
  onViewChange: (view: "graph" | "cards" | "table") => void;
}

export const ViewToggle = ({ view, onViewChange }: ViewToggleProps) => {
  return (
    <div className="flex items-center gap-1 border rounded-lg p-1 bg-muted/50">
      <Button
        variant={view === "graph" ? "default" : "ghost"}
        size="sm"
        onClick={() => onViewChange("graph")}
        className="gap-2 h-8"
      >
        <Share2 className="h-4 w-4" />
        Graph
      </Button>
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
        variant={view === "table" ? "default" : "ghost"}
        size="sm"
        onClick={() => onViewChange("table")}
        className="gap-2 h-8"
      >
        <Table className="h-4 w-4" />
        Table
      </Button>
    </div>
  );
};
