import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ExternalLink } from "lucide-react";
import { ReactNode } from "react";

interface VendorCardProps {
  title: string;
  description?: string;
  children: ReactNode;
  externalLink?: string;
  icon?: ReactNode;
}

export const VendorCard = ({ title, description, children, externalLink, icon }: VendorCardProps) => {
  return (
    <Card className="flex flex-col break-inside-avoid mb-4 border-2 shadow-md hover: hover:scale-[1.02] transition-all duration-200 animate-fade-in">
      <CardHeader>
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-2">
            {icon}
            <div>
              <CardTitle className="text-lg">{title}</CardTitle>
              {description && <CardDescription className="mt-1">{description}</CardDescription>}
            </div>
          </div>
          {externalLink && (
            <Button variant="ghost" size="sm" asChild className="hover-scale">
              <a href={externalLink} target="_blank" rel="noopener noreferrer">
                <ExternalLink className="h-4 w-4" />
              </a>
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
};
