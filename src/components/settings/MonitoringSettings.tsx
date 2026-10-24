import { Rss } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import FeedSourcesManager from "@/components/FeedSourcesManager";
import { NewsVendorMonitoring } from "@/components/settings/NewsVendorMonitoring";
import { useLanguage } from "@/contexts/LanguageContext";

export function MonitoringSettings() {
  const { language } = useLanguage();
  const pt = language === "pt";

  return (
    <div className="space-y-4">
      <NewsVendorMonitoring />
      <Card className="rounded-sm shadow-none">
        <CardHeader className="p-4 pb-3">
          <CardTitle className="flex items-center gap-2 text-sm"><Rss className="h-4 w-4 text-muted-foreground" /> {pt ? "Fontes de notícias" : "News sources"}</CardTitle>
          <CardDescription>
            {pt ? "RSS/Atom e páginas de publicações da coleta. Edição restrita a administradores." : "RSS/Atom feeds and publication pages. Editing is restricted to administrators."}
          </CardDescription>
        </CardHeader>
        <CardContent className="px-4 pb-4"><FeedSourcesManager /></CardContent>
      </Card>
    </div>
  );
}
