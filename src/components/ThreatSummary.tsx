
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ThreatBadge } from "./ThreatBadge";
import { Copy, Download, Info } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { VendorData } from "@/types/threat-intelligence";
import { useLanguage } from "@/contexts/LanguageContext";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

interface ThreatSummaryProps {
  query: string;
  overallScore: number;
  threatLevel: "safe" | "suspicious" | "malicious" | "unknown";
  totalVendors: number;
  detections: number;
  vendorData?: VendorData[];
}

export const ThreatSummary = ({ query, overallScore, threatLevel, totalVendors, detections, vendorData = [] }: ThreatSummaryProps) => {
  const { toast } = useToast();
  const { t } = useLanguage();

  const formatVendorData = (vendor: VendorData): string => {
    let text = `\n${vendor.name}\n${'='.repeat(vendor.name.length)}\n`;
    Object.entries(vendor.data).forEach(([key, value]) => {
      if (typeof value === 'object' && !Array.isArray(value)) {
        text += `${key}:\n`;
        Object.entries(value).forEach(([subKey, subValue]) => {
          text += `  ${subKey}: ${subValue}\n`;
        });
      } else if (Array.isArray(value)) {
        text += `${key}: ${value.join(', ')}\n`;
      } else {
        text += `${key}: ${value}\n`;
      }
    });
    return text;
  };

  const handleCopy = () => {
    let fullReport = `THREAT INTELLIGENCE REPORT\n${'='.repeat(50)}\n\n`;
    fullReport += `Query: ${query}\n`;
    fullReport += `Overall Score: ${overallScore}/100\n`;
    fullReport += `Threat Level: ${threatLevel.toUpperCase()}\n`;
    fullReport += `Detections: ${detections}/${totalVendors} vendors\n`;
    fullReport += `Generated: ${new Date().toISOString()}\n`;
    fullReport += `\n${'='.repeat(50)}\n`;
    fullReport += `VENDOR DETAILS\n${'='.repeat(50)}`;

    vendorData.forEach(vendor => {
      fullReport += formatVendorData(vendor);
    });

    navigator.clipboard.writeText(fullReport);
    toast({
      title: t('copiedToClipboard'),
      description: t('reportCopied'),
    });
  };

  const handleExport = () => {
    toast({
      title: t('exportInitiated'),
      description: t('exportDesc'),
    });
  };

  return (
    <Card className="border-2">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span>{t('threatSummary')}</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div>
            <p className="text-sm text-muted-foreground mb-1">{t('query')}</p>
            <p className="font-mono font-semibold text-lg">{query}</p>
            {(() => {
              const abuseData = vendorData.find(v => v.name === "AbuseIPDB")?.data;
              const hostnames = abuseData?.["Hostnames"];
              const hostname = hostnames && hostnames !== "None" ? hostnames.split(",")[0] : null;

              if (hostname) {
                return (
                  <p className="text-xs text-muted-foreground truncate max-w-[200px]" title={hostname}>
                    {hostname}
                  </p>
                );
              }
              return null;
            })()}
          </div>
          <div>
            <p className="text-sm text-muted-foreground mb-1">{t('overallScore')}</p>
            <p className="text-3xl font-bold">{overallScore}/100</p>
          </div>
          <div className="flex flex-col">
          <div className="flex items-center gap-1">
            <span className="text-sm text-muted-foreground">{t('threatLevel')}</span>
            <Dialog>
              <DialogTrigger asChild>
                <Button variant="ghost" size="icon" className="h-4 w-4 rounded-full text-muted-foreground hover:text-foreground">
                  <Info className="h-3 w-3" />
                  <span className="sr-only">How Scoring Works</span>
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-md">
                <DialogHeader>
                  <DialogTitle>{t('threatLevelScoringMethodology')}</DialogTitle>
                </DialogHeader>
                <div className="space-y-4 text-sm mt-4">
                  <p>{t('threatEngineExplanation')}</p>
                  
                  <div className="space-y-2">
                    <h4 className="font-semibold border-b pb-1">{t('primaryVendorWeights')}</h4>
                    <ul className="space-y-1.5 list-disc pl-4 text-xs text-muted-foreground">
                      <li><strong className="text-foreground">VirusTotal:</strong> {t('vtWeightDesc')}</li>
                      <li><strong className="text-foreground">AbuseIPDB:</strong> {t('abuseIpdbWeightDesc')}</li>
                    </ul>
                  </div>

                  <div className="space-y-2">
                    <h4 className="font-semibold border-b pb-1">{t('scoringThresholds')}</h4>
                    <ul className="space-y-1.5 list-disc pl-4 text-xs text-muted-foreground">
                      <li><strong className="text-green-500">SAFE (0-30):</strong> {t('safeDesc')}</li>
                      <li><strong className="text-orange-500">SUSPICIOUS (31-70):</strong> {t('suspiciousDesc')}</li>
                      <li><strong className="text-red-500">MALICIOUS (71-100):</strong> {t('maliciousDesc')}</li>
                    </ul>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          </div>
            <ThreatBadge level={threatLevel} className="text-sm px-3 py-1 mt-1 w-fit" />
          </div>
          <div>
            <p className="text-sm text-muted-foreground mb-1">{t('detections')}</p>
            <p className="text-3xl font-bold">
              {detections}<span className="text-lg text-muted-foreground">/{totalVendors}</span>
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
