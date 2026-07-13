import { useEffect, useRef } from "react";
import { ArrowRight, Search, Upload } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useLanguage } from "@/contexts/LanguageContext";
import { useToast } from "@/hooks/use-toast";
import { extractIocsFromText, MAX_ANALYZER_TARGETS } from "@/utils/iocExtract";

interface SearchFormProps {
  query: string;
  setQuery: (query: string) => void;
  onSubmit: (e: React.FormEvent) => void;
  isLoading: boolean;
  className?: string;
  selectedVendors: string[];
  onVendorsChange: (vendors: string[]) => void;
}

export const SearchForm = ({
  query,
  setQuery,
  onSubmit,
  isLoading,
  className = "",
  selectedVendors,
  onVendorsChange,
}: SearchFormProps) => {
  const { t, language } = useLanguage();
  const { toast } = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const getExtractedIocs = () => {
    return extractIocsFromText(query);
  };

  const extractedIocs = getExtractedIocs();
  const hasMultipleLines = query.includes("\n") || extractedIocs.length > 1;

  // Keep textarea height fixed
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = "40px";
    }
  }, [query]);

  const handleLogFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      const reader = new FileReader();
      reader.onload = (event) => {
        if (event.target?.result) {
          const text = event.target.result as string;
          const allIocs = extractIocsFromText(text);

          if (allIocs.length > 0) {
            setQuery(allIocs.join("\n"));
            toast({
              title: language === "pt" ? "IOCs Extraídos" : "IOCs Extracted",
              description: language === "pt"
                ? `Extraídos ${allIocs.length} alvos únicos de ${file.name}. A análise roda ${MAX_ANALYZER_TARGETS} por vez.`
                : `Extracted ${allIocs.length} unique targets from ${file.name}. Analysis runs ${MAX_ANALYZER_TARGETS} at a time.`,
            });
          } else {
            toast({
              title: language === "pt" ? "Nenhum IOC Encontrado" : "No IOCs Found",
              description: language === "pt"
                ? "Não foi possível encontrar IPs, domínios, hashes ou CVEs válidos no arquivo."
                : "Could not find any valid IPs, domains, hashes, or CVEs in the file.",
              variant: "destructive"
            });
          }
        }
      };
      reader.readAsText(file);
      e.target.value = "";
    }
  };

  return (
    <div className={`w-full ${className}`}>
      <form onSubmit={onSubmit} className="w-full">
        <div className="space-y-3">
          {/* Search bar */}
          <div className="soc-panel relative mx-auto flex w-full max-w-2xl flex-row items-center gap-2 rounded-full p-1.5 pl-5 transition-all duration-500 hover:border-primary/30 focus-within:border-primary/45 focus-within:shadow-[0_18px_70px_-34px_hsl(var(--primary))]">

            {/* Search icon */}
            <div className="flex items-center shrink-0">
              <Search className="h-4 w-4 text-primary/75" />
            </div>

            {/* Unified textarea input */}
            <textarea
              ref={textareaRef}
              placeholder={language === "pt"
                ? "IP, dominio, URL, hash ou CVE..."
                : "IP, domain, URL, hash or CVE..."
              }
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              rows={1}
              wrap="off"
              className="h-10 min-w-0 flex-1 resize-none overflow-hidden whitespace-nowrap border-0 bg-transparent py-2.5 pl-2.5 text-[13px] leading-relaxed text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus-visible:ring-0 [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden"
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  onSubmit(e as any);
                }
              }}
            />

            {/* Actions row */}
            <div className="flex items-center gap-1.5 shrink-0 pr-0.5">
              {/* IOC count badge */}
              {extractedIocs.length > 1 && (
                <div className="flex items-center gap-1.5 rounded-full border border-primary/25 bg-primary/10 px-2.5 py-1 font-mono text-[10px] font-bold tracking-wide text-primary">
                  <div className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
                  {Math.min(extractedIocs.length, MAX_ANALYZER_TARGETS)}/{extractedIocs.length > MAX_ANALYZER_TARGETS ? extractedIocs.length : MAX_ANALYZER_TARGETS} IOCs
                </div>
              )}

              {/* File upload */}
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleLogFileUpload}
                accept=".txt,.log,.csv,.json"
                className="hidden"
              />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-muted-foreground transition-all duration-200 hover:bg-primary/10 hover:text-primary"
                title={language === "pt" ? "Enviar arquivo de log" : "Upload log file"}
              >
                <Upload className="h-4 w-4" />
              </button>

              {/* Submit */}
              <Button
                type="submit"
                disabled={isLoading || !query.trim()}
                size="icon"
                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full border-0 bg-primary text-primary-foreground shadow-lg shadow-primary/20 transition-all duration-200 hover:bg-primary/90 hover:shadow-primary/30 disabled:opacity-30 disabled:shadow-none"
                title={language === "pt" ? "Analisar" : "Analyze"}
              >
                {isLoading ? (
                  <div className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                ) : (
                  <ArrowRight className="h-4 w-4 text-white" />
                )}
              </Button>
            </div>
          </div>

          {/* Parsed IOCs preview — only when many targets */}
          {extractedIocs.length > 1 && (
            <div className="flex flex-wrap items-center justify-center gap-1.5 max-w-2xl mx-auto animate-fade-in">
              {extractedIocs.slice(0, MAX_ANALYZER_TARGETS).map(ioc => (
                <span key={ioc} className="inline-flex items-center rounded-md border border-primary/15 bg-primary/5 px-2 py-0.5 font-mono text-[10px] tracking-wide text-muted-foreground">
                  {ioc}
                </span>
              ))}
              {extractedIocs.length > MAX_ANALYZER_TARGETS && (
                <span className="text-[10px] text-slate-500 font-medium">
                  +{extractedIocs.length - MAX_ANALYZER_TARGETS} {language === "pt" ? "fora deste lote" : "outside this batch"}
                </span>
              )}
            </div>
          )}
        </div>
      </form>
    </div>
  );
};

