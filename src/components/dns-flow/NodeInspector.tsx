import {
  Globe, Shield, Server, Mail, Database, FileText, Link2, Info,
  Copy, ExternalLink, Activity, X, AlertCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { useLanguage } from "@/contexts/LanguageContext";
import { TYPE_COLORS } from "./DnsNodes";

interface NodeInspectorProps {
  node: { id: string; type: string; value: string; label: string; meta?: any } | null;
  whoisData: any;
  onPivotSearch: (ip: string) => void;
  onClose: () => void;
}

const typeIcon = (type: string) => {
  switch (type) {
    case "domain": return <Globe className="h-4 w-4" />;
    case "A": return <Shield className="h-4 w-4" />;
    case "AAAA": return <Server className="h-4 w-4" />;
    case "MX": return <Mail className="h-4 w-4" />;
    case "NS": return <Database className="h-4 w-4" />;
    case "TXT": return <FileText className="h-4 w-4" />;
    case "CNAME": return <Link2 className="h-4 w-4" />;
    case "Subdomain": return <Server className="h-4 w-4" />;
    default: return <Info className="h-4 w-4" />;
  }
};

const typeDescription = (type: string, lang: string) => {
  const descs: Record<string, { en: string; pt: string }> = {
    A: { en: "IPv4 address record — Maps the domain to a 32-bit IPv4 address.", pt: "Registro de endereço IPv4 — Mapeia o domínio para um endereço IPv4 de 32 bits." },
    AAAA: { en: "IPv6 address record — Maps the domain to a 128-bit IPv6 address.", pt: "Registro de endereço IPv6 — Mapeia o domínio para um endereço IPv6 de 128 bits." },
    MX: { en: "Mail Exchange record — Specifies the mail server responsible for email delivery.", pt: "Registro MX — Especifica o servidor de e-mail responsável pela entrega de e-mails." },
    NS: { en: "Name Server record — Delegates the DNS zone to authoritative name servers.", pt: "Registro NS — Delega a zona DNS para servidores de nomes autoritativos." },
    TXT: { en: "Text record — Contains verification data (SPF, DKIM, DMARC).", pt: "Registro TXT — Contém dados de verificação (SPF, DKIM, DMARC)." },
    CNAME: { en: "Canonical Name record — Maps an alias to a canonical domain name.", pt: "Registro CNAME — Mapeia um alias para um nome de domínio canônico." },
    Subdomain: { en: "Subdomain host record — Discovered passive DNS node.", pt: "Registro de subdomínio — Nó de DNS passivo descoberto." },
    domain: { en: "The queried domain root with WHOIS registration data.", pt: "O domínio raiz consultado com dados de registro WHOIS." },
  };
  return descs[type]?.[lang === "pt" ? "pt" : "en"] || "";
};

export function NodeInspector({ node, whoisData, onPivotSearch, onClose }: NodeInspectorProps) {
  const { toast } = useToast();
  const { language, tr } = useLanguage();

  if (!node) return null;

  const colors = TYPE_COLORS[node.type] || TYPE_COLORS["domain"];
  const isIp = node.type === "A" || node.type === "AAAA";

  const copy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: tr({ pt: "Copiado!", en: "Copied!", es: "¡Copiado!", fr: "Copié !" }), description: `${label} copied.` });
  };

  return (
    <div className="flex flex-col h-full animate-in slide-in-from-right-4 duration-300">
      {/* Header */}
      <div className={`relative px-4 pt-4 pb-3 border-b border-border/30`}>
        <div className={`absolute top-0 left-0 right-0 h-0.5 ${colors.dot}`} />
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <div className={`shrink-0 flex items-center justify-center h-8 w-8 rounded-lg ${colors.bg} ${colors.text} border ${colors.border}`}>
              {typeIcon(node.type)}
            </div>
            <div className="min-w-0">
              <Badge variant="outline" className={`text-[9px] font-bold uppercase mb-0.5 ${colors.text} border-current/30`}>
                {node.type} Record
              </Badge>
              <p className="text-sm font-bold font-mono break-all leading-tight text-foreground">{node.value}</p>
            </div>
          </div>
          <div className="flex items-center gap-1 shrink-0">
            <Button variant="ghost" size="icon" className="h-7 w-7 rounded-lg" onClick={() => copy(node.value, node.type)}>
              <Copy className="h-3 w-3" />
            </Button>
            <Button variant="ghost" size="icon" className="h-7 w-7 rounded-lg" onClick={onClose}>
              <X className="h-3 w-3" />
            </Button>
          </div>
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4">
        {/* Description */}
        <p className="text-[11px] text-muted-foreground/70 leading-relaxed">
          {typeDescription(node.type, language)}
        </p>

        {/* Pivot for IPs */}
        {isIp && (
          <div className={`rounded-xl p-3 border ${colors.border} ${colors.bg} space-y-2`}>
            <div className="text-xs font-bold text-foreground/90 flex items-center gap-1.5">
              <Activity className="h-3.5 w-3.5 text-primary" />
              {tr({ pt: "Pivot de Inteligência", en: "Threat Intel Pivot", es: "Pivote de Inteligencia", fr: "Pivot de Renseignement" })}
            </div>
            <p className="text-[10px] text-muted-foreground leading-normal">
              {tr({
                pt: "Cruzar este IP com VirusTotal, AbuseIPDB e Shodan.",
                en: "Cross-query this IP through VirusTotal, AbuseIPDB and Shodan.",
                es: "Cruzar esta IP con VirusTotal, AbuseIPDB y Shodan.",
                fr: "Croiser cette IP avec VirusTotal, AbuseIPDB et Shodan.",
              })}
            </p>
            <Button size="sm" className="w-full h-8 rounded-lg text-xs font-semibold gap-1.5" onClick={() => onPivotSearch(node.value)}>
              <ExternalLink className="h-3 w-3" />
              {tr({ pt: "Analisar Reputação", en: "Analyze Reputation", es: "Analizar Reputación", fr: "Analyser la Réputation" })}
            </Button>
          </div>
        )}

        {/* DNSDumpster Metadata for A Record */}
        {isIp && node.meta && (
          <div className="bg-muted/10 border border-border/30 rounded-xl p-3 space-y-2 text-xs">
            <div className="text-[9px] font-bold uppercase tracking-wider text-pink-400 mb-1">Network Intel (DNSDumpster)</div>
            {node.meta.asn_name && (
              <div>
                <span className="text-muted-foreground font-semibold">ASN Owner: </span>
                <span className="text-foreground/90">{node.meta.asn_name} (AS{node.meta.asn})</span>
              </div>
            )}
            {node.meta.country && (
              <div>
                <span className="text-muted-foreground font-semibold">Country: </span>
                <span className="text-foreground/90">{node.meta.country}</span>
              </div>
            )}
            {node.meta.ptr && (
              <div>
                <span className="text-muted-foreground font-semibold">PTR: </span>
                <span className="font-mono text-foreground/90 break-all">{node.meta.ptr}</span>
              </div>
            )}
            {/* Banners */}
            {node.meta.banners && Object.keys(node.meta.banners).length > 0 && (
              <div className="bg-background/40 rounded-lg p-2 mt-1 space-y-1.5 border border-border/20 text-[10px]">
                <span className="text-[8px] font-black uppercase text-muted-foreground/60 tracking-wider">Service Banners</span>
                {Object.entries(node.meta.banners).map(([proto, bannerObj]: [string, any]) => (
                  <div key={proto} className="font-mono space-y-0.5 border-b border-border/10 pb-1 last:border-0 last:pb-0">
                    <span className="text-[8px] text-pink-400 font-bold uppercase">{proto}</span>
                    {bannerObj.server && <div>Server: <span className="text-foreground/80">{bannerObj.server}</span></div>}
                    {bannerObj.title && <div>Title: <span className="text-foreground/80">{bannerObj.title}</span></div>}
                    {bannerObj.apps && Array.isArray(bannerObj.apps) && (
                      <div>Apps: <span className="text-foreground/80">{bannerObj.apps.join(', ')}</span></div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* DNSDumpster Subdomain node metadata */}
        {node.type === "Subdomain" && node.meta && (
          <div className="bg-muted/10 border border-border/30 rounded-xl p-3 space-y-2.5 text-xs">
            <div className="text-[9px] font-bold uppercase tracking-wider text-pink-400 mb-1">Resolved IPs</div>
            {node.meta.ips?.map((ipObj: any, idx: number) => (
              <div key={idx} className="border-b border-border/10 pb-2 last:border-0 last:pb-0 space-y-1">
                <div className="flex justify-between items-center">
                  <span className="font-mono text-foreground font-semibold">{ipObj.ip}</span>
                  {ipObj.country && <Badge variant="secondary" className="text-[9px] scale-90">{ipObj.country}</Badge>}
                </div>
                {ipObj.asn_name && <p className="text-[10px] text-muted-foreground leading-normal">{ipObj.asn_name} (AS{ipObj.asn})</p>}
                {ipObj.ptr && <p className="text-[9px] text-muted-foreground/60 font-mono">PTR: {ipObj.ptr}</p>}
                {/* Banners */}
                {ipObj.banners && Object.keys(ipObj.banners).length > 0 && (
                  <div className="bg-background/40 rounded-lg p-2 mt-1 space-y-1 border border-border/20 text-[10px]">
                    <span className="text-[8px] font-black uppercase text-muted-foreground/60 tracking-wider">Service Banners</span>
                    {Object.entries(ipObj.banners).map(([proto, bannerObj]: [string, any]) => (
                      <div key={proto} className="font-mono space-y-0.5 border-b border-border/10 pb-1 last:border-0 last:pb-0">
                        <span className="text-[8px] text-pink-400 font-bold uppercase">{proto}</span>
                        {bannerObj.server && <div>Server: <span className="text-foreground/80">{bannerObj.server}</span></div>}
                        {bannerObj.title && <div>Title: <span className="text-foreground/80">{bannerObj.title}</span></div>}
                        {bannerObj.apps && Array.isArray(bannerObj.apps) && (
                          <div>Apps: <span className="text-foreground/80">{bannerObj.apps.join(', ')}</span></div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* WHOIS data for domain */}
        {node.type === "domain" && whoisData && (
          <div className="space-y-2">
            <div className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground/60">WHOIS</div>
            <div className="bg-muted/10 border border-border/30 rounded-xl p-3 space-y-1.5 text-xs">
              {[
                ["Registrar", whoisData.registrarName],
                ["Created", whoisData.createdDate ? new Date(whoisData.createdDate).toLocaleDateString() : null],
                ["Expires", whoisData.expiresDate ? new Date(whoisData.expiresDate).toLocaleDateString() : null],
                ["Updated", whoisData.updatedDate ? new Date(whoisData.updatedDate).toLocaleDateString() : null],
                ["WHOIS Server", whoisData.whoisServer],
              ].filter(([, v]) => v).map(([k, v]) => (
                <div key={k as string} className="flex justify-between gap-2">
                  <span className="text-muted-foreground font-semibold shrink-0">{k}:</span>
                  <span className="font-mono text-foreground/80 text-right truncate">{v}</span>
                </div>
              ))}
            </div>
            {whoisData.registrant && (
              <div className="bg-muted/10 border border-border/30 rounded-xl p-3 space-y-1.5 text-xs">
                <div className="text-[9px] font-bold uppercase tracking-wider text-primary mb-1">Registrant</div>
                <div className="grid grid-cols-2 gap-1.5 text-[11px]">
                  {[
                    ["Org", whoisData.registrant.organization],
                    ["Country", whoisData.registrant.country],
                    ["State", whoisData.registrant.state],
                    ["City", whoisData.registrant.city],
                  ].filter(([, v]) => v).map(([k, v]) => (
                    <div key={k as string}>
                      <span className="text-muted-foreground/60">{k}: </span>
                      <span className="font-semibold text-foreground/80">{v}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Record value for non-domain, non-IP, non-Subdomain */}
        {!isIp && node.type !== "domain" && node.type !== "Subdomain" && (
          <div className="bg-muted/10 border border-border/30 rounded-xl p-3">
            <div className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground/60 mb-1.5">Value</div>
            <code className="text-[11px] font-mono text-foreground/80 break-all leading-relaxed block">{node.value}</code>
          </div>
        )}
      </div>
    </div>
  );
}
