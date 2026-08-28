import React, { useState, useRef, useEffect } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, Globe, Shield, ShieldAlert, Mail, Eye, Sparkles, Filter, CheckCircle2, ChevronRight, Upload, AlertTriangle, FileText, Check, AlertCircle, RefreshCw, Terminal, ExternalLink, Copy, Loader2, ShieldCheck, Network, Hash, Image as ImageIcon, Download, FileJson, Search, Clock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from "@/components/ui/dropdown-menu";
import { PageLayout } from "@/components/PageLayout";
import { useLanguage } from "@/contexts/LanguageContext";
import { ThreatBadge } from "@/components/ThreatBadge";
import { toast } from "sonner";
import { fetchThreatDataProgressive } from "@/services/threatApi";
import type { ThreatIntelligenceResult } from "@/types/threat-intelligence";
import { defang, defangList } from "@/utils/defang";
import { detectTyposquat } from "@/utils/typosquat";
import { exportIOCsJSON, exportIOCsSTIX } from "@/utils/threatExport";
import { BrandHunt } from "@/components/phishing/BrandHunt";
import { PhishTickets } from "@/components/phishing/PhishTickets";

interface ScoreSignal {
  label: string;
  points: number;
  severity: "low" | "medium" | "high";
}

interface AttachmentItem {
  name: string;
  sizeKB: number;
  sha256?: string;
  risk: "low" | "medium" | "high";
}

interface ParsedEml {
  headers: Record<string, string>;
  subject: string;
  from: string;
  to: string;
  date: string;
  replyTo: string;
  returnPath: string;
  messageId: string;
  senderEmail: string;
  senderName: string;
  senderDomain: string;
  spf: string;
  dkim: string;
  dmarc: string;
  links: string[];
  attachments: AttachmentItem[];
  score: number;
  verdict: "safe" | "suspicious" | "malicious";
  signals: ScoreSignal[];
  alerts: string[];
  typosquat: { host: string; brand: string } | null;
  rawText: string;
}

const SAMPLE_PHISHING_EML = `From: "PayPal Security Support" <paypal-updates-billing@security-payment-alert.com>
To: target-user@victim-domain.com
Subject: URGENT: Your PayPal Account Has Been Suspended - Action Required
Date: Fri, 22 May 2026 14:23:45 -0400
Message-ID: <8427498274.92842.1287@security-payment-alert.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_NextPart_000_01C2_01C3"
Authentication-Results: mx.google.com; spf=fail (google.com: domain of security-payment-alert.com does not designate 192.0.2.1 as permitted sender) dkim=fail; dmarc=fail
Return-Path: <spoofed-bounce@malicious-redirect.org>
X-Mailer: PHPMailer 5.2.22

------=_NextPart_000_01C2_01C3
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: 7bit

<html>
<body>
  <h2>Dear Customer,</h2>
  <p>We detected unauthorized login attempts to your PayPal account from an unrecognized device in Russia.</p>
  <p><strong>To prevent account deletion and restore your balance access, you must immediately confirm your account:</strong></p>
  <p><a href="https://bit.ly/restore-paypal-login-redirect">Verify Your Identity Now</a></p>
  <p>If you do not complete this verification within 24 hours, your account will be permanently closed and any remaining funds will be withheld.</p>
  <p>Regards,<br>PayPal Billing Security Dept.</p>
</body>
</html>

------=_NextPart_000_01C2_01C3
Content-Type: application/octet-stream; name="invoice_details.exe"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="invoice_details.exe"

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
`;

const SAMPLE_SAFE_EML = `From: "GitHub Security" <noreply@github.com>
To: Mandrade <mandrade@dev-workspace.com>
Subject: [GitHub] Security Alert: New login detected from unknown browser
Date: Fri, 22 May 2026 10:11:12 -0000
Message-ID: <git-login-alert-98234@github.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Authentication-Results: mx.google.com; spf=pass (google.com: domain of noreply@github.com designates 192.30.252.20 as permitted sender) dkim=pass header.i=@github.com; dmarc=pass
Return-Path: <noreply@github.com>

<html>
<body>
  <h3>Hi Mandrade,</h3>
  <p>We noticed a new login to your GitHub account from a Linux device located in Brazil.</p>
  <p>If this was you, no action is needed. If you did not recognize this login, please change your password immediately.</p>
  <p><a href="https://github.com/settings/security">Review Security Settings</a></p>
  <p>Thanks,<br>The GitHub Team</p>
</body>
</html>
`;

// URL- and domain-capable providers used for live reputation enrichment.
const URL_VENDORS = ["VirusTotal", "URLhaus", "PhishTank", "OpenPhish", "PhishStats", "Pulsedive"];

// Extract attachment parts (name + decoded bytes) from a raw EML by walking the
// MIME boundary, so we can compute a real size + hash instead of guessing.
const extractAttachmentBytes = (rawText: string): { name: string; bytes: Uint8Array }[] => {
  const out: { name: string; bytes: Uint8Array }[] = [];
  const boundaryMatch = rawText.match(/boundary="?([^"\r\n;]+)"?/i);
  if (!boundaryMatch) return out;
  for (const part of rawText.split(`--${boundaryMatch[1]}`)) {
    if (!/content-disposition:\s*attachment/i.test(part)) continue;
    const nameMatch = part.match(/filename\*?="?([^"\r\n;]+)"?/i);
    if (!nameMatch) continue;
    const name = nameMatch[1].trim();
    const sepIdx = part.search(/\r?\n\r?\n/);
    if (sepIdx === -1) continue;
    let body = part.slice(sepIdx).trim();
    if (!/content-transfer-encoding:\s*base64/i.test(part)) {
      out.push({ name, bytes: new TextEncoder().encode(body) });
      continue;
    }
    body = body.replace(/\s+/g, "");
    try {
      const bin = atob(body);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      out.push({ name, bytes });
    } catch { /* undecodable part — skip */ }
  }
  return out;
};

const sha256Hex = async (bytes: Uint8Array): Promise<string> => {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
};

const attachmentRisk = (fileName: string): "low" | "medium" | "high" => {
  const ext = fileName.split(".").pop()?.toLowerCase() || "";
  if (["exe", "scr", "vbs", "js", "bat", "cmd", "msi", "jar", "ps1", "lnk"].includes(ext)) return "high";
  if (["zip", "rar", "7z", "pdf", "doc", "docx", "xls", "xlsx", "docm", "xlsm", "iso", "html"].includes(ext)) return "medium";
  return "low";
};

const PhishingAnalyzer = () => {
  const { t, language } = useLanguage();
  const [dragActive, setDragActive] = useState(false);
  const [parsedData, setParsedData] = useState<ParsedEml | null>(null);
  // A página tem dois trabalhos: analisar um e-mail que chegou, e caçar domínio
  // de phishing antes de ele chegar. As abas de dentro pertencem ao e-mail
  // analisado, então a troca de trabalho mora aqui em cima.
  const [mode, setMode] = useState<"eml" | "hunt" | "tickets">("eml");
  const [fileName, setFileName] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  // Live threat-intel enrichment (reuses the main scan engine).
  const [senderRep, setSenderRep] = useState<ThreatIntelligenceResult | null>(null);
  const [senderRepLoading, setSenderRepLoading] = useState(false);
  const [linkResults, setLinkResults] = useState<Record<string, ThreatIntelligenceResult | "loading">>({});
  const [copiedIocs, setCopiedIocs] = useState(false);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);

  // Core EML Parser Logic
  const parseEmlContent = (rawText: string, name: string) => {
    setFileName(name);
    
    // Split header block and body block
    const doubleNewlineIndex = rawText.search(/\r?\n\r?\n/);
    let headerText = "";
    let bodyText = "";
    
    if (doubleNewlineIndex !== -1) {
      headerText = rawText.substring(0, doubleNewlineIndex);
      bodyText = rawText.substring(doubleNewlineIndex).trim();
    } else {
      headerText = rawText;
    }
    
    // Parse Headers
    const headerLines = headerText.split(/\r?\n/);
    const headers: Record<string, string> = {};
    let currentKey = "";
    
    for (const line of headerLines) {
      if (/^\s/.test(line) && currentKey) {
        headers[currentKey] += " " + line.trim();
      } else {
        const match = line.match(/^([^:]+):\s*(.*)$/);
        if (match) {
          currentKey = match[1].toLowerCase();
          headers[currentKey] = match[2].trim();
        }
      }
    }
    
    // Extract key attributes
    const subject = headers["subject"] || "(No Subject)";
    const from = headers["from"] || "(Unknown Sender)";
    const to = headers["to"] || "(Unknown Recipient)";
    const date = headers["date"] || "(Unknown Date)";
    const replyTo = headers["reply-to"] || "";
    const returnPath = headers["return-path"] || "";
    const messageId = headers["message-id"] || "";
    const authenticationResults = headers["authentication-results"] || "";
    const xMailer = headers["x-mailer"] || "";
    
    // Sender Email details
    let senderEmail = "";
    let senderName = "";
    const fromMatch = from.match(/^(.*?)\s*<([^>]+)>/);
    if (fromMatch) {
      senderName = fromMatch[1].replace(/['"]/g, "").trim();
      senderEmail = fromMatch[2].trim();
    } else {
      senderEmail = from.replace(/['"]/g, "").trim();
    }
    
    // Parse authentication states (SPF, DKIM, DMARC)
    let spf = "unknown";
    let dkim = "unknown";
    let dmarc = "unknown";
    
    if (authenticationResults) {
      const authLower = authenticationResults.toLowerCase();
      if (authLower.includes("spf=pass")) spf = "pass";
      else if (authLower.includes("spf=fail")) spf = "fail";
      else if (authLower.includes("spf=softfail")) spf = "softfail";
      
      if (authLower.includes("dkim=pass")) dkim = "pass";
      else if (authLower.includes("dkim=fail")) dkim = "fail";
      
      if (authLower.includes("dmarc=pass")) dmarc = "pass";
      else if (authLower.includes("dmarc=fail")) dmarc = "fail";
    } else {
      const spfHeader = headers["received-spf"] || "";
      if (spfHeader) {
        if (spfHeader.toLowerCase().includes("pass")) spf = "pass";
        else if (spfHeader.toLowerCase().includes("fail")) spf = "fail";
      }
    }

    // Extract Links from body
    const urlRegex = /https?:\/\/[^\s"'<>\[\]]+/g;
    const linksFound: string[] = [];
    let match;
    while ((match = urlRegex.exec(bodyText)) !== null) {
      const url = match[0];
      const cleanUrl = url.replace(/[.,;:)\]]+$/, "");
      if (!linksFound.includes(cleanUrl)) {
        linksFound.push(cleanUrl);
      }
    }

    // Extract attachments with their real bytes so size + SHA-256 are genuine.
    const attachmentBytes = extractAttachmentBytes(rawText);
    const attachmentsFound: AttachmentItem[] = attachmentBytes.map((a) => ({
      name: a.name,
      sizeKB: Math.max(1, Math.round(a.bytes.length / 1024)),
      risk: attachmentRisk(a.name),
    }));

    // ---- Signal-based scoring: each signal carries its own point weight ----
    const signals: ScoreSignal[] = [];
    const add = (points: number, severity: "low" | "medium" | "high", label: string) =>
      signals.push({ points, severity, label });

    if (spf === "fail") add(25, "high", language === "pt" ? "Falha na autenticação SPF (IP do remetente não autorizado)." : "SPF authentication failed (sender IP not authorized).");
    if (dkim === "fail") add(20, "high", language === "pt" ? "Falha na verificação de assinatura DKIM." : "DKIM signature check failed.");
    if (spf === "unknown" && dkim === "unknown") add(10, "medium", language === "pt" ? "Sem cabeçalhos de autenticação modernos (SPF/DKIM)." : "No modern authentication headers (SPF/DKIM).");

    const brands = ["paypal", "microsoft", "netflix", "google", "amazon", "bank", "apple", "invoice", "finance", "billing"];
    const isBrandInName = brands.some(brand => senderName.toLowerCase().includes(brand));
    const isBrandInEmail = brands.some(brand => senderEmail.toLowerCase().includes(brand));
    const freeDomains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com"];
    const senderDomain = senderEmail.split("@")[1] || "";
    const isFreeDomain = freeDomains.includes(senderDomain.toLowerCase());

    if (isBrandInName && !isBrandInEmail) {
      add(30, "high", language === "pt"
        ? `Possível falsificação de display name: alega ser "${senderName}" mas o domínio real é "${senderDomain}".`
        : `Display name spoofing: claims to be "${senderName}" but the domain is "${senderDomain}".`);
    } else if (isBrandInName && isFreeDomain) {
      add(25, "high", language === "pt"
        ? `Nome comercial "${senderName}" em domínio de e-mail gratuito (${senderDomain}).`
        : `Brand display name "${senderName}" on a free email domain (${senderDomain}).`);
    }

    // Lookalike / typosquat sender domain (homoglyph + edit distance).
    const typo = detectTyposquat(senderDomain);
    if (typo) {
      add(30, "high", language === "pt"
        ? `Domínio sósia de "${typo.brand}": ${senderDomain}.`
        : `Lookalike of "${typo.brand}": ${senderDomain}.`);
    }

    const urgencyKeywords = [
      "urgent", "urgente", "action required", "ação necessária", "immediate", "imediato", "suspended", "suspenso", "security alert", "alerta de segurança",
      "password reset", "redefinir senha", "verify", "verifique", "verification", "verificação", "invoice", "fatura", "overdue", "atrasado",
      "unauthorized access", "acesso não autorizado", "compromise", "confirm your account", "confirme sua conta"
    ];
    const textToAnalyze = (subject + " " + bodyText).toLowerCase();
    const matchedKeywords = urgencyKeywords.filter(kw => textToAnalyze.includes(kw));
    if (matchedKeywords.length >= 2) {
      add(15, "medium", language === "pt"
        ? `Vocabulário de urgência/coação: ${matchedKeywords.slice(0, 3).join(", ")}.`
        : `Urgency/coercion vocabulary: ${matchedKeywords.slice(0, 3).join(", ")}.`);
    }

    const highRiskAttachments = attachmentsFound.filter(a => a.risk === "high");
    const medRiskAttachments = attachmentsFound.filter(a => a.risk === "medium");
    if (highRiskAttachments.length > 0) {
      add(40, "high", language === "pt"
        ? `Anexos executáveis de alto risco: ${highRiskAttachments.map(a => a.name).join(", ")}.`
        : `High-risk executable attachments: ${highRiskAttachments.map(a => a.name).join(", ")}.`);
    } else if (medRiskAttachments.length > 0) {
      add(15, "medium", language === "pt"
        ? `Anexos de documentos/arquivos compactados: ${medRiskAttachments.map(a => a.name).join(", ")}.`
        : `Document/archive attachments: ${medRiskAttachments.map(a => a.name).join(", ")}.`);
    }

    const suspiciousLinkDomains = ["bit.ly", "t.co", "tinyurl.com", "cutt.ly", "ow.ly", "googl", "formspree", "forms.gle"];
    if (linksFound.some(link => suspiciousLinkDomains.some(d => link.toLowerCase().includes(d)))) {
      add(25, "medium", language === "pt"
        ? "Contém encurtadores de links ou formulários usados em campanhas de phishing."
        : "Contains URL shorteners or form domains typical of phishing campaigns.");
    }
    if (linksFound.length > 5) {
      add(10, "low", language === "pt" ? `Alto número de hiperlinks (${linksFound.length}).` : `High link count (${linksFound.length}).`);
    }

    const score = Math.min(100, Math.max(0, signals.reduce((s, x) => s + x.points, 0)));
    const verdict: "safe" | "suspicious" | "malicious" = score >= 60 ? "malicious" : score >= 25 ? "suspicious" : "safe";
    const alerts = signals.map(s => s.label);

    // Compute real SHA-256 for each attachment in the background, then patch it in.
    attachmentBytes.forEach(async (a, idx) => {
      try {
        const sha = await sha256Hex(a.bytes);
        setParsedData(prev => prev
          ? { ...prev, attachments: prev.attachments.map((at, i) => i === idx ? { ...at, sha256: sha } : at) }
          : prev);
      } catch { /* hashing unavailable — leave undefined */ }
    });

    setParsedData({
      headers,
      subject,
      from,
      to,
      date,
      replyTo,
      returnPath,
      messageId,
      senderEmail,
      senderName,
      senderDomain,
      spf,
      dkim,
      dmarc,
      links: linksFound,
      attachments: attachmentsFound,
      score,
      verdict,
      signals,
      alerts,
      typosquat: typo ? { host: senderDomain, brand: typo.brand } : null,
      rawText
    });

    toast.success(language === "pt" ? "E-mail analisado com sucesso!" : "Email parsed and analyzed successfully!");
  };

  // Drag and Drop Handlers
  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      if (file.name.endsWith(".eml")) {
        const reader = new FileReader();
        reader.onload = (event) => {
          if (event.target?.result) {
            parseEmlContent(event.target.result as string, file.name);
          }
        };
        reader.readAsText(file);
      } else {
        toast.error(language === "pt" ? "Por favor, selecione apenas arquivos .eml" : "Please select only .eml files");
      }
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      const reader = new FileReader();
      reader.onload = (event) => {
        if (event.target?.result) {
          parseEmlContent(event.target.result as string, file.name);
        }
      };
      reader.readAsText(file);
    }
  };

  const loadSample = (type: "phish" | "safe") => {
    if (type === "phish") {
      parseEmlContent(SAMPLE_PHISHING_EML, "paypal_suspicion_invoice.eml");
    } else {
      parseEmlContent(SAMPLE_SAFE_EML, "github_security_alert.eml");
    }
  };

  const resetAnalyzer = () => {
    setParsedData(null);
    setFileName(null);
    setSenderRep(null);
    setLinkResults({});
    setPreviewUrl(null);
  };

  // ---- Live reputation enrichment (reuses fetchThreatDataProgressive) ----
  const enrichSender = async (domain: string) => {
    setSenderRepLoading(true);
    try {
      const res = await fetchThreatDataProgressive(domain, ["VirusTotal", "URLhaus", "WHOIS", "AlienVault OTX", "Pulsedive"], () => {});
      setSenderRep(res);
    } catch {
      /* enrichment best-effort */
    } finally {
      setSenderRepLoading(false);
    }
  };

  const checkLink = async (url: string) => {
    setLinkResults((prev) => ({ ...prev, [url]: "loading" }));
    try {
      const res = await fetchThreatDataProgressive(url, URL_VENDORS, () => {});
      setLinkResults((prev) => ({ ...prev, [url]: res }));
    } catch {
      setLinkResults((prev) => {
        const next = { ...prev };
        delete next[url];
        return next;
      });
      toast.error(language === "pt" ? "Falha ao consultar o link." : "Link lookup failed.");
    }
  };

  // Check up to 10 links sequentially to respect the per-scan rate limit.
  const checkAllLinks = async () => {
    const targets = (parsedData?.links || []).slice(0, 10).filter((l) => !linkResults[l]);
    for (const url of targets) {
      // eslint-disable-next-line no-await-in-loop
      await checkLink(url);
    }
  };

  // All unique indicators worth exporting: links, sender domain, attachment hashes.
  const collectIocs = (): string[] => {
    if (!parsedData) return [];
    const set = new Set<string>();
    parsedData.links.forEach((l) => set.add(l));
    if (parsedData.senderDomain) set.add(parsedData.senderDomain);
    parsedData.attachments.forEach((a) => a.sha256 && set.add(a.sha256));
    return [...set];
  };

  const copyIocs = async () => {
    const text = defangList(collectIocs());
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopiedIocs(true);
      setTimeout(() => setCopiedIocs(false), 1500);
      toast.success(language === "pt" ? "IOCs copiados (defanged)." : "IOCs copied (defanged).");
    } catch {
      toast.error(language === "pt" ? "Falha ao copiar." : "Copy failed.");
    }
  };

  // Auto-enrich the sender domain whenever a new email is parsed.
  useEffect(() => {
    setLinkResults({});
    setSenderRep(null);
    setPreviewUrl(null);
    if (parsedData?.senderDomain) enrichSender(parsedData.senderDomain);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [parsedData?.senderDomain, parsedData?.messageId]);

  // The verdict, escalated if live intel flags the sender or any link as malicious.
  const liveMalicious =
    senderRep?.threatLevel === "malicious" ||
    Object.values(linkResults).some((r) => r !== "loading" && r?.threatLevel === "malicious");
  const effectiveVerdict: "safe" | "suspicious" | "malicious" =
    liveMalicious ? "malicious" : (parsedData?.verdict || "safe");

  // Helper values for display
  const getVerdictStyle = (verdict: "safe" | "suspicious" | "malicious") => {
    switch (verdict) {
      case "malicious":
        return {
          title: language === "pt" ? "Malicioso" : "Malicious",
          color: "text-red-500 bg-red-500/10 border-red-500/30",
          progressColor: "bg-red-500",
          cardBg: "from-red-500/10 via-background to-background"
        };
      case "suspicious":
        return {
          title: language === "pt" ? "Suspeito" : "Suspicious",
          color: "text-amber-500 bg-amber-500/10 border-amber-500/30",
          progressColor: "bg-amber-500",
          cardBg: "from-amber-500/10 via-background to-background"
        };
      default:
        return {
          title: language === "pt" ? "Seguro" : "Safe",
          color: "text-green-500 bg-green-500/10 border-green-500/30",
          progressColor: "bg-green-500",
          cardBg: "from-green-500/10 via-background to-background"
        };
    }
  };

  const getAuthBadge = (status: string) => {
    switch (status) {
      case "pass":
        return <Badge className="bg-green-500/10 text-green-500 border-green-500/30 font-semibold gap-1"><Check className="h-3 w-3" /> PASS</Badge>;
      case "fail":
        return <Badge className="bg-red-500/10 text-red-500 border-red-500/30 font-semibold gap-1"><AlertCircle className="h-3 w-3" /> FAIL</Badge>;
      case "softfail":
        return <Badge className="bg-amber-500/10 text-amber-500 border-amber-500/30 font-semibold gap-1"><AlertCircle className="h-3 w-3" /> SOFTFAIL</Badge>;
      default:
        return <Badge className="bg-slate-500/10 text-slate-500 border-slate-500/30 font-semibold">UNKNOWN</Badge>;
    }
  };

  return (
    <PageLayout width="max-w-7xl">
        <div className="space-y-6">
          
          {/* Header Row */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
            <div>
              <h1 className="page-title">
                {language === "pt" ? "Análise de Phishing" : "Phishing Analysis"}
              </h1>
              <p className="page-lede">
                {mode === "eml"
                  ? (language === "pt"
                    ? "O e-mail suspeito, aberto por dentro: remetente, autenticação, links e anexos. O .eml é lido aqui no navegador e nunca sai da sua máquina."
                    : "The suspicious email, opened up: sender, authentication, links and attachments. The .eml is read here in the browser and never leaves your machine.")
                  : mode === "hunt"
                    ? (language === "pt"
                      ? "Todo phishing começa com um domínio novo. A caça acha no dia em que ele nasce, cruzando as marcas do seu perfil com tudo que o urlscan já varreu — e nenhuma URL sua vira scan público."
                      : "Every phishing campaign starts with a new domain. The hunt finds it the day it is born, crossing your profile's brands with everything urlscan has already scanned — and no URL of yours ever becomes a public scan.")
                    : (language === "pt"
                      ? "Do achado até a derrubada: evidência congelada antes de o domínio sumir, contato de abuse descoberto sozinho, e o pedido pronto para enviar."
                      : "From find to takedown: evidence frozen before the domain disappears, abuse contacts discovered on their own, and the request ready to send.")}
              </p>
            </div>
            {mode === "eml" && parsedData && (
              <Button
                variant="outline"
                size="sm"
                onClick={resetAnalyzer}
                className="h-8 text-xs border-border/50 hover:bg-primary/5 shrink-0"
              >
                <RefreshCw className="h-3 w-3 mr-1.5" />
                {language === "pt" ? "Analisar Outro" : "Analyze Another"}
              </Button>
            )}
          </div>

          <div className="flex gap-2">
            {([
              { key: "eml" as const, label: language === "pt" ? "Analisar e-mail" : "Analyze email" },
              { key: "hunt" as const, label: language === "pt" ? "Caça a domínios" : "Domain hunt" },
              { key: "tickets" as const, label: language === "pt" ? "Tickets" : "Tickets" },
            ]).map((tab) => (
              <button
                key={tab.key}
                type="button"
                onClick={() => setMode(tab.key)}
                aria-pressed={mode === tab.key}
                className={`rounded-full border px-4 py-1.5 text-xs font-semibold transition ${mode === tab.key ? "border-primary bg-primary/10 text-primary" : "text-muted-foreground hover:border-primary/40"}`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {mode === "tickets" ? (
            <PhishTickets />
          ) : mode === "hunt" ? (
            <BrandHunt />
          ) : !parsedData ? (
            /* Dropzone and Sample Loader Card */
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <Card className="lg:col-span-2 border shadow-sm bg-muted/40  flex flex-col justify-center min-h-[380px]">
                <CardContent className="p-6">
                  <div
                    onDragEnter={handleDrag}
                    onDragOver={handleDrag}
                    onDragLeave={handleDrag}
                    onDrop={handleDrop}
                    onClick={() => fileInputRef.current?.click()}
                    className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all duration-300 flex flex-col items-center justify-center space-y-4 ${
                      dragActive
                        ? "border-primary bg-primary/5 scale-98"
                        : "border-muted-foreground/20 bg-background/20 hover:border-border/50 hover:bg-primary/5"
                    }`}
                  >
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".eml"
                      onChange={handleFileChange}
                      className="hidden"
                    />
                    
                    <div className="h-16 w-16 rounded-full bg-primary/10 flex items-center justify-center text-primary border border-border/50 shadow-sm">
                      <Upload className="h-7 w-7" />
                    </div>
                    
                    <div className="space-y-1.5">
                      <h3 className="font-semibold text-base text-foreground">
                        {language === "pt" ? "Arraste e solte seu arquivo .eml" : "Drag and drop your .eml file here"}
                      </h3>
                      <p className="text-xs text-muted-foreground">
                        {language === "pt" ? "ou clique para navegar nos seus arquivos locais" : "or click to browse from your computer"}
                      </p>
                    </div>
                    
                    <Badge variant="secondary" className="text-[10px] font-semibold tracking-wider font-mono">
                      .EML ONLY
                    </Badge>
                  </div>
                </CardContent>
              </Card>

              {/* Sample Files Card */}
              <Card className="border shadow-sm bg-muted/40  flex flex-col justify-between">
                <CardHeader>
                  <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                    <Sparkles className="h-4 w-4 text-primary animate-pulse" />
                    {language === "pt" ? "Demonstração Rápida" : "Instant Demo"}
                  </CardTitle>
                  <CardDescription className="text-xs">
                    {language === "pt"
                      ? "Não tem um arquivo .eml em mãos? Carregue um dos nossos e-mails de teste para ver a análise em tempo real."
                      : "Don't have an EML file ready? Load one of our mock email templates to test the analyzer output immediately."}
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3.5 pb-6">
                  <Button
                    variant="outline"
                    className="w-full justify-start text-xs h-11 border-red-500/20 hover:bg-red-500/5 text-red-500 font-semibold gap-2.5"
                    onClick={() => loadSample("phish")}
                  >
                    <AlertTriangle className="h-4 w-4 shrink-0" />
                    <div className="text-left truncate">
                      <div>PayPal Account Suspended</div>
                      <div className="text-[10px] text-muted-foreground/70 font-normal">Mock Phishing E-mail</div>
                    </div>
                  </Button>
                  <Button
                    variant="outline"
                    className="w-full justify-start text-xs h-11 border-green-500/20 hover:bg-green-500/5 text-green-500 font-semibold gap-2.5"
                    onClick={() => loadSample("safe")}
                  >
                    <CheckCircle2 className="h-4 w-4 shrink-0" />
                    <div className="text-left truncate">
                      <div>GitHub Login Alert</div>
                      <div className="text-[10px] text-muted-foreground/70 font-normal">Mock Legitimate E-mail</div>
                    </div>
                  </Button>
                </CardContent>
              </Card>
            </div>
          ) : (
             /* Analysis Dashboard View */
            <div className="space-y-6">
              {/* Top Banner: Security Assessment Header */}
              {(() => {
                const style = getVerdictStyle(effectiveVerdict);
                return (
                  <Card className={`border shadow bg-gradient-to-r ${style.cardBg} transition-all`}>
                    <CardContent className="p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                      {/* Left: File Name and Label */}
                      <div className="space-y-1 min-w-0 flex-1">
                        <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest block">
                          {language === "pt" ? "Resultado da Análise de Phishing" : "Phishing Analysis Assessment"}
                        </span>
                        <h2 className="text-lg md:text-2xl font-black tracking-tight break-all text-foreground" title={fileName || ""}>
                          {fileName}
                        </h2>
                      </div>
                      
                      {/* Middle/Right: Score and Verdict */}
                      <div className="flex flex-wrap items-center gap-4 sm:gap-6 shrink-0 w-full md:w-auto justify-between md:justify-end">
                        {/* Compact score display */}
                        <div className="flex items-center gap-3 bg-background/45  px-4 py-2 rounded-xl border border-border/50">
                          <div className="flex flex-col text-right">
                            <span className="text-[9px] text-muted-foreground font-semibold uppercase tracking-wider">Risk Score</span>
                            <span className="text-xs text-muted-foreground/80"><span className="font-bold text-foreground text-sm">{parsedData.score}</span> / 100</span>
                          </div>
                          <div className="h-9 w-9 rounded-full bg-primary/10 flex items-center justify-center border border-border/50">
                            <span className="text-xs font-black text-primary font-mono">{parsedData.score}</span>
                          </div>
                        </div>

                        {/* Verdict Badge */}
                        <div className="flex flex-col items-end gap-1 shrink-0">
                          <Badge variant="outline" className={`text-xs py-1.5 px-4 rounded-full font-bold uppercase tracking-wider ${style.color} bg-background/45 `}>
                            {style.title}
                          </Badge>
                          {liveMalicious && parsedData.verdict !== "malicious" && (
                            <span className="text-[9px] font-bold text-red-500 uppercase tracking-wide flex items-center gap-1">
                              <AlertTriangle className="h-2.5 w-2.5" />
                              {language === "pt" ? "Escalado por intel ao vivo" : "Escalated by live intel"}
                            </span>
                          )}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })()}

              {/* IOC toolbar — copy / export every indicator from this email */}
              {(() => {
                const iocs = collectIocs();
                if (iocs.length === 0) return null;
                return (
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <span className="text-[11px] text-muted-foreground font-medium flex items-center gap-1.5">
                      <Network className="h-3.5 w-3.5 text-primary" />
                      {iocs.length} {language === "pt" ? "indicadores extraídos" : "extracted indicators"}
                    </span>
                    <div className="flex items-center gap-2">
                      <Button variant="outline" size="sm" className="h-8 text-xs gap-1.5" onClick={copyIocs}>
                        {copiedIocs ? <Check className="h-3.5 w-3.5 text-green-500" /> : <Copy className="h-3.5 w-3.5" />}
                        {language === "pt" ? "Copiar IOCs" : "Copy IOCs"}
                      </Button>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="outline" size="sm" className="h-8 text-xs gap-1.5">
                            <Download className="h-3.5 w-3.5" />
                            {language === "pt" ? "Exportar" : "Export"}
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="w-44">
                          <DropdownMenuItem className="gap-2 cursor-pointer" onClick={() => exportIOCsJSON(collectIocs())}>
                            <FileJson className="h-4 w-4" /> JSON
                          </DropdownMenuItem>
                          <DropdownMenuItem className="gap-2 cursor-pointer" onClick={() => exportIOCsSTIX(collectIocs())}>
                            <Shield className="h-4 w-4" /> STIX 2.1
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                  </div>
                );
              })()}

              {/* Main Content Area: Tabs at the top, stretching full width */}
              <Tabs defaultValue="overview" className="w-full">
                <TabsList variant="underline" className="overflow-x-auto scrollbar-none">
                  <TabsTrigger value="overview" className="bg-transparent border-b-2 rounded-none px-2.5 sm:px-4 pb-2 pt-1 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent text-[10px] sm:text-xs font-bold uppercase tracking-wider">
                    {language === "pt" ? "Visão Geral" : "Overview"}
                  </TabsTrigger>
                  <TabsTrigger value="headers" className="bg-transparent border-b-2 rounded-none px-2.5 sm:px-4 pb-2 pt-1 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent text-[10px] sm:text-xs font-bold uppercase tracking-wider">
                    {language === "pt" ? "Cabeçalhos & Autenticação" : "Authentication"}
                  </TabsTrigger>
                  <TabsTrigger value="links" className="bg-transparent border-b-2 rounded-none px-2.5 sm:px-4 pb-2 pt-1 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent text-[10px] sm:text-xs font-bold uppercase tracking-wider">
                    {language === "pt" ? "Links Encontrados" : "Links Checked"} ({parsedData.links.length})
                  </TabsTrigger>
                  <TabsTrigger value="attachments" className="bg-transparent border-b-2 rounded-none px-2.5 sm:px-4 pb-2 pt-1 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent text-[10px] sm:text-xs font-bold uppercase tracking-wider">
                    {language === "pt" ? "Anexos" : "Attachments"} ({parsedData.attachments.length})
                  </TabsTrigger>
                  <TabsTrigger value="raw" className="bg-transparent border-b-2 rounded-none px-2.5 sm:px-4 pb-2 pt-1 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent text-[10px] sm:text-xs font-bold uppercase tracking-wider">
                    {language === "pt" ? "Cabeçalhos Brutos" : "Raw Headers"}
                  </TabsTrigger>
                </TabsList>

                {/* Overview Tab Content */}
                <TabsContent value="overview" className="pt-4 space-y-6">
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
                    {/* Left: Envelope Sender detail card (1/3 columns) */}
                    <div className="lg:col-span-1 space-y-6">
                      <Card className="border shadow bg-card">
                        <CardHeader className="pb-2">
                          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">
                            {language === "pt" ? "Remetente Detalhado" : "Envelope Sender"}
                          </span>
                        </CardHeader>
                        <CardContent className="text-xs space-y-3.5 leading-relaxed">
                          <div>
                            <div className="font-semibold text-muted-foreground">{language === "pt" ? "Nome de Exibição" : "Display Name"}</div>
                            <div className="font-bold text-foreground text-sm truncate" title={parsedData.senderName}>
                              {parsedData.senderName || "(None)"}
                            </div>
                          </div>
                          <div>
                            <div className="font-semibold text-muted-foreground">{language === "pt" ? "Endereço de E-mail" : "Email Address"}</div>
                            <div className="font-mono font-bold text-foreground truncate" title={parsedData.senderEmail}>
                              {parsedData.senderEmail}
                            </div>
                          </div>
                          <div>
                            <div className="font-semibold text-muted-foreground">{language === "pt" ? "Domínio do Remetente" : "Sender Domain"}</div>
                            <div className="font-mono font-bold text-primary truncate">
                              {parsedData.senderDomain}
                            </div>
                          </div>
                        </CardContent>
                      </Card>

                      {/* Live Sender Reputation */}
                      <Card className="border shadow bg-card">
                        <CardHeader className="pb-2 flex flex-row items-center justify-between space-y-0">
                          <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                            <ShieldCheck className="h-3.5 w-3.5 text-primary" />
                            {language === "pt" ? "Reputação do Remetente" : "Sender Reputation"}
                          </span>
                          {senderRepLoading && <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />}
                        </CardHeader>
                        <CardContent className="text-xs space-y-3">
                          {parsedData.typosquat && (
                            <div className="flex items-start gap-2 p-2 rounded-md bg-red-500/10 border border-red-500/20 text-red-500">
                              <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                              <span className="font-semibold leading-snug">
                                {language === "pt" ? `Domínio sósia de ${parsedData.typosquat.brand}` : `Lookalike of ${parsedData.typosquat.brand}`}
                              </span>
                            </div>
                          )}
                          {senderRep ? (() => {
                            const whois = senderRep.vendorData.find(v => v.name === "WHOIS");
                            const created = whois?.data?.["Created"] || whois?.data?.["Creation Date"];
                            let age: { days: number; created: string } | null = null;
                            if (created) {
                              const d = new Date(created as string);
                              if (!isNaN(d.getTime())) age = { days: Math.floor((Date.now() - d.getTime()) / 86400000), created: d.toISOString().slice(0, 10) };
                            }
                            const sources = senderRep.vendorData.filter(v => !v.error && v.data && Object.keys(v.data).length > 0);
                            return (
                              <>
                                <div className="flex items-center justify-between">
                                  <span className="text-muted-foreground">{language === "pt" ? "Veredito" : "Verdict"}</span>
                                  <ThreatBadge level={senderRep.threatLevel} />
                                </div>
                                <div className="flex items-center justify-between">
                                  <span className="text-muted-foreground">{language === "pt" ? "Pontuação" : "Score"}</span>
                                  <span className="font-bold text-foreground">
                                    {senderRep.overallScore}/100{typeof senderRep.confidence === "number" ? ` · ${senderRep.confidence}%` : ""}
                                  </span>
                                </div>
                                {age && age.days >= 0 && (
                                  <div className={`flex items-center justify-between ${age.days < 30 ? "text-red-500 font-semibold" : ""}`}>
                                    <span className="text-muted-foreground flex items-center gap-1"><Clock className="h-3 w-3" />{language === "pt" ? "Idade do domínio" : "Domain age"}</span>
                                    <span title={age.created}>{age.days}d {age.days < 30 ? (language === "pt" ? "(novo!)" : "(new!)") : ""}</span>
                                  </div>
                                )}
                                {sources.length > 0 && (
                                  <div className="flex flex-wrap gap-1 pt-1">
                                    {sources.map((v, i) => (<Badge key={i} variant="outline" className="text-[9px]">{v.name}</Badge>))}
                                  </div>
                                )}
                              </>
                            );
                          })() : (
                            <p className="text-muted-foreground">{senderRepLoading ? (language === "pt" ? "Consultando fontes..." : "Querying sources...") : (language === "pt" ? "Sem dados de reputação." : "No reputation data.")}</p>
                          )}
                        </CardContent>
                      </Card>
                    </div>

                    {/* Right: Message Summary & Threats (2/3 columns) */}
                    <div className="lg:col-span-2 space-y-6">
                      <Card className="border shadow-sm bg-card">
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground">
                            {language === "pt" ? "Informações Principais" : "Message Summary"}
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-4 text-xs md:text-sm">
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 border-b border-muted pb-4">
                            <div>
                              <span className="font-semibold text-muted-foreground">{language === "pt" ? "Assunto:" : "Subject:"}</span>
                              <div className="font-bold text-foreground text-sm mt-0.5">{parsedData.subject}</div>
                            </div>
                            <div>
                              <span className="font-semibold text-muted-foreground">{language === "pt" ? "De:" : "From:"}</span>
                              <div className="font-bold text-foreground text-sm mt-0.5">{parsedData.from}</div>
                            </div>
                            <div>
                              <span className="font-semibold text-muted-foreground">{language === "pt" ? "Data do E-mail:" : "Date:"}</span>
                              <div className="font-bold text-foreground text-sm mt-0.5">{parsedData.date}</div>
                            </div>
                          </div>

                          <div>
                            <span className="font-semibold text-muted-foreground">{language === "pt" ? "Destinatário:" : "To:"}</span>
                            <div className="font-mono text-foreground mt-0.5">{parsedData.to}</div>
                          </div>

                          {parsedData.messageId && (
                            <div>
                              <span className="font-semibold text-muted-foreground">Message-ID:</span>
                              <div className="font-mono text-muted-foreground text-xs break-all mt-0.5">{parsedData.messageId}</div>
                            </div>
                          )}
                        </CardContent>
                      </Card>

                      {/* Score breakdown card — each signal with the points it contributed */}
                      <Card className="border shadow-sm bg-card">
                        <CardHeader className="pb-2 flex flex-row items-center justify-between space-y-0">
                          <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground">
                            {language === "pt" ? "Como a Pontuação foi Calculada" : "How the Score Was Built"}
                          </CardTitle>
                          {parsedData.signals.length > 0 && (
                            <span className="text-[10px] font-mono text-muted-foreground">
                              {parsedData.signals.length} {language === "pt" ? "sinais" : "signals"} · {parsedData.score}/100
                            </span>
                          )}
                        </CardHeader>
                        <CardContent className="space-y-2.5">
                          {parsedData.signals.length === 0 ? (
                            <div className="p-6 text-center text-sm text-green-500 font-semibold flex flex-col items-center gap-2">
                              <CheckCircle2 className="h-8 w-8 text-green-500" />
                              {language === "pt" ? "Nenhum indicador de phishing detectado." : "No phishing indicators detected."}
                            </div>
                          ) : (
                            parsedData.signals.map((sig, idx) => {
                              const tone = sig.severity === "high" ? "text-red-500 border-red-500/30 bg-red-500/5"
                                : sig.severity === "medium" ? "text-amber-500 border-amber-500/30 bg-amber-500/5"
                                : "text-muted-foreground border-border/50 bg-muted/30";
                              return (
                                <div key={idx} className={`flex items-start gap-3 p-3 rounded-lg border text-xs ${tone}`}>
                                  <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                                  <div className="leading-relaxed font-medium text-foreground flex-1">{sig.label}</div>
                                  <Badge variant="outline" className="font-mono shrink-0">+{sig.points}</Badge>
                                </div>
                              );
                            })
                          )}
                        </CardContent>
                      </Card>
                    </div>
                  </div>
                </TabsContent>

                {/* Headers & Authentication Tab Content */}
                <TabsContent value="headers" className="pt-4 space-y-4">
                  <Card className="border shadow-sm bg-card">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground">
                        {language === "pt" ? "Verificação de Autenticação" : "Security Protocols Validation"}
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                        <div className="p-4 border rounded-xl bg-muted/20 flex flex-col justify-between h-24">
                          <span className="text-xs font-semibold text-muted-foreground">SPF</span>
                          <div>{getAuthBadge(parsedData.spf)}</div>
                        </div>
                        <div className="p-4 border rounded-xl bg-muted/20 flex flex-col justify-between h-24">
                          <span className="text-xs font-semibold text-muted-foreground">DKIM</span>
                          <div>{getAuthBadge(parsedData.dkim)}</div>
                        </div>
                        <div className="p-4 border rounded-xl bg-muted/20 flex flex-col justify-between h-24">
                          <span className="text-xs font-semibold text-muted-foreground">DMARC</span>
                          <div>{getAuthBadge(parsedData.dmarc)}</div>
                        </div>
                      </div>

                      <div className="p-3 bg-muted/30 border rounded-lg text-xs leading-relaxed text-muted-foreground">
                        <strong>Authentication-Results:</strong>
                        <div className="font-mono mt-1 select-all break-all bg-card border p-2 rounded">
                          {parsedData.headers["authentication-results"] || "None"}
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="border shadow-sm bg-card">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground">
                        {language === "pt" ? "Principais Metadados de Roteamento" : "Routing Metadata Headers"}
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3.5 text-xs">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <span className="font-bold text-muted-foreground">Return-Path:</span>
                          <div className="font-mono bg-muted/40 p-2 rounded mt-1 truncate" title={parsedData.returnPath}>
                            {parsedData.returnPath || "None"}
                          </div>
                        </div>
                        <div>
                          <span className="font-bold text-muted-foreground">Reply-To:</span>
                          <div className="font-mono bg-muted/40 p-2 rounded mt-1 truncate" title={parsedData.replyTo}>
                            {parsedData.replyTo || "None"}
                          </div>
                        </div>
                      </div>
                      <div>
                        <span className="font-bold text-muted-foreground">X-Mailer / Mail Client:</span>
                        <div className="font-mono bg-muted/40 p-2 rounded mt-1">
                          {parsedData.headers["x-mailer"] || "Not Declared"}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </TabsContent>

                {/* Links Tab Content */}
                <TabsContent value="links" className="pt-4">
                  <Card className="border shadow-sm bg-card">
                    <CardHeader className="pb-2 flex flex-row items-center justify-between gap-2 space-y-0">
                      <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground">
                        {language === "pt" ? "Links — Reputação ao Vivo" : "Links — Live Reputation"}
                      </CardTitle>
                      {parsedData.links.length > 0 && (
                        <Button variant="outline" size="sm" className="h-8 text-xs gap-1.5" onClick={checkAllLinks}>
                          <Search className="h-3.5 w-3.5" />
                          {language === "pt" ? "Verificar todos" : "Check all"}
                        </Button>
                      )}
                    </CardHeader>
                    <CardContent className="p-0">
                      {parsedData.links.length === 0 ? (
                        <div className="p-8 text-center text-xs text-muted-foreground">
                          {language === "pt" ? "Nenhum link encontrado no corpo do e-mail." : "No hyperlinks found in the email body."}
                        </div>
                      ) : (
                        <div className="divide-y max-h-[460px] overflow-y-auto">
                          {parsedData.links.map((link, idx) => {
                            const isSuspicious = ["bit.ly", "t.co", "tinyurl.com", "cutt.ly", "ow.ly", "forms.gle"].some(d => link.toLowerCase().includes(d));
                            let host = "";
                            try { host = new URL(link).hostname; } catch { host = ""; }
                            const rep = linkResults[link];
                            return (
                              <div key={idx} className="p-4 space-y-2 text-xs">
                                <div className="flex items-start justify-between gap-3">
                                  <div className="space-y-1 min-w-0 flex-1">
                                    <div className="flex items-center gap-2 min-w-0">
                                      {host && <img src={`https://www.google.com/s2/favicons?domain=${host}&sz=32`} alt="" className="h-4 w-4 rounded-sm shrink-0" loading="lazy" />}
                                      <span className="font-mono font-bold text-foreground truncate break-all select-all">{defang(link)}</span>
                                    </div>
                                    <div className="flex items-center gap-1.5 flex-wrap">
                                      {isSuspicious && <Badge variant="outline" className="text-amber-500 border-amber-500/30 text-[10px]">{language === "pt" ? "Encurtador" : "Redirector"}</Badge>}
                                      {rep === "loading" && <Badge variant="outline" className="text-[10px] gap-1"><Loader2 className="h-2.5 w-2.5 animate-spin" />{language === "pt" ? "Consultando" : "Checking"}</Badge>}
                                      {rep && rep !== "loading" && <ThreatBadge level={rep.threatLevel} />}
                                      {rep && rep !== "loading" && <span className="text-muted-foreground">{rep.detections}/{rep.reportingVendors ?? rep.totalVendors} {language === "pt" ? "fontes" : "sources"}</span>}
                                    </div>
                                  </div>
                                  <div className="flex items-center gap-1 shrink-0">
                                    <Button variant="ghost" size="icon" className="h-8 w-8 border border-border" title={language === "pt" ? "Copiar (defanged)" : "Copy (defanged)"} onClick={() => { navigator.clipboard.writeText(defang(link)); toast.success(language === "pt" ? "Copiado (defanged)" : "Copied (defanged)"); }}>
                                      <Copy className="h-3.5 w-3.5" />
                                    </Button>
                                    <Button variant="ghost" size="icon" className="h-8 w-8 border border-border" title={language === "pt" ? "Pré-visualizar" : "Preview"} onClick={() => setPreviewUrl(previewUrl === link ? null : link)}>
                                      <ImageIcon className="h-3.5 w-3.5" />
                                    </Button>
                                    {(!rep || rep === "loading") && (
                                      <Button variant="outline" size="sm" className="h-8 text-[11px] gap-1" disabled={rep === "loading"} onClick={() => checkLink(link)}>
                                        <Search className="h-3 w-3" />{language === "pt" ? "Verificar" : "Check"}
                                      </Button>
                                    )}
                                  </div>
                                </div>
                                {previewUrl === link && (
                                  <div className="rounded-lg border overflow-hidden bg-muted/30">
                                    <div className="px-2 py-1 text-[10px] text-muted-foreground flex items-center gap-1.5 border-b">
                                      <ImageIcon className="h-3 w-3 shrink-0" />
                                      {language === "pt" ? "Prévia renderizada por terceiros (WordPress mShots) — seu navegador não acessa o site diretamente." : "Preview rendered by a third party (WordPress mShots) — your browser does not load the site directly."}
                                    </div>
                                    <img src={`https://s.wordpress.com/mshots/v1/${encodeURIComponent(link)}?w=600`} alt="preview" className="w-full max-h-72 object-contain bg-white" loading="lazy" />
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                </TabsContent>

                {/* Attachments Tab Content */}
                <TabsContent value="attachments" className="pt-4">
                  <Card className="border shadow-sm bg-card">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground">
                        {language === "pt" ? "Arquivos Anexados" : "Mail Attachments Scanner"}
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="p-0">
                      {parsedData.attachments.length === 0 ? (
                        <div className="p-8 text-center text-xs text-muted-foreground">
                          {language === "pt" ? "Nenhum anexo encontrado nesta mensagem." : "No attachment files found in this message."}
                        </div>
                      ) : (
                        <div className="divide-y">
                          {parsedData.attachments.map((attach, idx) => {
                            const badgeStyle = 
                              attach.risk === "high"
                                ? "bg-red-500/10 text-red-500 border-red-500/30 font-bold"
                                : attach.risk === "medium"
                                ? "bg-amber-500/10 text-amber-500 border-amber-500/30 font-semibold"
                                : "bg-green-500/10 text-green-500 border-green-500/30";

                            return (
                              <div key={idx} className="p-4 flex items-start justify-between gap-4 text-xs">
                                <div className="flex items-start gap-3 min-w-0">
                                  <div className="h-9 w-9 rounded bg-muted/60 flex items-center justify-center shrink-0 border">
                                    <FileText className="h-4.5 w-4.5 text-muted-foreground" />
                                  </div>
                                  <div className="min-w-0 space-y-1">
                                    <div className="font-bold text-foreground break-all">{attach.name}</div>
                                    <div className="text-[10px] text-muted-foreground">{attach.sizeKB} KB</div>
                                    {attach.sha256 && (
                                      <div className="flex items-center gap-1.5 flex-wrap">
                                        <Hash className="h-3 w-3 text-muted-foreground shrink-0" />
                                        <span className="font-mono text-[10px] text-muted-foreground break-all select-all" title="SHA-256">{attach.sha256}</span>
                                        <button
                                          className="text-muted-foreground hover:text-foreground"
                                          title={language === "pt" ? "Copiar hash" : "Copy hash"}
                                          onClick={() => { navigator.clipboard.writeText(attach.sha256!); toast.success(language === "pt" ? "Hash copiado" : "Hash copied"); }}
                                        >
                                          <Copy className="h-3 w-3" />
                                        </button>
                                      </div>
                                    )}
                                  </div>
                                </div>
                                <div className="flex flex-col items-end gap-1.5 shrink-0">
                                  <Badge variant="outline" className={badgeStyle}>
                                    {attach.risk.toUpperCase()} RISK
                                  </Badge>
                                  {attach.sha256 && (
                                    <Button variant="outline" size="sm" className="h-7 text-[10px] gap-1" asChild>
                                      <a href={`https://www.virustotal.com/gui/file/${attach.sha256}`} target="_blank" rel="noopener noreferrer">
                                        <ExternalLink className="h-3 w-3" />{language === "pt" ? "Consultar no VT" : "Look up on VT"}
                                      </a>
                                    </Button>
                                  )}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                </TabsContent>

                {/* Raw Headers Tab Content */}
                <TabsContent value="raw" className="pt-4">
                  <Card className="border shadow-sm bg-card">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                        <Terminal className="h-4 w-4 text-primary" />
                        {language === "pt" ? "Estrutura de Cabeçalho Bruto" : "Raw Headers Inspect"}
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="pt-2">
                      <pre className="text-[10px] font-mono leading-relaxed p-4 bg-muted/40 rounded-lg overflow-x-auto max-h-[380px] select-all break-all whitespace-pre-wrap">
                        {parsedData.rawText.split(/\r?\n\r?\n/)[0]}
                      </pre>
                    </CardContent>
                  </Card>
                </TabsContent>
              </Tabs>
            </div>
          )}

        </div>
    </PageLayout>
  );
};

export default PhishingAnalyzer;
