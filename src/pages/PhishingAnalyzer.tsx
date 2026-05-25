import React, { useState, useRef } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, Globe, Shield, ShieldAlert, Mail, Eye, Sparkles, Filter, CheckCircle2, ChevronRight, Upload, AlertTriangle, FileText, Check, AlertCircle, RefreshCw, Terminal, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Footer } from "@/components/Footer";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";
import { Header } from "@/components/Header";
import { toast } from "sonner";

interface AttachmentItem {
  name: string;
  sizeKB: number;
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
  alerts: string[];
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

const PhishingAnalyzer = () => {
  const { isCollapsed } = useSidebar();
  const { t, language } = useLanguage();
  const [dragActive, setDragActive] = useState(false);
  const [parsedData, setParsedData] = useState<ParsedEml | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

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

    // Extract Attachments
    const attachmentRegex = /content-disposition:\s*attachment;\s*filename=["']?([^"'\r\n;]+)["']?/gi;
    const attachmentsFound: AttachmentItem[] = [];
    
    let attachMatch;
    while ((attachMatch = attachmentRegex.exec(rawText)) !== null) {
      const fName = attachMatch[1];
      const extension = fName.split(".").pop()?.toLowerCase() || "";
      let risk: "low" | "medium" | "high" = "low";
      if (["exe", "scr", "vbs", "js", "bat", "cmd", "msi"].includes(extension)) {
        risk = "high";
      } else if (["zip", "rar", "7z", "pdf", "doc", "docx", "xls", "xlsx"].includes(extension)) {
        risk = "medium";
      }
      
      attachmentsFound.push({
        name: fName,
        sizeKB: Math.floor(Math.random() * 450) + 12,
        risk
      });
    }

    // scoring logic
    const alerts: string[] = [];
    let score = 0;
    
    if (spf === "fail") {
      score += 25;
      alerts.push(language === "pt" ? "Falha na autenticação SPF (IP do remetente não está autorizado)." : "SPF authentication failed (Sender IP is spoofed or not authorized).");
    }
    if (dkim === "fail") {
      score += 20;
      alerts.push(language === "pt" ? "Falha na verificação de assinatura criptográfica DKIM." : "DKIM cryptographic signature check failed.");
    }
    if (spf === "unknown" && dkim === "unknown") {
      score += 10;
      alerts.push(language === "pt" ? "O e-mail carece de cabeçalhos de autenticação modernos (SPF/DKIM)." : "Email lacks modern authentication checks (SPF/DKIM).");
    }
    
    const brands = ["paypal", "microsoft", "netflix", "google", "amazon", "bank", "apple", "invoice", "finance", "billing"];
    const isBrandInName = brands.some(brand => senderName.toLowerCase().includes(brand));
    const isBrandInEmail = brands.some(brand => senderEmail.toLowerCase().includes(brand));
    
    const freeDomains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com"];
    const senderDomain = senderEmail.split("@")[1] || "";
    const isFreeDomain = freeDomains.includes(senderDomain.toLowerCase());
    
    if (isBrandInName && !isBrandInEmail) {
      score += 30;
      alerts.push(language === "pt" 
        ? `Possível falsificação de display name: Alega ser "${senderName}" mas o domínio real é "${senderDomain}".`
        : `Display name spoofing suspected: Claims to be "${senderName}" but email domain is "${senderDomain}".`);
    } else if (isBrandInName && isFreeDomain) {
      score += 25;
      alerts.push(language === "pt"
        ? `Remetente suspeito: Nome comercial "${senderName}" associado a um domínio de e-mail gratuito (${senderDomain}).`
        : `Suspicious sender address: Brand display name "${senderName}" paired with a free email domain (${senderDomain}).`);
    }
    
    const urgencyKeywords = [
      "urgent", "urgente", "action required", "ação necessária", "immediate", "imediato", "suspended", "suspenso", "security alert", "alerta de segurança",
      "password reset", "redefinir senha", "verify", "verifique", "verification", "verificação", "invoice", "fatura", "overdue", "atrasado",
      "unauthorized access", "acesso não autorizado", "compromise", "confirm your account", "confirme sua conta"
    ];
    
    const textToAnalyze = (subject + " " + bodyText).toLowerCase();
    const matchedKeywords = urgencyKeywords.filter(kw => textToAnalyze.includes(kw));
    if (matchedKeywords.length >= 2) {
      score += 15;
      alerts.push(language === "pt"
        ? `Urgência e coação detectadas no conteúdo: ${matchedKeywords.slice(0, 3).join(", ")}.`
        : `Urgency and coercion vocabulary detected: ${matchedKeywords.slice(0, 3).join(", ")}.`);
    }

    const highRiskAttachments = attachmentsFound.filter(a => a.risk === "high");
    const medRiskAttachments = attachmentsFound.filter(a => a.risk === "medium");
    
    if (highRiskAttachments.length > 0) {
      score += 40;
      alerts.push(language === "pt"
        ? `Contém anexos executáveis de alto risco: ${highRiskAttachments.map(a => a.name).join(", ")}.`
        : `Contains high-risk executable attachments: ${highRiskAttachments.map(a => a.name).join(", ")}.`);
    } else if (medRiskAttachments.length > 0) {
      score += 15;
      alerts.push(language === "pt"
        ? `Contém anexos de documentos ou arquivos compactados: ${medRiskAttachments.map(a => a.name).join(", ")}.`
        : `Contains document/archive attachments: ${medRiskAttachments.map(a => a.name).join(", ")}.`);
    }

    const suspiciousLinkDomains = ["bit.ly", "t.co", "tinyurl.com", "cutt.ly", "ow.ly", "googl", "formspree", "forms.gle"];
    const hasSuspiciousLink = linksFound.some(link => 
      suspiciousLinkDomains.some(domain => link.toLowerCase().includes(domain))
    );
    
    if (hasSuspiciousLink) {
      score += 25;
      alerts.push(language === "pt"
        ? "Contém encurtadores de links ou formulários frequentemente usados em campanhas de phishing."
        : "Contains URL shorteners or form domains typically used in phishing campaigns.");
    }
    
    if (linksFound.length > 5) {
      score += 10;
      alerts.push(language === "pt"
        ? `Alto número de hiperlinks (${linksFound.length} links encontrados).`
        : `High link count (${linksFound.length} links found).`);
    }

    score = Math.min(100, Math.max(0, score));
    
    let verdict: "safe" | "suspicious" | "malicious" = "safe";
    if (score >= 60) {
      verdict = "malicious";
    } else if (score >= 25) {
      verdict = "suspicious";
    }

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
      alerts,
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
  };

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
    <div className={`min-h-screen bg-background flex flex-col transition-all duration-300 ${isCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
      <Header showBackButton />

      <div className="flex-1 p-4 md:p-8">
        <div className="max-w-7xl mx-auto space-y-6">
          
          {/* Header Row */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b pb-4">
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
                <ShieldAlert className="h-6 w-6 text-primary" />
                {language === "pt" ? "Analisador de Phishing EML" : "EML Phishing Analyzer"}
              </h1>
              <p className="text-xs text-muted-foreground mt-1">
                {language === "pt"
                  ? "Analise arquivos de e-mail (.eml) localmente para verificar indicadores de falsificação, links maliciosos e anexos perigosos"
                  : "Analyze email files (.eml) locally to scan for domain spoofing, suspicious links, dangerous attachments, and authentication status"}
              </p>
            </div>
            {parsedData && (
              <Button
                variant="outline"
                size="sm"
                onClick={resetAnalyzer}
                className="h-8 text-xs border-primary/20 hover:bg-primary/5 shrink-0"
              >
                <RefreshCw className="h-3 w-3 mr-1.5" />
                {language === "pt" ? "Analisar Outro" : "Analyze Another"}
              </Button>
            )}
          </div>

          {!parsedData ? (
            /* Dropzone and Sample Loader Card */
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <Card className="lg:col-span-2 border shadow-sm bg-card/65 backdrop-blur-sm flex flex-col justify-center min-h-[380px]">
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
                        : "border-muted-foreground/20 bg-background/20 hover:border-primary/50 hover:bg-primary/5"
                    }`}
                  >
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".eml"
                      onChange={handleFileChange}
                      className="hidden"
                    />
                    
                    <div className="h-16 w-16 rounded-full bg-primary/10 flex items-center justify-center text-primary border border-primary/15 shadow-sm">
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
              <Card className="border shadow-sm bg-card/65 backdrop-blur-sm flex flex-col justify-between">
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
                const style = getVerdictStyle(parsedData.verdict);
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
                        <div className="flex items-center gap-3 bg-background/45 backdrop-blur-md px-4 py-2 rounded-xl border border-primary/5">
                          <div className="flex flex-col text-right">
                            <span className="text-[9px] text-muted-foreground font-semibold uppercase tracking-wider">Risk Score</span>
                            <span className="text-xs text-muted-foreground/80"><span className="font-bold text-foreground text-sm">{parsedData.score}</span> / 100</span>
                          </div>
                          <div className="h-9 w-9 rounded-full bg-primary/10 flex items-center justify-center border border-primary/10">
                            <span className="text-xs font-black text-primary font-mono">{parsedData.score}</span>
                          </div>
                        </div>

                        {/* Verdict Badge */}
                        <Badge variant="outline" className={`text-xs py-1.5 px-4 rounded-full font-bold uppercase tracking-wider ${style.color} bg-background/45 backdrop-blur-md shrink-0`}>
                          {style.title}
                        </Badge>
                      </div>
                    </CardContent>
                  </Card>
                );
              })()}

              {/* Main Content Area: Tabs at the top, stretching full width */}
              <Tabs defaultValue="overview" className="w-full">
                <TabsList className="justify-start overflow-x-auto h-auto p-1 bg-muted/30 border-b border-border/60 rounded-none w-full flex gap-1.5 sm:gap-4 scrollbar-none">
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

                      {/* Alerts checklist card */}
                      <Card className="border shadow-sm bg-card">
                        <CardHeader className="pb-2">
                          <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground">
                            {language === "pt" ? "Indicadores de Ameaça Identificados" : "Analyzed Risk Indicators"}
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-3.5">
                          {parsedData.alerts.length === 0 ? (
                            <div className="p-6 text-center text-sm text-green-500 font-semibold flex flex-col items-center gap-2">
                              <CheckCircle2 className="h-8 w-8 text-green-500" />
                              {language === "pt" ? "Nenhum indicador de phishing detectado." : "No phishing indicators detected."}
                            </div>
                          ) : (
                            parsedData.alerts.map((alert, idx) => (
                              <div key={idx} className="flex items-start gap-3 p-3 rounded-lg border bg-muted/30 border-primary/5 text-xs">
                                <AlertCircle className="h-4.5 w-4.5 text-primary shrink-0 mt-0.5" />
                                <div className="leading-relaxed font-medium text-foreground">{alert}</div>
                              </div>
                            ))
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
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground">
                        {language === "pt" ? "Hiperlinks Extraídos do E-mail" : "Extracted URLs Details"}
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="p-0">
                      {parsedData.links.length === 0 ? (
                        <div className="p-8 text-center text-xs text-muted-foreground">
                          {language === "pt" ? "Nenhum link encontrado no corpo do e-mail." : "No hyperlinks found in the email body."}
                        </div>
                      ) : (
                        <div className="divide-y max-h-[350px] overflow-y-auto">
                          {parsedData.links.map((link, idx) => {
                            const isSuspicious = ["bit.ly", "t.co", "tinyurl.com", "cutt.ly"].some(domain => 
                              link.toLowerCase().includes(domain)
                            );
                            return (
                              <div key={idx} className="p-4 flex items-center justify-between gap-4 text-xs">
                                <div className="space-y-1 truncate">
                                  <div className="font-mono font-bold text-foreground truncate break-all select-all">
                                    {link}
                                  </div>
                                  <div className="flex items-center gap-2">
                                    <Badge variant="outline" className={isSuspicious ? "text-amber-500 border-amber-500/30" : "text-green-500 border-green-500/30"}>
                                      {isSuspicious ? "Suspicious / Redirector" : "Legitimate format"}
                                    </Badge>
                                  </div>
                                </div>
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  className="h-8 w-8 border border-border shrink-0"
                                  asChild
                                >
                                  <a href={link} target="_blank" rel="noopener noreferrer">
                                    <ExternalLink className="h-3.5 w-3.5" />
                                  </a>
                                </Button>
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
                              <div key={idx} className="p-4 flex items-center justify-between gap-4 text-xs">
                                <div className="flex items-center gap-3">
                                  <div className="h-9 w-9 rounded bg-muted/60 flex items-center justify-center shrink-0 border">
                                    <FileText className="h-4.5 w-4.5 text-muted-foreground" />
                                  </div>
                                  <div>
                                    <div className="font-bold text-foreground">{attach.name}</div>
                                    <div className="text-[10px] text-muted-foreground mt-0.5">{attach.sizeKB} KB</div>
                                  </div>
                                </div>
                                <Badge variant="outline" className={badgeStyle}>
                                  {attach.risk.toUpperCase()} RISK
                                </Badge>
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
      </div>
      <Footer />
    </div>
  );
};

export default PhishingAnalyzer;
