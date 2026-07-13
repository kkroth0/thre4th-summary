import { ElementType, Fragment, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  FileSpreadsheet,
  Loader2,
  Radar,
  Search,
  Server,
  ShieldAlert,
  Upload,
} from "lucide-react";
import { toast } from "sonner";
import { PageLayout } from "@/components/PageLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useLanguage } from "@/contexts/LanguageContext";
import { ExposureMonitorPanel } from "@/components/attack-surface/ExposureMonitorPanel";
import {
  AttackSurfaceFinding,
  AttackSurfaceInput,
  AttackSurfaceRisk,
  AttackSurfaceTargetType,
  fetchAttackSurface,
} from "@/services/threatApi";
import { exportAttackSurfaceExcel } from "@/utils/attackSurfaceExcel";
import { parseAttackSurfaceTargets, type AttackSurfaceImportedTarget } from "@/utils/attackSurfaceImport";
import { cn } from "@/lib/utils";

const riskStyles: Record<AttackSurfaceRisk, string> = {
  critical: "border-red-500/30 bg-red-500/10 text-red-500",
  high: "border-orange-500/30 bg-orange-500/10 text-orange-500",
  medium: "border-yellow-500/30 bg-yellow-500/10 text-yellow-600",
  low: "border-emerald-500/30 bg-emerald-500/10 text-emerald-500",
};

const riskLabels = {
  en: { all: "All", critical: "Critical", high: "High", medium: "Medium", low: "Low" },
  pt: { all: "Todos", critical: "Critico", high: "Alto", medium: "Medio", low: "Baixo" },
};

const validationLabels: Record<string, string> = {
  open: "Open",
  closed: "Closed",
  timeout: "Timeout",
  udp_not_supported: "UDP",
  error: "Error",
  not_requested: "Not requested",
};

const targetPlaceholders: Record<AttackSurfaceTargetType, string> = {
  ip: "8.8.8.8",
  domain: "example.com",
  cidr: "203.0.113.0/24",
  org: "Example Corp",
};

const formatDate = (value: string | null) => {
  if (!value) return "N/A";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
};

const serviceLabel = (finding: AttackSurfaceFinding) => {
  const name = finding.product || finding.service || "Unknown service";
  return finding.version ? `${name} ${finding.version}` : name;
};

const riskSortValue: Record<AttackSurfaceRisk, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

export default function AttackSurface() {
  const { language } = useLanguage();
  const pt = language === "pt";
  const labels = riskLabels[pt ? "pt" : "en"];
  const [searchParams, setSearchParams] = useSearchParams();
  const routeMode = searchParams.get("mode") === "monitor" ? "monitor" : "scan";
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const [featureMode, setFeatureMode] = useState<"scan" | "monitor">(routeMode);
  const [mode, setMode] = useState<"guided" | "advanced">("guided");
  const [targetType, setTargetType] = useState<AttackSurfaceTargetType>("cidr");
  const [target, setTarget] = useState("");
  const [advancedQuery, setAdvancedQuery] = useState("");
  const [limit, setLimit] = useState(50);
  const [activeValidation, setActiveValidation] = useState(false);
  const [riskFilter, setRiskFilter] = useState<AttackSurfaceRisk | "all">("all");
  const [textFilter, setTextFilter] = useState("");
  const [openRows, setOpenRows] = useState<Record<string, boolean>>({});
  const [isLoading, setIsLoading] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [importTargets, setImportTargets] = useState<AttackSurfaceImportedTarget[]>([]);
  const [result, setResult] = useState<Awaited<ReturnType<typeof fetchAttackSurface>> | null>(null);

  useEffect(() => {
    setFeatureMode(routeMode);
  }, [routeMode]);

  const findings = useMemo(() => result?.findings ?? [], [result?.findings]);

  const filteredFindings = useMemo(() => {
    const text = textFilter.trim().toLowerCase();
    return findings
      .filter((finding) => riskFilter === "all" || finding.risk === riskFilter)
      .filter((finding) => {
        if (!text) return true;
        return [
          finding.ip,
          String(finding.port),
          finding.product,
          finding.service,
          finding.organization,
          finding.asn,
          finding.country,
          ...finding.hostnames,
          ...finding.cves,
          ...finding.tags,
        ].filter(Boolean).join(" ").toLowerCase().includes(text);
      })
      .sort((a, b) => {
        const riskDelta = riskSortValue[b.risk] - riskSortValue[a.risk];
        if (riskDelta !== 0) return riskDelta;
        return b.riskScore - a.riskScore;
      });
  }, [findings, riskFilter, textFilter]);

  const topPorts = useMemo(() => {
    const counts = new Map<number, number>();
    findings.forEach((finding) => counts.set(finding.port, (counts.get(finding.port) || 0) + 1));
    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6);
  }, [findings]);

  const switchFeatureMode = (value: string) => {
    const next = value === "monitor" ? "monitor" : "scan";
    setFeatureMode(next);
    setSearchParams(next === "monitor" ? { mode: "monitor" } : {});
  };

  const applyImportedTarget = (imported: AttackSurfaceImportedTarget) => {
    if (imported.kind === "shodan_query") {
      setMode("advanced");
      setAdvancedQuery(imported.value);
      return;
    }
    if (imported.kind === "asn") {
      setMode("advanced");
      setAdvancedQuery(`asn:"${imported.value}"`);
      return;
    }
    setMode("guided");
    setTargetType(imported.kind);
    setTarget(imported.value);
  };

  const importTxt = async (file: File | undefined) => {
    if (!file) return;
    try {
      const parsed = parseAttackSurfaceTargets(await file.text());
      setImportTargets(parsed.targets);
      if (parsed.targets[0]) applyImportedTarget(parsed.targets[0]);
      if (parsed.targets.length === 0) {
        toast.warning(pt ? "Nenhum alvo reconhecido no TXT." : "No supported targets found in TXT.");
      } else {
        toast.success(pt ? `${parsed.targets.length} alvo(s) importado(s).` : `${parsed.targets.length} target(s) imported.`);
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : pt ? "Falha ao ler TXT." : "Failed to read TXT.");
    } finally {
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const exportExcel = async () => {
    if (!result) return;
    setIsExporting(true);
    try {
      await exportAttackSurfaceExcel(result);
      toast.success(pt ? "XLSX gerado." : "XLSX generated.");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : pt ? "Falha ao gerar XLSX." : "Failed to generate XLSX.");
    } finally {
      setIsExporting(false);
    }
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    const input: AttackSurfaceInput = {
      mode,
      targetType: mode === "guided" ? targetType : undefined,
      target: mode === "guided" ? target.trim() : undefined,
      advancedQuery: mode === "advanced" ? advancedQuery.trim() : undefined,
      limit,
      activeValidation,
    };

    const hasTarget = mode === "advanced" ? input.advancedQuery : input.target;
    if (!hasTarget) {
      toast.error(pt ? "Informe um alvo para buscar." : "Enter a target to search.");
      return;
    }

    setIsLoading(true);
    setOpenRows({});
    try {
      const response = await fetchAttackSurface(input);
      setResult(response);
      if (response.warnings.length > 0) {
        toast.warning(pt ? "Busca concluida com avisos." : "Search completed with warnings.");
      } else {
        toast.success(pt ? "Attack surface atualizado." : "Attack surface updated.");
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Attack Surface API error");
      setResult(null);
    } finally {
      setIsLoading(false);
    }
  };

  const toggleRow = (id: string) => {
    setOpenRows((current) => ({ ...current, [id]: !current[id] }));
  };

  return (
    <PageLayout width="max-w-7xl">
      <div className="flex flex-col gap-6">
        <header className="flex flex-col gap-4 border-b border-border pb-6 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-3xl">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="secondary" className="gap-1 border-primary/25 bg-primary/10 text-primary">
                <Radar className="h-3.5 w-3.5" />
                Attack Surface
              </Badge>
              <Badge variant="outline">Shodan</Badge>
              <Badge variant="outline">Censys optional</Badge>
            </div>
            <h1 className="mt-4 text-3xl font-semibold tracking-tight md:text-4xl">
              {pt ? "Superficie exposta externa" : "External attack surface"}
            </h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
              {pt
                ? "Mapeie servicos expostos, importe alvos por TXT, exporte XLSX e acompanhe mudancas de ativos salvos."
                : "Map exposed services, import TXT targets, export XLSX, and monitor changes for saved assets."}
            </p>
          </div>
          {result && (
            <div className="text-xs text-muted-foreground lg:text-right">
              <div className="font-mono text-foreground">{result.query}</div>
              <div>{formatDate(result.generatedAt)}</div>
            </div>
          )}
        </header>

        <Tabs value={featureMode} onValueChange={switchFeatureMode} className="flex flex-col gap-6">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <TabsList>
              <TabsTrigger value="scan">Scan</TabsTrigger>
              <TabsTrigger value="monitor">{pt ? "Monitoramento" : "Monitor"}</TabsTrigger>
            </TabsList>
          </div>

          <TabsContent value="scan" className="mt-0 flex flex-col gap-6">
        <form onSubmit={submit} className="soc-panel rounded-lg p-4">
          <Tabs value={mode} onValueChange={(value) => setMode(value as "guided" | "advanced")} className="flex flex-col gap-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
              <TabsList>
                <TabsTrigger value="guided">{pt ? "Guiado" : "Guided"}</TabsTrigger>
                <TabsTrigger value="advanced">{pt ? "Query Shodan" : "Shodan query"}</TabsTrigger>
              </TabsList>
              <input
                ref={fileInputRef}
                type="file"
                accept=".txt,text/plain"
                className="hidden"
                onChange={(event) => void importTxt(event.target.files?.[0])}
              />
              <div className="flex flex-wrap items-center gap-3">
                <div className="flex items-center gap-2">
                  <Label htmlFor="limit" className="text-xs font-semibold text-muted-foreground">Limit</Label>
                  <Input
                    id="limit"
                    type="number"
                    min={1}
                    max={100}
                    value={limit}
                    onChange={(event) => setLimit(Number(event.target.value))}
                    className="h-9 w-24"
                  />
                </div>
                <div className="flex items-center gap-2 rounded-md border border-border px-3 py-2">
                  <Checkbox
                    id="active-validation"
                    checked={activeValidation}
                    onCheckedChange={(checked) => setActiveValidation(checked === true)}
                  />
                  <Label htmlFor="active-validation" className="text-xs font-semibold">
                    {pt ? "Validar portas agora" : "Validate ports now"}
                  </Label>
                </div>
                <Button type="button" variant="outline" onClick={() => fileInputRef.current?.click()} className="h-9 gap-2">
                  <Upload className="h-4 w-4" />
                  TXT
                </Button>
                <Button type="submit" disabled={isLoading} className="h-9 gap-2">
                  {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                  {pt ? "Buscar" : "Search"}
                </Button>
              </div>
            </div>

            <TabsContent value="guided" className="mt-0">
              <div className="grid gap-3 lg:grid-cols-[220px_1fr]">
                <Select value={targetType} onValueChange={(value) => setTargetType(value as AttackSurfaceTargetType)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      <SelectItem value="cidr">CIDR</SelectItem>
                      <SelectItem value="domain">{pt ? "Dominio" : "Domain"}</SelectItem>
                      <SelectItem value="ip">IP</SelectItem>
                      <SelectItem value="org">Organization</SelectItem>
                    </SelectGroup>
                  </SelectContent>
                </Select>
                <Input
                  value={target}
                  onChange={(event) => setTarget(event.target.value)}
                  placeholder={targetPlaceholders[targetType]}
                />
              </div>
            </TabsContent>

            <TabsContent value="advanced" className="mt-0">
              <Input
                value={advancedQuery}
                onChange={(event) => setAdvancedQuery(event.target.value)}
                placeholder='org:"Example" port:3389'
              />
            </TabsContent>
          </Tabs>

          {importTargets.length > 0 && (
            <div className="mt-4 flex flex-wrap gap-2">
              {importTargets.slice(0, 10).map((imported) => (
                <Button
                  key={`${imported.kind}:${imported.value}`}
                  type="button"
                  variant="outline"
                  size="sm"
                  className="h-8 max-w-full gap-2"
                  onClick={() => applyImportedTarget(imported)}
                >
                  <Badge variant="secondary" className="px-1.5 py-0 text-[10px] uppercase">
                    {imported.kind.replace("_", " ")}
                  </Badge>
                  <span className="max-w-52 truncate font-mono text-xs">{imported.value}</span>
                </Button>
              ))}
            </div>
          )}

          {activeValidation && (
            <Alert className="mt-4 border-amber-500/30 bg-amber-500/10">
              <AlertTriangle className="h-4 w-4 text-amber-500" />
              <AlertTitle>{pt ? "Validacao ativa habilitada" : "Active validation enabled"}</AlertTitle>
              <AlertDescription>
                {pt
                  ? "O backend tentara conexao TCP apenas nos IPs publicos e portas retornadas pelos provedores. Use somente com autorizacao."
                  : "The backend will attempt TCP connections only against public IPs and provider-observed ports. Use only with authorization."}
              </AlertDescription>
            </Alert>
          )}
        </form>

        {result && (
          <>
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <Metric icon={Server} label={pt ? "Ativos" : "Assets"} value={result.summary.totalAssets} />
              <Metric icon={Activity} label={pt ? "Servicos" : "Services"} value={result.summary.totalServices} />
              <Metric icon={ShieldAlert} label={pt ? "Critico/Alto" : "Critical/High"} value={result.summary.criticalHighFindings} />
              <Metric icon={CheckCircle2} label={pt ? "TCP aberto" : "TCP open"} value={result.summary.activelyConfirmedOpen} />
            </div>

            {result.warnings.length > 0 && (
              <Alert>
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>{pt ? "Avisos da coleta" : "Collection warnings"}</AlertTitle>
                <AlertDescription>{result.warnings.slice(0, 3).join(" | ")}</AlertDescription>
              </Alert>
            )}

            <div className="soc-panel rounded-lg p-4">
              <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                <div className="flex flex-wrap gap-2">
                  {(["all", "critical", "high", "medium", "low"] as const).map((risk) => (
                    <Button
                      key={risk}
                      type="button"
                      variant={riskFilter === risk ? "default" : "outline"}
                      size="sm"
                      onClick={() => setRiskFilter(risk)}
                    >
                      {labels[risk]}
                    </Button>
                  ))}
                </div>
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                  {topPorts.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {topPorts.map(([port, count]) => (
                        <Badge key={port} variant="outline" className="font-mono">
                          :{port} x{count}
                        </Badge>
                      ))}
                    </div>
                  )}
                  <Input
                    value={textFilter}
                    onChange={(event) => setTextFilter(event.target.value)}
                    placeholder={pt ? "Filtrar IP, CVE, servico..." : "Filter IP, CVE, service..."}
                    className="h-9 sm:w-72"
                  />
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="h-9 gap-2"
                    onClick={() => void exportExcel()}
                    disabled={!result || isExporting}
                  >
                    {isExporting ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileSpreadsheet className="h-4 w-4" />}
                    Excel
                  </Button>
                </div>
              </div>

              <div className="mt-4 rounded-lg border border-border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Risk</TableHead>
                      <TableHead>Asset</TableHead>
                      <TableHead>Service</TableHead>
                      <TableHead>CVEs</TableHead>
                      <TableHead>Observed</TableHead>
                      <TableHead>TCP</TableHead>
                      <TableHead className="text-right">Details</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredFindings.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={7} className="py-12 text-center text-muted-foreground">
                          {pt ? "Nenhum servico corresponde aos filtros." : "No services match the filters."}
                        </TableCell>
                      </TableRow>
                    ) : (
                      filteredFindings.map((finding) => (
                        <Fragment key={finding.id}>
                          <TableRow className="align-top">
                            <TableCell>
                              <Badge className={cn("border capitalize", riskStyles[finding.risk])}>
                                {labels[finding.risk]}
                              </Badge>
                              <div className="mt-1 font-mono text-[11px] text-muted-foreground">{finding.riskScore}/100</div>
                            </TableCell>
                            <TableCell>
                              <div className="font-mono text-sm font-semibold">{finding.ip}:{finding.port}</div>
                              <div className="mt-1 text-xs text-muted-foreground">
                                {finding.organization || "Unknown org"} {finding.asn ? `- ${finding.asn}` : ""}
                              </div>
                              <div className="text-xs text-muted-foreground">
                                {[finding.city, finding.country].filter(Boolean).join(", ") || "Unknown location"}
                              </div>
                            </TableCell>
                            <TableCell>
                              <div className="text-sm font-medium">{serviceLabel(finding)}</div>
                              <div className="mt-1 font-mono text-[11px] uppercase text-muted-foreground">{finding.transport}</div>
                            </TableCell>
                            <TableCell>
                              {finding.cves.length > 0 ? (
                                <div className="flex flex-wrap gap-1">
                                  {finding.cves.slice(0, 3).map((cve) => (
                                    <Badge key={cve} variant="destructive" className="font-mono text-[10px]">
                                      {cve}
                                    </Badge>
                                  ))}
                                  {finding.cves.length > 3 && <Badge variant="outline">+{finding.cves.length - 3}</Badge>}
                                </div>
                              ) : (
                                <span className="text-xs text-muted-foreground">None</span>
                              )}
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground">
                              {formatDate(finding.observedAt)}
                              <div className="mt-1 flex gap-1">
                                {finding.source.shodan && <Badge variant="outline">Shodan</Badge>}
                                {finding.source.censys && <Badge variant="outline">Censys</Badge>}
                              </div>
                            </TableCell>
                            <TableCell>
                              <Badge variant={finding.validation.status === "open" ? "default" : "outline"}>
                                {validationLabels[finding.validation.status] || finding.validation.status}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-right">
                              <Button type="button" variant="ghost" size="sm" onClick={() => toggleRow(finding.id)}>
                                <ChevronDown className={cn("h-4 w-4 transition-transform", openRows[finding.id] && "rotate-180")} />
                              </Button>
                            </TableCell>
                          </TableRow>
                          {openRows[finding.id] && (
                              <TableRow>
                                <TableCell colSpan={7} className="bg-muted/30">
                                  <div className="grid gap-4 text-xs lg:grid-cols-3">
                                    <Detail title={pt ? "Motivos" : "Reasons"} items={finding.riskReasons} />
                                    <Detail title="Hostnames" items={finding.hostnames.length ? finding.hostnames : ["None"]} />
                                    <Detail title="Tags" items={finding.tags.length ? finding.tags : ["None"]} />
                                  </div>
                                  {finding.bannerSnippet && (
                                    <pre className="mt-4 max-h-32 overflow-auto rounded-md bg-background p-3 text-xs text-muted-foreground">
                                      {finding.bannerSnippet}
                                    </pre>
                                  )}
                                  {finding.validation.detail && (
                                    <div className="mt-3 text-xs text-muted-foreground">
                                      TCP: {finding.validation.detail}
                                    </div>
                                  )}
                                </TableCell>
                              </TableRow>
                          )}
                        </Fragment>
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
            </div>
          </>
        )}

        {!result && !isLoading && (
          <div className="soc-panel rounded-lg p-10 text-center">
            <Radar className="mx-auto h-10 w-10 text-muted-foreground/50" />
            <h2 className="mt-4 text-lg font-semibold">{pt ? "Nenhuma busca executada" : "No search yet"}</h2>
            <p className="mx-auto mt-2 max-w-xl text-sm text-muted-foreground">
              {pt
                ? "Use o modo guiado para alvos comuns ou a query Shodan para pesquisas avancadas."
                : "Use guided mode for common targets or Shodan query mode for advanced investigations."}
            </p>
          </div>
        )}
          </TabsContent>

          <TabsContent value="monitor" className="mt-0">
            <ExposureMonitorPanel />
          </TabsContent>
        </Tabs>
      </div>
    </PageLayout>
  );
}

function Metric({ icon: Icon, label, value }: { icon: ElementType; label: string; value: number }) {
  return (
    <div className="soc-panel rounded-lg p-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{label}</div>
          <div className="mt-2 font-mono text-2xl font-bold">{value}</div>
        </div>
        <div className="flex h-10 w-10 items-center justify-center rounded-md border border-border bg-secondary">
          <Icon className="h-4 w-4 text-primary" />
        </div>
      </div>
    </div>
  );
}

function Detail({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <div className="mb-2 font-semibold uppercase tracking-wide text-muted-foreground">{title}</div>
      <div className="flex flex-wrap gap-1">
        {items.map((item) => (
          <Badge key={item} variant="outline" className="max-w-full truncate">
            {item}
          </Badge>
        ))}
      </div>
    </div>
  );
}
