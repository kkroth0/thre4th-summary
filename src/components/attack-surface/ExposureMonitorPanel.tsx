import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, Clock, Loader2, Lock, Play, Plus, RefreshCw, Trash2, Upload } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/contexts/AuthContext";
import { useLanguage } from "@/contexts/LanguageContext";
import { cn } from "@/lib/utils";
import {
  createExposureAsset,
  deleteExposureAsset,
  fetchExposureAssets,
  fetchExposureChanges,
  fetchExposureSnapshots,
  runExposureAsset,
  updateExposureAsset,
  type ExposureAsset,
  type ExposureAssetInput,
  type ExposureAssetType,
  type ExposureChange,
  type ExposureSnapshot,
} from "@/services/threatApi";
import {
  parseAttackSurfaceTargets,
  targetToMonitorDraft,
  type AttackSurfaceImportedTarget,
} from "@/utils/attackSurfaceImport";

const emptyForm: ExposureAssetInput = {
  label: "",
  type: "domain",
  value: "",
  limit: 50,
  activeValidation: false,
  scheduleEnabled: true,
};

const riskTone: Record<string, string> = {
  critical: "border-destructive/40 bg-destructive/10 text-destructive",
  high: "border-orange-500/40 bg-orange-500/10 text-orange-500",
  medium: "border-amber-500/40 bg-amber-500/10 text-amber-600",
  low: "border-emerald-500/40 bg-emerald-500/10 text-emerald-500",
  info: "border-primary/40 bg-primary/10 text-primary",
  none: "border-border bg-muted text-muted-foreground",
};

const statusLabel = (status: string) => ({
  never_run: "Never run",
  running: "Running",
  success: "OK",
  error: "Error",
  config_error: "Config",
}[status] || status);

const assetTypeLabel = (type: ExposureAssetType) => ({
  domain: "Domain",
  ip: "IP",
  cidr: "CIDR",
  asn: "ASN",
  shodan_query: "Shodan query",
}[type]);

function MonitorMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="soc-panel rounded-lg p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="mt-2 font-mono text-2xl font-bold tabular-nums">{value}</p>
    </div>
  );
}

export function ExposureMonitorPanel() {
  const { auth, loading: authLoading } = useAuth();
  const { language } = useLanguage();
  const pt = language === "pt";
  const canUseMonitor = !authLoading && auth.authenticated && auth.isPremium;
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const [assets, setAssets] = useState<ExposureAsset[]>([]);
  const [changes, setChanges] = useState<ExposureChange[]>([]);
  const [snapshots, setSnapshots] = useState<ExposureSnapshot[]>([]);
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [form, setForm] = useState<ExposureAssetInput>(emptyForm);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [importTargets, setImportTargets] = useState<AttackSurfaceImportedTarget[]>([]);

  const selectedAsset = useMemo(
    () => assets.find((asset) => asset.id === selectedAssetId) || null,
    [assets, selectedAssetId],
  );

  const totals = useMemo(() => assets.reduce((acc, asset) => {
    acc.services += asset.lastSummary?.totalServices || 0;
    acc.criticalHigh += asset.lastSummary?.criticalHighFindings || 0;
    if (["error", "config_error"].includes(asset.lastStatus)) acc.errors += 1;
    return acc;
  }, { services: 0, criticalHigh: 0, errors: 0 }), [assets]);

  const load = useCallback(async () => {
    if (!canUseMonitor) return;
    setLoading(true);
    try {
      const [assetList, changeList] = await Promise.all([fetchExposureAssets(), fetchExposureChanges(100)]);
      setAssets(assetList);
      setChanges(changeList);
      setSelectedAssetId((current) => current || assetList[0]?.id || null);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Exposure Watchlist API error");
    } finally {
      setLoading(false);
    }
  }, [canUseMonitor]);

  useEffect(() => {
    if (!canUseMonitor) {
      setAssets([]);
      setChanges([]);
      setSnapshots([]);
      setSelectedAssetId(null);
      return;
    }
    void load();
  }, [canUseMonitor, load]);

  useEffect(() => {
    if (!canUseMonitor || !selectedAssetId) {
      setSnapshots([]);
      return;
    }
    void fetchExposureSnapshots(selectedAssetId).then(setSnapshots).catch((error) => {
      toast.error(error instanceof Error ? error.message : "Snapshot API error");
    });
  }, [canUseMonitor, selectedAssetId]);

  const importTxt = async (file: File | undefined) => {
    if (!file) return;
    try {
      const parsed = parseAttackSurfaceTargets(await file.text());
      setImportTargets(parsed.targets);
      if (parsed.targets.length === 0) {
        toast.warning(pt ? "Nenhum alvo reconhecido no arquivo." : "No supported targets found in the file.");
      } else {
        toast.success(pt ? `${parsed.targets.length} alvo(s) importado(s).` : `${parsed.targets.length} target(s) imported.`);
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : pt ? "Falha ao ler o arquivo." : "Failed to read the file.");
    } finally {
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const applyDraft = (target: AttackSurfaceImportedTarget) => {
    const draft = targetToMonitorDraft(target);
    setForm((current) => ({ ...current, ...draft }));
  };

  const submit = async () => {
    try {
      const saved = editingId ? await updateExposureAsset(editingId, form) : await createExposureAsset(form);
      toast.success(pt ? "Ativo salvo" : "Asset saved");
      setForm(emptyForm);
      setEditingId(null);
      setSelectedAssetId(saved.id);
      await load();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to save asset");
    }
  };

  const edit = (asset: ExposureAsset) => {
    setEditingId(asset.id);
    setForm({
      label: asset.label,
      type: asset.type,
      value: asset.value,
      limit: asset.limit,
      activeValidation: asset.activeValidation,
      scheduleEnabled: asset.scheduleEnabled,
    });
  };

  const runNow = async (asset: ExposureAsset) => {
    setBusyId(asset.id);
    try {
      await runExposureAsset(asset.id);
      await load();
      setSelectedAssetId(asset.id);
      setSnapshots(await fetchExposureSnapshots(asset.id));
      toast.success(pt ? "Snapshot finalizado" : "Snapshot complete");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Snapshot failed");
    } finally {
      setBusyId(null);
    }
  };

  const remove = async (asset: ExposureAsset) => {
    setBusyId(asset.id);
    try {
      await deleteExposureAsset(asset.id);
      if (selectedAssetId === asset.id) setSelectedAssetId(null);
      await load();
      toast.success(pt ? "Ativo removido" : "Asset removed");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Delete failed");
    } finally {
      setBusyId(null);
    }
  };

  if (authLoading) {
    return (
      <div className="soc-panel rounded-lg p-6 text-sm text-muted-foreground">
        <Loader2 className="mr-2 inline h-4 w-4 animate-spin" />
        {pt ? "Verificando acesso..." : "Checking access..."}
      </div>
    );
  }

  if (!canUseMonitor) {
    return (
      <div className="soc-panel rounded-lg p-8 text-center">
        <Lock className="mx-auto h-9 w-9 text-muted-foreground/60" />
        <h2 className="mt-4 text-lg font-semibold">{pt ? "Monitoramento premium" : "Premium monitoring"}</h2>
        <p className="mx-auto mt-2 max-w-xl text-sm text-muted-foreground">
          {pt
            ? "O scan manual continua disponivel. Entre com uma conta premium para salvar ativos, rodar snapshots e acompanhar mudancas."
            : "Manual scan remains available. Sign in with premium access to save assets, run snapshots, and track changes."}
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
        <div>
          <h2 className="text-xl font-semibold tracking-tight">{pt ? "Monitoramento de superficie" : "Exposure monitoring"}</h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            {pt
              ? "Salve ativos externos, rode snapshots e acompanhe mudancas de servicos, CVEs, risco e validacao TCP."
              : "Save external assets, run snapshots, and track service, CVE, risk, and TCP validation changes."}
          </p>
        </div>
        <Button type="button" variant="outline" onClick={() => void load()} disabled={loading} className="gap-2">
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
          {pt ? "Atualizar" : "Refresh"}
        </Button>
      </div>

      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <MonitorMetric label={pt ? "Ativos" : "Assets"} value={assets.length} />
        <MonitorMetric label={pt ? "Servicos" : "Services"} value={totals.services} />
        <MonitorMetric label="Critical / High" value={totals.criticalHigh} />
        <MonitorMetric label={pt ? "Erros" : "Errors"} value={totals.errors} />
      </section>

      <section className="grid gap-5 lg:grid-cols-[340px_1fr]">
        <div className="soc-panel rounded-lg p-4">
          <div className="flex items-center justify-between gap-3">
            <h3 className="flex items-center gap-2 text-base font-semibold">
              <Plus className="h-4 w-4 text-primary" />
              {editingId ? (pt ? "Editar ativo" : "Edit asset") : (pt ? "Novo ativo" : "New asset")}
            </h3>
            <input
              ref={fileInputRef}
              type="file"
              accept=".txt,.json,text/plain,application/json"
              className="hidden"
              onChange={(event) => void importTxt(event.target.files?.[0])}
            />
            <Button type="button" variant="outline" size="sm" className="gap-2" onClick={() => fileInputRef.current?.click()}>
              <Upload className="h-4 w-4" />
              TXT/JSON
            </Button>
          </div>

          <div className="mt-4 flex flex-col gap-4">
            <label className="flex flex-col gap-1.5">
              <Label>Label</Label>
              <Input value={form.label} onChange={(event) => setForm({ ...form, label: event.target.value })} />
            </label>
            <label className="flex flex-col gap-1.5">
              <Label>Type</Label>
              <Select value={form.type} onValueChange={(value) => setForm({ ...form, type: value as ExposureAssetType })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="domain">Domain</SelectItem>
                    <SelectItem value="ip">IP</SelectItem>
                    <SelectItem value="cidr">CIDR</SelectItem>
                    <SelectItem value="asn">ASN</SelectItem>
                    <SelectItem value="shodan_query">Shodan query</SelectItem>
                  </SelectGroup>
                </SelectContent>
              </Select>
            </label>
            <label className="flex flex-col gap-1.5">
              <Label>Value</Label>
              {form.type === "shodan_query" ? (
                <Textarea rows={3} value={form.value} onChange={(event) => setForm({ ...form, value: event.target.value })} />
              ) : (
                <Input value={form.value} onChange={(event) => setForm({ ...form, value: event.target.value })} />
              )}
            </label>
            <label className="flex flex-col gap-1.5">
              <Label>Limit</Label>
              <Input
                type="number"
                min={1}
                max={100}
                value={form.limit}
                onChange={(event) => setForm({ ...form, limit: Number(event.target.value) || 50 })}
              />
            </label>

            <div className="flex items-center justify-between gap-3 rounded-md border border-border p-3">
              <Label>Daily snapshot</Label>
              <Switch checked={form.scheduleEnabled} onCheckedChange={(value) => setForm({ ...form, scheduleEnabled: value })} />
            </div>
            <div className="flex flex-col gap-2 rounded-md border border-border p-3">
              <div className="flex items-center justify-between gap-3">
                <Label>Active TCP</Label>
                <Switch checked={form.activeValidation} onCheckedChange={(value) => setForm({ ...form, activeValidation: value })} />
              </div>
              <p className="text-xs text-muted-foreground">
                {pt ? "Somente pares IP/porta publicos observados pelos providers." : "Only provider-observed public IP/port pairs."}
              </p>
            </div>

            {importTargets.length > 0 && (
              <div className="rounded-md border border-border p-3">
                <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  {pt ? "Alvos importados" : "Imported targets"}
                </div>
                <div className="mt-2 flex flex-col gap-2">
                  {importTargets.slice(0, 8).map((target) => (
                    <button
                      key={`${target.kind}:${target.value}`}
                      type="button"
                      onClick={() => applyDraft(target)}
                      className="flex min-w-0 items-center gap-2 rounded-md border border-border px-2 py-1.5 text-left text-xs hover:bg-secondary"
                    >
                      <Badge variant="secondary" className="shrink-0 px-1.5 py-0 text-[10px] uppercase">
                        {target.kind.replace("_", " ")}
                      </Badge>
                      <span className="min-w-0 truncate font-mono">{target.value}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}

            <div className="flex gap-2">
              <Button
                type="button"
                onClick={() => void submit()}
                disabled={!form.label.trim() || !form.value.trim()}
                className="flex-1"
              >
                {editingId ? (pt ? "Salvar alteracoes" : "Save changes") : (pt ? "Adicionar ativo" : "Add asset")}
              </Button>
              {editingId && (
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    setEditingId(null);
                    setForm(emptyForm);
                  }}
                >
                  {pt ? "Cancelar" : "Cancel"}
                </Button>
              )}
            </div>
          </div>
        </div>

        <div className="soc-panel min-w-0 rounded-lg">
          <div className="border-b border-border p-4">
            <h3 className="text-base font-semibold">Watchlist</h3>
          </div>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Asset</TableHead>
                  <TableHead>Risk</TableHead>
                  <TableHead>Services</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {assets.map((asset) => (
                  <TableRow key={asset.id} className={cn(selectedAssetId === asset.id && "bg-muted/50")}>
                    <TableCell>
                      <button className="text-left" onClick={() => setSelectedAssetId(asset.id)}>
                        <span className="block font-medium">{asset.label}</span>
                        <span className="block max-w-64 truncate text-xs text-muted-foreground">
                          {assetTypeLabel(asset.type)} - {asset.value}
                        </span>
                      </button>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className={riskTone[asset.lastRisk || "none"]}>{asset.lastRisk || "none"}</Badge>
                    </TableCell>
                    <TableCell>{asset.lastSummary?.totalServices || 0}</TableCell>
                    <TableCell><Badge variant="secondary">{statusLabel(asset.lastStatus)}</Badge></TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-1">
                        <Button
                          size="icon"
                          variant="ghost"
                          aria-label="Run snapshot"
                          onClick={() => void runNow(asset)}
                          disabled={busyId === asset.id}
                        >
                          {busyId === asset.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                        </Button>
                        <Button size="sm" variant="ghost" onClick={() => edit(asset)}>{pt ? "Editar" : "Edit"}</Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          aria-label="Delete asset"
                          onClick={() => void remove(asset)}
                          disabled={busyId === asset.id}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
                {assets.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="py-10 text-center text-sm text-muted-foreground">
                      {pt ? "Nenhum ativo cadastrado." : "No assets saved."}
                    </TableCell>
                  </TableRow>
                ) : null}
              </TableBody>
            </Table>
          </div>
        </div>
      </section>

      <section className="grid gap-5 lg:grid-cols-2">
        <div className="soc-panel rounded-lg">
          <div className="border-b border-border p-4">
            <h3 className="flex items-center gap-2 text-base font-semibold">
              <AlertTriangle className="h-4 w-4 text-primary" />
              {pt ? "Mudancas recentes" : "Recent changes"}
            </h3>
          </div>
          <div className="flex flex-col gap-2 p-4">
            {changes.slice(0, 12).map((change) => (
              <article key={change.id} className="rounded-md border border-border p-3">
                <div className="flex items-center justify-between gap-2">
                  <Badge variant="outline" className={riskTone[change.severity]}>{change.severity}</Badge>
                  <time className="text-xs text-muted-foreground">{new Date(change.detectedAt).toLocaleString()}</time>
                </div>
                <p className="mt-2 text-sm font-medium">{change.title}</p>
                <p className="text-xs text-muted-foreground">{change.description}</p>
              </article>
            ))}
            {changes.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">{pt ? "Sem mudancas ainda." : "No changes yet."}</p>
            ) : null}
          </div>
        </div>

        <div className="soc-panel rounded-lg">
          <div className="border-b border-border p-4">
            <h3 className="flex items-center gap-2 text-base font-semibold">
              <Clock className="h-4 w-4 text-primary" />
              {selectedAsset?.label || (pt ? "Historico" : "History")}
            </h3>
          </div>
          <div className="flex flex-col gap-3 p-4">
            {selectedAsset?.lastError ? (
              <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
                {selectedAsset.lastError}
              </p>
            ) : null}
            {snapshots.slice(0, 8).map((snapshot) => (
              <article key={snapshot.id} className="rounded-md border border-border p-3">
                <div className="flex items-center justify-between gap-2">
                  <Badge variant="secondary">{snapshot.status}</Badge>
                  <time className="text-xs text-muted-foreground">
                    {snapshot.completedAt ? new Date(snapshot.completedAt).toLocaleString() : "running"}
                  </time>
                </div>
                <dl className="mt-3 grid grid-cols-3 gap-2 text-sm">
                  <div>
                    <dt className="text-xs text-muted-foreground">Services</dt>
                    <dd className="font-semibold">{snapshot.summary.totalServices}</dd>
                  </div>
                  <div>
                    <dt className="text-xs text-muted-foreground">Critical/High</dt>
                    <dd className="font-semibold">{snapshot.summary.criticalHighFindings}</dd>
                  </div>
                  <div>
                    <dt className="text-xs text-muted-foreground">Changes</dt>
                    <dd className="font-semibold">{snapshot.changes.length}</dd>
                  </div>
                </dl>
              </article>
            ))}
            {snapshots.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">
                {pt ? "Selecione um ativo ou rode o primeiro snapshot." : "Select an asset or run the first snapshot."}
              </p>
            ) : null}
          </div>
        </div>
      </section>
    </div>
  );
}
