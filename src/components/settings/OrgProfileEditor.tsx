import { useEffect, useState } from "react";
import { Building2, Download, Loader2, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { useLanguage } from "@/contexts/LanguageContext";
import { useOrgProfile } from "@/hooks/useOrgProfile";
import {
  createOrgProfile,
  deleteOrgProfile,
  fetchOrgAssetSuggestions,
  fetchOrgVocab,
  updateOrgProfile,
  type OrgProfile,
  type OrgVocab,
} from "@/services/threatApi";

const EMPTY: Partial<OrgProfile> = {
  name: "", sectors: [], regions: [], assets: [], ot: { present: false, vendors: [], protocols: [] }, actors: [],
};

// Alternar um rótulo dentro de uma lista fechada — setores e regiões só aceitam
// o vocabulário que o servidor devolve, então marcar/desmarcar é toda a edição.
const toggle = (list: string[], value: string): string[] =>
  list.includes(value) ? list.filter((item) => item !== value) : [...list, value];

export function OrgProfileEditor() {
  const { language } = useLanguage();
  const pt = language === "pt";
  const { profiles, activeId, setActiveId, reload } = useOrgProfile();
  const [vocab, setVocab] = useState<OrgVocab>({ sectors: [], regions: [] });
  const [draft, setDraft] = useState<Partial<OrgProfile> | null>(null);
  const [saving, setSaving] = useState(false);
  const [assetInput, setAssetInput] = useState("");

  useEffect(() => { fetchOrgVocab().then(setVocab).catch(() => undefined); }, []);

  const edit = (profile: OrgProfile | null) => setDraft(profile ? { ...profile } : { ...EMPTY });

  const save = async () => {
    if (!draft) return;
    setSaving(true);
    try {
      const saved = draft.id ? await updateOrgProfile(draft.id, draft) : await createOrgProfile(draft);
      await reload();
      // Um perfil recém-criado é quase certamente o que a pessoa quer usar.
      if (!draft.id) setActiveId(saved.id);
      setDraft(null);
      toast.success(pt ? "Perfil salvo" : "Profile saved");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Falha ao salvar");
    } finally {
      setSaving(false);
    }
  };

  const remove = async (profile: OrgProfile) => {
    try {
      await deleteOrgProfile(profile.id);
      if (activeId === profile.id) setActiveId("");
      await reload();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Falha ao remover");
    }
  };

  const importFromWatchlist = async () => {
    if (!draft) return;
    try {
      const suggestions = await fetchOrgAssetSuggestions();
      if (suggestions.length === 0) {
        toast.info(pt ? "Nenhum produto detectado no watchlist ainda" : "No products detected in the watchlist yet");
        return;
      }
      const existing = new Set((draft.assets ?? []).map((asset) => asset.product.toLowerCase()));
      const added = suggestions
        .filter((suggestion) => !existing.has(suggestion.product.toLowerCase()))
        .map((suggestion) => ({ vendor: "", product: suggestion.product }));
      setDraft({ ...draft, assets: [...(draft.assets ?? []), ...added] });
      toast.success(pt ? `${added.length} ativo(s) sugerido(s)` : `${added.length} asset(s) suggested`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Falha ao importar");
    }
  };

  const addAsset = () => {
    const product = assetInput.trim();
    if (!draft || !product) return;
    setDraft({ ...draft, assets: [...(draft.assets ?? []), { vendor: "", product }] });
    setAssetInput("");
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base"><Building2 className="text-primary" /> {pt ? "Contexto da organização" : "Organization context"}</CardTitle>
        <CardDescription>
          {pt
            ? "O que a organização é: setor, região, ativos de software e presença de OT. As Notícias usam isso para subir e explicar o que interessa — nada é escondido por padrão."
            : "What the organization is: sector, region, software assets, and OT presence. News uses it to rank and explain what matters — nothing is hidden by default."}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {profiles.map((profile) => (
          <div key={profile.id} className="flex items-center gap-3 rounded-md border px-3 py-2">
            <input
              type="radio"
              name="active-org-profile"
              checked={activeId === profile.id}
              onChange={() => setActiveId(profile.id)}
              aria-label={pt ? `Usar ${profile.name}` : `Use ${profile.name}`}
            />
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm font-medium">{profile.name}</div>
              <div className="truncate text-xs text-muted-foreground">
                {[...profile.sectors, ...profile.regions].join(" · ") || (pt ? "sem setor ou região" : "no sector or region")}
                {profile.assets.length > 0 ? ` · ${profile.assets.length} ${pt ? "ativos" : "assets"}` : ""}
                {profile.ot.present ? " · OT" : ""}
              </div>
            </div>
            <Button variant="ghost" size="sm" onClick={() => edit(profile)}>{pt ? "Editar" : "Edit"}</Button>
            <Button variant="ghost" size="sm" onClick={() => remove(profile)} aria-label={pt ? "Remover" : "Remove"}><Trash2 /></Button>
          </div>
        ))}

        {draft ? (
          <div className="flex flex-col gap-4 rounded-md border p-4">
            <div className="space-y-1.5">
              <Label htmlFor="org-name">{pt ? "Nome" : "Name"}</Label>
              <Input id="org-name" value={draft.name ?? ""} onChange={(event) => setDraft({ ...draft, name: event.target.value })} maxLength={80} />
            </div>

            <div className="space-y-1.5">
              <Label>{pt ? "Setores" : "Sectors"}</Label>
              <div className="flex flex-wrap gap-1.5">
                {vocab.sectors.map((sector) => (
                  <button
                    key={sector}
                    type="button"
                    onClick={() => setDraft({ ...draft, sectors: toggle(draft.sectors ?? [], sector) })}
                    aria-pressed={(draft.sectors ?? []).includes(sector)}
                    className={`rounded-full border px-3 py-1 text-xs transition ${(draft.sectors ?? []).includes(sector) ? "border-primary bg-primary/10 text-primary" : "text-muted-foreground hover:border-primary/40"}`}
                  >
                    {sector}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-1.5">
              <Label>{pt ? "Regiões" : "Regions"}</Label>
              <div className="flex max-h-40 flex-wrap gap-1.5 overflow-y-auto">
                {vocab.regions.map((region) => (
                  <button
                    key={region}
                    type="button"
                    onClick={() => setDraft({ ...draft, regions: toggle(draft.regions ?? [], region) })}
                    aria-pressed={(draft.regions ?? []).includes(region)}
                    className={`rounded-full border px-3 py-1 text-xs transition ${(draft.regions ?? []).includes(region) ? "border-primary bg-primary/10 text-primary" : "text-muted-foreground hover:border-primary/40"}`}
                  >
                    {region}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="org-asset">{pt ? "Ativos de software" : "Software assets"}</Label>
              <div className="flex gap-2">
                <Input
                  id="org-asset"
                  value={assetInput}
                  placeholder={pt ? "FortiGate, SAP, VMware ESXi…" : "FortiGate, SAP, VMware ESXi…"}
                  onChange={(event) => setAssetInput(event.target.value)}
                  onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); addAsset(); } }}
                />
                {/* Botões só-ícone: sem aria-label um leitor de tela não anuncia o que fazem. */}
                <Button variant="outline" size="sm" onClick={addAsset} aria-label={pt ? "Adicionar ativo" : "Add asset"}><Plus /></Button>
                <Button variant="outline" size="sm" onClick={importFromWatchlist} title={pt ? "Importar do Watchlist" : "Import from Watchlist"} aria-label={pt ? "Importar do Watchlist" : "Import from Watchlist"}><Download /></Button>
              </div>
              <div className="flex flex-wrap gap-1.5 pt-1">
                {(draft.assets ?? []).map((asset, index) => (
                  <Badge key={`${asset.product}-${index}`} variant="secondary" className="gap-1 text-[11px]">
                    {[asset.vendor, asset.product].filter(Boolean).join(" ")}
                    <button
                      type="button"
                      onClick={() => setDraft({ ...draft, assets: (draft.assets ?? []).filter((_, i) => i !== index) })}
                      aria-label={pt ? "Remover ativo" : "Remove asset"}
                    >
                      ×
                    </button>
                  </Badge>
                ))}
              </div>
            </div>

            <div className="flex items-center gap-3">
              <Switch
                checked={draft.ot?.present ?? false}
                onCheckedChange={(next) => setDraft({ ...draft, ot: { ...(draft.ot ?? { vendors: [], protocols: [] }), present: next } })}
                aria-label="OT"
              />
              <span className="text-sm">{pt ? "A organização tem ambiente OT/ICS" : "The organization has an OT/ICS environment"}</span>
            </div>

            <div className="flex gap-2">
              <Button onClick={save} disabled={saving}>{saving ? <Loader2 className="animate-spin" /> : null} {pt ? "Salvar" : "Save"}</Button>
              <Button variant="ghost" onClick={() => setDraft(null)}>{pt ? "Cancelar" : "Cancel"}</Button>
            </div>
          </div>
        ) : (
          <Button variant="outline" className="self-start" onClick={() => edit(null)}><Plus /> {pt ? "Novo perfil" : "New profile"}</Button>
        )}
      </CardContent>
    </Card>
  );
}
