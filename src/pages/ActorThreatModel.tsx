import { useMemo, useState, type ElementType } from 'react';
import { Crosshair, Plus, Trash2, UsersRound } from 'lucide-react';
import { EmptyState } from '@/components/EmptyState';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { cn } from '@/lib/utils';
import { matchActors, topTechniques, type OrgProfile } from './actorsView';
import type { ActorListItem } from './actorsTypes';
const PROFILES_KEY = 'actor-threat-profiles';
const formatNumber = (value: number) => new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 }).format(value);
function StatTile({
  icon: Icon,
  label,
  value,
  detail,
  tone = "text-primary",
}: {
  icon: ElementType;
  label: string;
  value: string;
  detail: string;
  tone?: string;
}) {
  return (
    <div className="soc-panel rounded-lg p-4">
      <div className="flex items-center justify-between gap-3">
        <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">{label}</span>
        <Icon className={cn("h-4 w-4", tone)} />
      </div>
      <div className="mt-3 text-2xl font-semibold tracking-tight">{value}</div>
      <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{detail}</p>
    </div>
  );
}

const loadProfiles = (): OrgProfile[] => {
  try {
    const raw = JSON.parse(localStorage.getItem(PROFILES_KEY) || "[]");
    return Array.isArray(raw) ? raw : [];
  } catch {
    return [];
  }
};

function ChipPicker({ options, chosen, onToggle }: {
  options: string[];
  chosen: string[];
  onToggle: (value: string) => void;
}) {
  return (
    <div className="flex max-h-40 flex-wrap gap-1.5 overflow-y-auto rounded-lg border border-border/80 bg-muted/20 p-2">
      {options.map((option) => {
        const on = chosen.includes(option);
        return (
          <button
            key={option}
            type="button"
            aria-pressed={on}
            onClick={() => onToggle(option)}
            className={cn(
              "rounded-md border px-2 py-1 text-xs transition-colors",
              on ? "border-primary/40 bg-primary/10 text-foreground" : "border-border/70 text-muted-foreground hover:border-primary/30",
            )}
          >
            {option}
          </button>
        );
      })}
      {!options.length && <span className="px-1 py-0.5 text-xs text-muted-foreground">—</span>}
    </div>
  );
}

export function ThreatModelTab({ actors, sectors, targets, pt, onOpen }: {
  actors: ActorListItem[];
  sectors: string[];
  targets: string[];
  pt: boolean;
  onOpen: (id: string) => void;
}) {
  const [profiles, setProfiles] = useState<OrgProfile[]>(loadProfiles);
  const [activeId, setActiveId] = useState<string>(() => loadProfiles()[0]?.id || "");

  const persist = (next: OrgProfile[]) => {
    setProfiles(next);
    try { localStorage.setItem(PROFILES_KEY, JSON.stringify(next)); } catch { /* sem persistência, segue */ }
  };
  const active = profiles.find((profile) => profile.id === activeId) || null;
  const patch = (changes: Partial<OrgProfile>) =>
    active && persist(profiles.map((profile) => (profile.id === active.id ? { ...profile, ...changes } : profile)));
  const toggle = (key: "sectors" | "regions", value: string) => {
    if (!active) return;
    const current = active[key];
    patch({ [key]: current.includes(value) ? current.filter((item) => item !== value) : [...current, value] });
  };
  const addProfile = () => {
    const profile: OrgProfile = { id: String(Date.now()), name: pt ? "Nova organização" : "New organization", sectors: [], regions: [] };
    persist([...profiles, profile]);
    setActiveId(profile.id);
  };
  const removeProfile = (id: string) => {
    const next = profiles.filter((profile) => profile.id !== id);
    persist(next);
    if (activeId === id) setActiveId(next[0]?.id || "");
  };

  const matches = useMemo(() => (active ? matchActors(actors, active) : []), [actors, active]);
  const ttps = useMemo(() => topTechniques(matches), [matches]);

  return (
    <div className="grid gap-6 xl:grid-cols-[280px_minmax(0,1fr)]">
      <aside className="soc-panel h-fit rounded-lg p-4">
        <div className="mb-3 flex items-center justify-between gap-2">
          <h2 className="text-sm font-semibold">{pt ? "Organizações" : "Organizations"}</h2>
          <Button size="sm" variant="outline" className="h-8 gap-1.5 px-2 text-xs" onClick={addProfile}>
            <Plus className="h-3.5 w-3.5" /> {pt ? "Nova" : "New"}
          </Button>
        </div>
        <div className="space-y-1.5">
          {profiles.map((profile) => (
            <div
              key={profile.id}
              className={cn(
                "flex items-center gap-1 rounded-lg border px-2 py-1.5 text-sm",
                profile.id === activeId ? "border-primary/40 bg-primary/5" : "border-border/70",
              )}
            >
              <button type="button" onClick={() => setActiveId(profile.id)} className="min-w-0 flex-1 truncate text-left">
                {profile.name}
                <span className="ml-1.5 text-xs text-muted-foreground">
                  {profile.sectors.length + profile.regions.length}
                </span>
              </button>
              <Button
                size="icon" variant="ghost" className="h-7 w-7 shrink-0 text-muted-foreground hover:text-destructive"
                aria-label={pt ? `Remover ${profile.name}` : `Remove ${profile.name}`}
                onClick={() => removeProfile(profile.id)}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </div>
          ))}
          {!profiles.length && (
            <p className="py-6 text-center text-xs text-muted-foreground">
              {pt ? "Crie uma organização para mapear quem ataca gente como ela." : "Create an organization to map who attacks its kind."}
            </p>
          )}
        </div>
      </aside>

      {!active ? (
        <EmptyState
          title={pt ? "Nenhuma organização selecionada" : "No organization selected"}
          description={pt
            ? "Escolha uma organização acima para modelar as ameaças que interessam a ela."
            : "Pick an organization above to model the threats that matter to it."}
        />
      ) : (
        <section className="space-y-5">
          <div className="soc-panel space-y-4 rounded-lg p-4">
            <div>
              <Label htmlFor="profile-name" className="text-xs">{pt ? "Nome" : "Name"}</Label>
              <Input
                id="profile-name"
                value={active.name}
                onChange={(event) => patch({ name: event.target.value })}
                className="mt-1 h-9"
              />
            </div>
            <div>
              <Label className="text-xs">{pt ? "Setores da organização" : "Organization sectors"}</Label>
              <div className="mt-1"><ChipPicker options={sectors} chosen={active.sectors} onToggle={(value) => toggle("sectors", value)} /></div>
            </div>
            <div>
              <Label className="text-xs">{pt ? "Países / regiões de operação" : "Countries / regions of operation"}</Label>
              <div className="mt-1"><ChipPicker options={targets} chosen={active.regions} onToggle={(value) => toggle("regions", value)} /></div>
            </div>
          </div>

          {!active.sectors.length && !active.regions.length ? (
            <div className="rounded-lg border border-dashed border-border p-8 text-center text-sm text-muted-foreground">
              {pt ? "Escolha ao menos um setor ou região para ver os grupos relevantes." : "Pick at least one sector or region to see the relevant groups."}
            </div>
          ) : (
            <>
              <div className="grid gap-3 sm:grid-cols-2">
                <StatTile
                  icon={UsersRound}
                  label={pt ? "Grupos relevantes" : "Relevant groups"}
                  value={formatNumber(matches.length)}
                  detail={pt ? "Atacam o setor ou a região do perfil." : "They hit this profile's sector or region."}
                />
                <StatTile
                  icon={Crosshair}
                  label={pt ? "TTPs em destaque" : "Highlighted TTPs"}
                  value={formatNumber(ttps.length)}
                  detail={pt ? "Técnicas mais repetidas entre eles." : "Techniques most repeated among them."}
                  tone="text-sky-500"
                />
              </div>

              {ttps.length > 0 && (
                <div className="soc-panel rounded-lg p-4">
                  <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    {pt ? "TTPs a priorizar" : "TTPs to prioritize"}
                  </h3>
                  <div className="flex flex-wrap gap-1.5">
                    {ttps.map((item) => (
                      <span
                        key={item.id}
                        title={pt ? `${item.actors} grupo(s)` : `${item.actors} group(s)`}
                        className="rounded-md border border-border/70 bg-muted/30 px-2 py-1 font-mono text-xs text-foreground"
                      >
                        {item.id} <span className="opacity-70">· {item.actors}</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div className="rounded-lg border border-border">
                <Table stickyHeader>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="h-9 px-2 text-[10px] font-semibold uppercase tracking-wide">{pt ? "Grupo" : "Group"}</TableHead>
                      <TableHead className="hidden h-9 px-2 text-[10px] font-semibold uppercase tracking-wide sm:table-cell">{pt ? "Setores" : "Sectors"}</TableHead>
                      <TableHead className="hidden h-9 px-2 text-[10px] font-semibold uppercase tracking-wide lg:table-cell">{pt ? "Regiões" : "Regions"}</TableHead>
                      <TableHead className="h-9 px-2 text-right text-[10px] font-semibold uppercase tracking-wide">TTPs</TableHead>
                      <TableHead className="h-9 px-2 text-right text-[10px] font-semibold uppercase tracking-wide">{pt ? "Ação" : "Action"}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {matches.slice(0, 60).map(({ actor, sectorHits, regionHits }) => (
                      <TableRow key={actor.id}>
                        <TableCell className="px-2 py-2">
                          <div className="truncate text-sm font-semibold">{actor.name}</div>
                          <div className="truncate text-xs text-muted-foreground">{actor.country || "—"} · {actor.motivation || "—"}</div>
                        </TableCell>
                        <TableCell className="hidden px-2 py-2 text-xs text-muted-foreground sm:table-cell">{sectorHits.join(", ") || "—"}</TableCell>
                        <TableCell className="hidden px-2 py-2 text-xs text-muted-foreground lg:table-cell">{regionHits.join(", ") || "—"}</TableCell>
                        <TableCell className="px-2 py-2 text-right font-mono text-xs font-semibold">{actor.technique_count}</TableCell>
                        <TableCell className="px-2 py-2 text-right">
                          <Button variant="outline" size="sm" className="h-8 px-2 text-xs" onClick={() => onOpen(actor.id)}>
                            {pt ? "Abrir" : "Open"}
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              {matches.length > 60 && (
                <p className="text-xs text-muted-foreground">
                  {pt ? `Mostrando 60 de ${formatNumber(matches.length)}.` : `Showing 60 of ${formatNumber(matches.length)}.`}
                </p>
              )}
            </>
          )}
        </section>
      )}
    </div>
  );
}

