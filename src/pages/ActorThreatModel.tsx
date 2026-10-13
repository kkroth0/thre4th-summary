import { useEffect, useMemo, useState, type ElementType } from 'react';
import { Crosshair, Plus, Trash2, UsersRound, Download, Search, Target } from 'lucide-react';
import { EmptyState } from '@/components/EmptyState';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { cn } from '@/lib/utils';
import { matchActors, topTechniques, type OrgProfile } from './actorsView';
import type { ActorListItem } from './actorsTypes';
import { ActorAvatar } from '@/components/ActorAvatar';
import { DataPager } from '@/components/workbench/DataPager';
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
    <div className="actor-surface rounded-xl p-4">
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
    return Array.isArray(raw) ? raw.filter(profile => profile && typeof profile.id === 'string' && typeof profile.name === 'string' && Array.isArray(profile.sectors) && Array.isArray(profile.regions)).map(profile => ({ ...profile, sectors: profile.sectors.filter(value => typeof value === 'string'), regions: profile.regions.filter(value => typeof value === 'string') })) : [];
  } catch {
    return [];
  }
};

function ChipPicker({ options, chosen, onToggle, searchLabel }: {
  options: string[];
  chosen: string[];
  onToggle: (value: string) => void;
  searchLabel: string;
}) {
  const [query, setQuery] = useState('');
  const filtered = options.filter(option => option.toLocaleLowerCase().includes(query.toLocaleLowerCase()));
  return (
    <div className="space-y-2">
    {!!chosen.length && <div className="flex flex-wrap gap-1.5">{chosen.map(value => <button key={value} type="button" aria-label={`${value} ×`} onClick={() => onToggle(value)} className="rounded-md border border-primary/30 bg-primary/10 px-2 py-1 text-xs text-primary">{value} <span aria-hidden="true">×</span></button>)}</div>}
    <Input aria-label={searchLabel} placeholder={searchLabel} value={query} onChange={event => setQuery(event.target.value)} className="h-8 text-xs" />
    <div className="flex max-h-40 flex-wrap gap-1.5 overflow-y-auto rounded-lg border border-border/80 bg-muted/20 p-2">
      {filtered.map((option) => {
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
      {!filtered.length && <span className="px-1 py-0.5 text-xs text-muted-foreground">—</span>}
    </div>
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
  const [activeId, setActiveId] = useState<string>(() => { const profiles = loadProfiles(); try { const saved = localStorage.getItem(`${PROFILES_KEY}-active`); return profiles.find(profile => profile.id === saved)?.id || profiles[0]?.id || ''; } catch { return profiles[0]?.id || ''; } });
  const [mode, setMode] = useState<'any' | 'all'>(() => { try { return localStorage.getItem(`${PROFILES_KEY}-mode`) === 'all' ? 'all' : 'any'; } catch { return 'any'; } });
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [saved, setSaved] = useState(true);
  useEffect(() => { try { localStorage.setItem(`${PROFILES_KEY}-active`, activeId); } catch { /* Profiles can still be used in memory. */ } }, [activeId]);
  useEffect(() => { try { localStorage.setItem(`${PROFILES_KEY}-mode`, mode); } catch { /* Matching can still be used in memory. */ } }, [mode]);

  const persist = (next: OrgProfile[]) => {
    setProfiles(next);
    try { localStorage.setItem(PROFILES_KEY, JSON.stringify(next)); setSaved(true); } catch { setSaved(false); }
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
    const profile: OrgProfile = { id: crypto.randomUUID(), name: pt ? "Nova organização" : "New organization", sectors: [], regions: [] };
    persist([...profiles, profile]);
    setActiveId(profile.id);
  };
  const removeProfile = (id: string) => {
    const next = profiles.filter((profile) => profile.id !== id);
    persist(next);
    if (activeId === id) setActiveId(next[0]?.id || "");
  };

  const matches = useMemo(() => (active ? matchActors(actors, active, mode) : []), [actors, active, mode]);
  const ttps = useMemo(() => topTechniques(matches), [matches]);
  const filtered = useMemo(() => matches.filter(({ actor }) => [actor.name, ...actor.aliases].join(' ').toLocaleLowerCase().includes(query.toLocaleLowerCase())), [matches, query]);
  const both = matches.filter(match => match.sectorHits.length && match.regionHits.length).length;
  useEffect(() => setPage(1), [activeId, active?.sectors, active?.regions, mode, query]);
  const current = Math.min(page, Math.max(1, Math.ceil(filtered.length / pageSize)));
  const exportResults = () => {
    const cell = (value: unknown) => { const text = String(value ?? ''); return `"${(/^[\s\uFEFF]*[=+@-]/.test(text) ? "'" : '') + text.replace(/"/g, '""')}"`; };
    const rows = [[pt ? 'Ator' : 'Actor', pt ? 'Setores correspondentes' : 'Matching sectors', pt ? 'Regiões correspondentes' : 'Matching regions', pt ? 'Pontos de aderência' : 'Relevance points', 'TTPs', pt ? 'Perfil' : 'Profile'], ...filtered.map(({ actor, sectorHits, regionHits, score }) => [actor.name, sectorHits.join('; '), regionHits.join('; '), score, (actor.techniques || []).join('; '), `${window.location.origin}/atores?actor=${encodeURIComponent(actor.id)}`])];
    const url = URL.createObjectURL(new Blob(['\uFEFF' + rows.map(row => row.map(cell).join(',')).join('\r\n')], { type: 'text/csv;charset=utf-8' }));
    const link = document.createElement('a'); link.href = url; link.download = 'threat-model.csv'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  return (
    <div className="grid gap-6 xl:grid-cols-[280px_minmax(0,1fr)]">
      <aside className="actor-surface h-fit rounded-xl p-4">
        <div className="mb-3 flex items-center justify-between gap-2">
          <h2 className="text-sm font-semibold">{pt ? "Perfis de contexto" : "Context profiles"}</h2>
          <Button size="sm" variant="outline" className="h-8 gap-1.5 px-2 text-xs" onClick={addProfile}>
            <Plus className="h-3.5 w-3.5" /> {pt ? "Nova" : "New"}
          </Button>
        </div>
        <p className="mb-4 text-xs text-muted-foreground">{pt ? 'Perfis salvos neste navegador.' : 'Profiles saved in this browser.'}</p>
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
              {pt ? "Crie um perfil e escolha o contexto da organização." : "Create a profile and choose your organization context."}
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
          <div className="actor-surface space-y-4 rounded-xl p-5">
            <div className="flex items-center justify-between gap-3"><h2 className="text-sm font-semibold">{pt ? 'Contexto da organização' : 'Organization context'}</h2><span className="text-[11px] text-muted-foreground" role="status">{saved ? (pt ? 'Salvo neste navegador' : 'Saved in this browser') : (pt ? 'Não foi possível salvar neste navegador' : 'Could not save in this browser')}</span></div>
            <div>
              <Label htmlFor="profile-name" className="text-xs">{pt ? "Nome" : "Name"}</Label>
              <Input
                id="profile-name"
                value={active.name}
                onChange={(event) => patch({ name: event.target.value })}
                className="mt-1 h-9"
              />
            </div>
            <div className="grid gap-4 lg:grid-cols-2"><div>
              <Label className="text-xs">{pt ? "Setores da organização" : "Organization sectors"}</Label>
              <div className="mt-2"><ChipPicker options={sectors} chosen={active.sectors} onToggle={(value) => toggle("sectors", value)} searchLabel={pt ? 'Buscar setor…' : 'Search sectors…'} /></div>
            </div>
            <div>
              <Label className="text-xs">{pt ? "Países / regiões de operação" : "Countries / regions of operation"}</Label>
              <div className="mt-2"><ChipPicker options={targets} chosen={active.regions} onToggle={(value) => toggle("regions", value)} searchLabel={pt ? 'Buscar país ou região…' : 'Search countries or regions…'} /></div>
            </div></div>
            <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-4"><Label htmlFor="model-match-mode" className="text-xs">{pt ? 'Correspondência' : 'Matching'}</Label><select id="model-match-mode" value={mode} onChange={event => setMode(event.target.value as 'any' | 'all')} className="h-8 rounded-md border bg-background px-2 text-xs"><option value="any">{pt ? 'Setor ou região' : 'Sector or region'}</option><option value="all">{pt ? 'Setor e região' : 'Sector and region'}</option></select></div>
            <p className="text-xs leading-5 text-muted-foreground">{pt ? 'Aderência ao contexto: 2 pontos por setor e 1 por região correspondente. É uma priorização baseada em metadados, não uma probabilidade de ataque. Não restringe a coleta.' : 'Context relevance: 2 points per matching sector and 1 per matching region. Metadata-based prioritization, not an attack probability. Collection is not restricted.'}</p>
          </div>

          {!active.sectors.length && !active.regions.length ? (
            <div className="rounded-lg border border-dashed border-border p-8 text-center text-sm text-muted-foreground">
              {pt ? "Escolha ao menos um setor ou região para ver os grupos relevantes." : "Pick at least one sector or region to see the relevant groups."}
            </div>
          ) : (
            <>
              <div className="grid gap-3 sm:grid-cols-3">
                <StatTile
                  icon={UsersRound}
                  label={pt ? "Grupos relevantes" : "Relevant groups"}
                  value={formatNumber(matches.length)}
                  detail={pt ? "Correspondência com o contexto selecionado." : "Matches the selected context."}
                />
                <StatTile icon={Target} label={pt ? 'Setor e região' : 'Sector and region'} value={formatNumber(both)} detail={pt ? 'Perfis com correspondência nas duas dimensões.' : 'Profiles matching both dimensions.'} />
                <StatTile
                  icon={Crosshair}
                  label={pt ? "TTPs em destaque" : "Highlighted TTPs"}
                  value={formatNumber(ttps.length)}
                  detail={pt ? "Técnicas mais repetidas entre eles." : "Techniques most repeated among them."}
                  tone="text-sky-500"
                />
              </div>

              {ttps.length > 0 && (
                <div className="actor-surface rounded-xl p-4">
                  <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    {pt ? "TTPs a priorizar" : "TTPs to prioritize"}
                  </h3>
                  <div className="flex flex-wrap gap-1.5">
                    {ttps.map((item) => (
                      <a href={`https://attack.mitre.org/techniques/${item.id.replace('.', '/')}/`} target="_blank" rel="noopener noreferrer"
                        key={item.id}
                        title={pt ? `${item.actors} grupo(s)` : `${item.actors} group(s)`}
                        className="rounded-md border border-border/70 bg-muted/30 px-2 py-1 font-mono text-xs text-foreground"
                      >
                        {item.id} <span className="opacity-70">· {item.actors}</span>
                      </a>
                    ))}
                  </div>
                </div>
              )}

              <div className="actor-surface overflow-hidden rounded-xl">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b p-4"><div className="relative w-full sm:w-64"><Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" /><Input aria-label={pt ? 'Buscar atores no modelo' : 'Search model actors'} placeholder={pt ? 'Buscar ator ou alias…' : 'Search actor or alias…'} value={query} onChange={event => setQuery(event.target.value)} className="h-9 pl-9 text-xs" /></div><Button variant="outline" size="sm" disabled={!filtered.length} onClick={exportResults}><Download className="mr-2 h-3.5 w-3.5" />CSV · {filtered.length}</Button></div>
                <DataPager pt={pt} total={filtered.length} page={current} pageSize={pageSize} onPage={setPage} onPageSize={value => { setPageSize(value); setPage(1); }} pageSizes={[25, 50, 100]} />
                <Table stickyHeader>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="h-9 px-2 text-[10px] font-semibold uppercase tracking-wide">{pt ? "Grupo" : "Group"}</TableHead>
                      <TableHead className="hidden h-9 px-2 text-[10px] font-semibold uppercase tracking-wide sm:table-cell">{pt ? "Setores" : "Sectors"}</TableHead>
                      <TableHead className="hidden h-9 px-2 text-[10px] font-semibold uppercase tracking-wide lg:table-cell">{pt ? "Regiões" : "Regions"}</TableHead>
                      <TableHead className="h-9 px-2 text-right text-[10px] font-semibold uppercase tracking-wide">TTPs</TableHead>
                      <TableHead className="h-9 px-2 text-right text-[10px] font-semibold uppercase tracking-wide">{pt ? 'Aderência' : 'Relevance'}</TableHead>
                      <TableHead className="h-9 px-2 text-right text-[10px] font-semibold uppercase tracking-wide">{pt ? "Ação" : "Action"}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filtered.slice((current - 1) * pageSize, current * pageSize).map(({ actor, sectorHits, regionHits, score }) => (
                      <TableRow key={actor.id}>
                        <TableCell className="px-2 py-2">
                          <div className="flex items-center gap-2"><ActorAvatar name={actor.name} logo={actor.logo} size="sm" /><button className="truncate text-left text-sm font-semibold text-primary hover:underline" onClick={() => onOpen(actor.id)}>{actor.name}</button></div>
                          <div className="truncate text-xs text-muted-foreground">{actor.country || "—"} · {actor.motivation || "—"}</div>
                        </TableCell>
                        <TableCell className="hidden px-2 py-2 text-xs text-muted-foreground sm:table-cell">{sectorHits.join(", ") || "—"}</TableCell>
                        <TableCell className="hidden px-2 py-2 text-xs text-muted-foreground lg:table-cell">{regionHits.join(", ") || "—"}</TableCell>
                        <TableCell className="px-2 py-2 text-right font-mono text-xs font-semibold">{actor.technique_count}</TableCell>
                        <TableCell className="px-2 py-2 text-right"><Badge variant="secondary" title={pt ? '2 × setores + regiões' : '2 × sectors + regions'}>{score} {pt ? 'pts' : 'pts'}</Badge></TableCell>
                        <TableCell className="px-2 py-2 text-right">
                          <Button variant="outline" size="sm" className="h-8 px-2 text-xs" onClick={() => onOpen(actor.id)}>
                            {pt ? "Abrir" : "Open"}
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                {!filtered.length && <p className="p-8 text-center text-sm text-muted-foreground">{pt ? 'Nenhum ator corresponde a esse contexto e busca. Ajuste os critérios.' : 'No actors match this context and search. Adjust the criteria.'}</p>}
              </div>
            </>
          )}
        </section>
      )}
    </div>
  );
}

