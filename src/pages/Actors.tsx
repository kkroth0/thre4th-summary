import { useEffect, useMemo, useState } from "react";
import { Search, ArrowLeft, ExternalLink, Loader2, MapPin, Target } from "lucide-react";
import { PageLayout } from "@/components/PageLayout";
import { PageHeader } from "@/components/PageHeader";
import { Section } from "@/components/Section";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { useLanguage } from "@/contexts/LanguageContext";

interface ActorListItem {
  id: string;
  name: string;
  aliases: string[];
  country: string;
  motivation: string;
  source: string;
  technique_count: number;
}

interface Ref { name: string; url: string }
interface Technique { id: string; name: string; url: string }
interface Software { id: string; name: string; url: string }

interface ActorDetail extends ActorListItem {
  description: string;
  attack_id: string;
  attack_url: string;
  techniques: Technique[];
  software: Software[];
  refs: Array<string | Ref>;
}

const ALL = "__all__";

const Actors = () => {
  const { language } = useLanguage();
  const pt = language === "pt";

  const [list, setList] = useState<ActorListItem[]>([]);
  const [countries, setCountries] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const [q, setQ] = useState("");
  const [country, setCountry] = useState<string>(ALL);

  const [selected, setSelected] = useState<ActorDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const r = await fetch("/api/actors");
        if (!r.ok) throw new Error(String(r.status));
        const data = await r.json();
        if (!alive) return;
        setList(data.actors || []);
        setCountries(data.countries || []);
      } catch {
        if (alive) setError(true);
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => { alive = false; };
  }, []);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return list.filter((a) => {
      if (country !== ALL && a.country !== country) return false;
      if (!needle) return true;
      return (
        a.name.toLowerCase().includes(needle) ||
        a.aliases.some((x) => x.toLowerCase().includes(needle))
      );
    });
  }, [list, q, country]);

  const openActor = async (id: string) => {
    setDetailLoading(true);
    setSelected(null);
    try {
      const r = await fetch(`/api/actors/${encodeURIComponent(id)}`);
      if (r.ok) setSelected(await r.json());
    } finally {
      setDetailLoading(false);
    }
  };

  // ---- Detail view ---------------------------------------------------------
  if (detailLoading || selected) {
    return (
      <PageLayout width="max-w-3xl">
        <Button
          variant="ghost"
          size="sm"
          className="mb-6 -ml-2 text-muted-foreground"
          onClick={() => { setSelected(null); setDetailLoading(false); }}
        >
          <ArrowLeft className="h-4 w-4 mr-1.5" /> {pt ? "Voltar" : "Back"}
        </Button>

        {detailLoading || !selected ? (
          <div className="py-20 text-center"><Loader2 className="h-5 w-5 animate-spin mx-auto text-muted-foreground" /></div>
        ) : (
          <>
            <PageHeader
              title={selected.name}
              subtitle={selected.aliases.length ? `${pt ? "Também conhecido como" : "Also known as"}: ${selected.aliases.join(", ")}` : undefined}
            />

            <div className="flex flex-wrap gap-2 mb-8">
              {selected.attack_id && (
                <a href={selected.attack_url} target="_blank" rel="noopener noreferrer">
                  <Badge variant="outline" className="gap-1 hover:bg-muted/60">{selected.attack_id} <ExternalLink className="h-3 w-3" /></Badge>
                </a>
              )}
              {selected.country && <Badge variant="outline" className="gap-1"><MapPin className="h-3 w-3" /> {selected.country}</Badge>}
              {selected.motivation && <Badge variant="outline" className="gap-1"><Target className="h-3 w-3" /> {selected.motivation}</Badge>}
            </div>

            {selected.description && (
              <Section title={pt ? "Descrição" : "Description"}>
                <p className="text-sm leading-relaxed text-foreground/90">{selected.description}</p>
              </Section>
            )}

            {selected.techniques.length > 0 && (
              <Section title={`${pt ? "Técnicas MITRE ATT&CK" : "MITRE ATT&CK Techniques"} · ${selected.techniques.length}`}>
                <div className="flex flex-wrap gap-1.5">
                  {selected.techniques.map((t) => (
                    <a key={t.id} href={t.url} target="_blank" rel="noopener noreferrer"
                       className="text-xs rounded-lg bg-muted/40 hover:bg-muted/70 px-2.5 py-1.5 transition-colors">
                      <span className="font-mono text-primary">{t.id}</span>{" "}
                      <span className="text-muted-foreground">{t.name}</span>
                    </a>
                  ))}
                </div>
              </Section>
            )}

            {selected.software.length > 0 && (
              <Section title={`${pt ? "Malware & ferramentas" : "Malware & tools"} · ${selected.software.length}`}>
                <div className="flex flex-wrap gap-1.5">
                  {selected.software.map((s) => (
                    <Badge key={s.name} variant="secondary" className="bg-muted/50">{s.name}</Badge>
                  ))}
                </div>
              </Section>
            )}

            {selected.refs.length > 0 && (
              <Section title={pt ? "Referências" : "References"}>
                <ul className="space-y-1.5">
                  {selected.refs.map((ref, i) => {
                    const url = typeof ref === "string" ? ref : ref.url;
                    const label = typeof ref === "string" ? ref : (ref.name || ref.url);
                    return (
                      <li key={i} className="text-xs truncate">
                        <a href={url} target="_blank" rel="noopener noreferrer"
                           className="text-muted-foreground hover:text-foreground inline-flex items-center gap-1">
                          <ExternalLink className="h-3 w-3 shrink-0" /> <span className="truncate">{label}</span>
                        </a>
                      </li>
                    );
                  })}
                </ul>
              </Section>
            )}
          </>
        )}
      </PageLayout>
    );
  }

  // ---- List view -----------------------------------------------------------
  const shown = filtered.slice(0, 150);
  return (
    <PageLayout width="max-w-4xl">
      <PageHeader
        title={pt ? "Atores de Ameaça" : "Threat Actors"}
        subtitle={pt
          ? "Grupos e campanhas de ameaça a partir do MITRE ATT&CK e do MISP galaxy — aliases, país, motivação e as técnicas usadas."
          : "Threat groups and campaigns from MITRE ATT&CK and the MISP galaxy — aliases, country, motivation and the techniques they use."}
      />

      <Section>
        <div className="flex flex-col sm:flex-row gap-2">
          <div className="flex items-center gap-2 flex-1 rounded-xl bg-muted/40 px-3">
            <Search className="h-4 w-4 text-muted-foreground shrink-0" />
            <Input
              placeholder={pt ? "Buscar por nome ou alias (ex.: APT29, Lazarus)…" : "Search by name or alias (e.g. APT29, Lazarus)…"}
              value={q}
              onChange={(e) => setQ(e.target.value)}
              className="flex-1 border-0 bg-transparent shadow-none focus-visible:ring-0 px-0"
            />
          </div>
          <Select value={country} onValueChange={setCountry}>
            <SelectTrigger className="w-full sm:w-[200px] rounded-xl bg-muted/40 border-0">
              <SelectValue placeholder={pt ? "País" : "Country"} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>{pt ? "Todos os países" : "All countries"}</SelectItem>
              {countries.map((c) => <SelectItem key={c} value={c}>{c}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
      </Section>

      <Section title={`${filtered.length} ${pt ? "atores" : "actors"}${filtered.length > shown.length ? ` · ${pt ? "mostrando" : "showing"} ${shown.length}` : ""}`}>
        {loading ? (
          <div className="py-20 text-center"><Loader2 className="h-5 w-5 animate-spin mx-auto text-muted-foreground" /></div>
        ) : error ? (
          <p className="py-10 text-center text-sm text-muted-foreground">{pt ? "Não foi possível carregar os atores." : "Could not load actors."}</p>
        ) : shown.length === 0 ? (
          <p className="py-10 text-center text-sm text-muted-foreground">{pt ? "Nenhum ator encontrado." : "No actors found."}</p>
        ) : (
          <div className="space-y-1.5">
            {shown.map((a) => (
              <button
                key={a.id}
                onClick={() => openActor(a.id)}
                className="w-full text-left rounded-xl bg-muted/40 hover:bg-muted/70 transition-colors p-4 flex items-center gap-3"
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-medium">{a.name}</span>
                  </div>
                  {a.aliases.length > 0 && (
                    <div className="text-xs text-muted-foreground truncate mt-0.5">{a.aliases.slice(0, 5).join(", ")}</div>
                  )}
                </div>
                <div className="flex items-center gap-1.5 shrink-0">
                  {a.country && <Badge variant="outline" className="text-[10px] font-normal hidden sm:inline-flex">{a.country}</Badge>}
                  {a.technique_count > 0 && (
                    <Badge variant="secondary" className="text-[10px] bg-primary/10 text-primary border-primary/20">
                      {a.technique_count} TTP{a.technique_count > 1 ? "s" : ""}
                    </Badge>
                  )}
                </div>
              </button>
            ))}
          </div>
        )}
      </Section>
    </PageLayout>
  );
};

export default Actors;
