import { useCallback, useEffect, useState } from "react";
import {
  fetchOrgProfiles,
  fetchOrgThreatModel,
  type OrgProfile,
} from "@/services/threatApi";
import type { OrgThreatModel } from "@/utils/orgRelevance";

const STORAGE_KEY = "org.activeProfile";

// O perfil ativo é escolha de quem está na frente da tela, não estado de sessão
// no servidor — por isso mora no localStorage. Quem quiser calibrar outra tela
// pelo contexto chama este hook e passa `model` para orgRelevance.
export function useOrgProfile() {
  const [profiles, setProfiles] = useState<OrgProfile[]>([]);
  const [activeId, setActive] = useState<string>(() => localStorage.getItem(STORAGE_KEY) ?? "");
  const [model, setModel] = useState<OrgThreatModel | null>(null);
  const [loading, setLoading] = useState(true);

  const reload = useCallback(
    () => fetchOrgProfiles().then(setProfiles).catch(() => setProfiles([])),
    [],
  );

  useEffect(() => { reload().finally(() => setLoading(false)); }, [reload]);

  const setActiveId = useCallback((id: string) => {
    setActive(id);
    if (id) localStorage.setItem(STORAGE_KEY, id);
    else localStorage.removeItem(STORAGE_KEY);
  }, []);

  // Um id apontando para perfil apagado responde 404. Tratar como "sem
  // contexto" e limpar é melhor do que deixar a tela presa num perfil morto.
  useEffect(() => {
    if (!activeId) { setModel(null); return; }
    let cancelled = false;
    fetchOrgThreatModel(activeId)
      .then((next) => { if (!cancelled) setModel(next); })
      .catch(() => { if (!cancelled) { setModel(null); setActiveId(""); } });
    return () => { cancelled = true; };
  }, [activeId, setActiveId]);

  return {
    profiles,
    activeId,
    setActiveId,
    active: profiles.find((profile) => profile.id === activeId) ?? null,
    model,
    loading,
    reload,
  };
}
