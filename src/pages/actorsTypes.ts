export interface ActorAliasEvidence {
  name: string; source: string; url: string; declaredBy?: string; sourceUpdatedAt?: string;
  relation: 'source-declared-name' | 'source-association'; relatedActorIds?: string[];
}
export interface ActorInfrastructure {
  host: string; url: string; source: string; sourceUrl: string; sourceCommit: string; collectedAt: string;
  type: 'onion'; reportedStatus: 'listed' | 'historical' | 'reported-offline' | 'reported-seized'; addressVersion: 2 | 3;
}
export interface ActorListItem {
  logo?: string | null;
  logoSource?: string | null;
  id: string;
  name: string;
  aliases: string[];
  country: string;
  motivation: string;
  source: string;
  technique_count: number;
  techniques: string[];
  sectors: string[];
  targets: string[];
}

export interface ActorDetail extends Omit<ActorListItem, 'techniques'> {
  aliasEvidence?: ActorAliasEvidence[];
  relatedNames?: ActorAliasEvidence[];
  infrastructure?: ActorInfrastructure[];
  ctiFyi?: { group: string; description: string; claims: number; metadataBasis: string; references: string[] };
  description: string;
  attack_id: string;
  attack_url: string;
  techniques: { id: string; name: string; url: string }[];
  software: { id: string; name: string; url: string }[];
  refs: (string | { name: string; url: string })[];
}

export interface ActorStory {
  id: string;
  title: string;
  lastSeen: string;
  sources: { link: string; source?: string; name?: string }[];
}

export const actorSourceLabel = (source = '') => {
  if (source.includes('attack') && source.includes('misp')) return 'MITRE + MISP';
  if (source.includes('attack')) return 'MITRE ATT&CK';
  if (source.includes('misp')) return 'MISP';
  if (source.includes('ransomware.live')) return 'Ransomware.live';
  return source || '—';
};

export const actorLink = (url?: string) => /^https?:\/\//i.test(url || '') ? url : undefined;
