export interface PublicationDate {
  pubDate: string;
  dateInferred?: boolean;
  publicationTimeKnown?: boolean;
  publicationDateBasis?: string;
  firstCollectedAt?: string;
  repository?: { dateBasis?: string };
}

export function formatPublicationDate(item: PublicationDate, pt = true) {
  const collected = item.dateInferred === true;
  const value = collected ? item.firstCollectedAt || item.pubDate : item.pubDate;
  const hasTime = collected || (item.publicationTimeKnown !== false && item.repository?.dateBasis !== 'report-date' && /[T\s]\d{2}:\d{2}/.test(value));
  // Date-only publishers do not supply a timezone: preserve their calendar day.
  const date = new Date(hasTime ? value : value.slice(0, 10) + 'T12:00:00Z');
  const updated = item.publicationDateBasis === 'updated' || item.repository?.dateBasis === 'last-commit';
  const label = collected ? (pt ? 'Coleta' : 'Collected') : updated ? (pt ? 'Atualização' : 'Updated') : (pt ? 'Publicação' : 'Published');
  if (!Number.isFinite(date.getTime())) return { text: '—', label, title: pt ? 'Data indisponível' : 'Date unavailable' };
  const locale = pt ? 'pt-BR' : 'en-US';
  const day = date.toLocaleDateString(locale, { timeZone: 'America/Fortaleza', day: '2-digit', month: '2-digit', year: 'numeric' });
  const time = hasTime ? date.toLocaleTimeString(locale, { timeZone: 'America/Fortaleza', hour: '2-digit', minute: '2-digit', hour12: false }) : (pt ? 'hora não informada' : 'time unavailable');
  return { text: `${day} · ${time}`, label, title: `${label}: ${day} · ${time}${hasTime ? ' (Fortaleza, UTC−3)' : ''}` };
}
