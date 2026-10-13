import { formatPublicationDate, type PublicationDate } from '@/utils/publicationDate';

export function NewsTimestamp({ item, pt = true, className }: { item: PublicationDate; pt?: boolean; className?: string }) {
  const date = formatPublicationDate(item, pt);
  return <span className={className} title={date.title}>{(item.dateInferred || item.publicationDateBasis === 'updated' || item.repository?.dateBasis === 'last-commit') && <span className="mr-1 text-muted-foreground">{date.label}:</span>}{date.text}</span>;
}
