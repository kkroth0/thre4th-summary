import { ReactNode } from "react";

interface SectionProps {
  /** Hairline uppercase section label (ThreatBrief style). */
  title?: ReactNode;
  /** Optional right-aligned action (e.g. a "Clear" button). */
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}

/**
 * A page section in the ThreatBrief style: a small uppercase muted label with
 * generous bottom spacing. Keeps section headers consistent across pages.
 */
export function Section({ title, action, children, className = "" }: SectionProps) {
  return (
    <section className={`mb-12 ${className}`}>
      {(title || action) && (
        <div className="flex items-center justify-between mb-1.5">
          {title && (
            <h2 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
              {title}
            </h2>
          )}
          {action}
        </div>
      )}
      {children}
    </section>
  );
}
