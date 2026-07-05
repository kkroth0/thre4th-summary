import { ReactNode } from "react";

interface PageHeaderProps {
  title: ReactNode;
  subtitle?: ReactNode;
  /** Optional right-aligned actions next to the title. */
  actions?: ReactNode;
  className?: string;
}

/**
 * Page title block in the ThreatBrief style: a large semibold heading with a
 * muted subtitle. Use once at the top of a page, inside PageLayout.
 */
export function PageHeader({ title, subtitle, actions, className = "" }: PageHeaderProps) {
  return (
    <header className={`mb-10 ${className}`}>
      <div className="flex items-start justify-between gap-4">
        <h1 className="text-3xl font-semibold tracking-tight">{title}</h1>
        {actions && <div className="shrink-0">{actions}</div>}
      </div>
      {subtitle && (
        <p className="text-muted-foreground mt-2 leading-relaxed">{subtitle}</p>
      )}
    </header>
  );
}
