import { ReactNode } from "react";

interface PageHeaderProps {
  title: ReactNode;
  subtitle?: ReactNode;
  /** Optional right-aligned actions next to the title. */
  actions?: ReactNode;
  className?: string;
}

/**
 * Page title block: title, supporting line and optional actions, under the one
 * frame every page uses (`.page-head` — rule under the title, no card).
 * Use once at the top of a page, inside PageLayout.
 */
export function PageHeader({ title, subtitle, actions, className = "" }: PageHeaderProps) {
  return (
    <header className={`page-head ${className}`}>
      <div>
        <h1 className="page-title">{title}</h1>
        {subtitle && <p className="page-lede">{subtitle}</p>}
      </div>
      {actions && <div className="shrink-0">{actions}</div>}
    </header>
  );
}
