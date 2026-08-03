import { ReactNode } from "react";
import { Header, NavTabs } from "@/components/Header";
import { Footer } from "@/components/Footer";

interface PageLayoutProps {
  children: ReactNode;
  /**
   * Tailwind max-width class for the centered main column. Defaults to the
   * ThreatBrief width (`max-w-3xl`). Dashboards pass a wider one
   * (e.g. `max-w-6xl` / `max-w-7xl`) so tables/charts aren't squeezed.
   */
  width?: string;
  showBackButton?: boolean;
  /** Optional actions passed through to the Header. */
  headerActions?: ReactNode;
  /** Extra classes for the <main> column (rarely needed). */
  className?: string;
  /**
   * Chrome-only mode: render just the shell (Header/Footer) and let the page
   * supply its own body — for full-bleed or
   * self-laying-out pages that don't want the centered content column.
   */
  bare?: boolean;
}

/**
 * Standard page shell: Vercel-like top navigation, centered content, shared
 * Footer, and the subtle background treatment used across internal tools.
 */
export function PageLayout({
  children,
  width = "max-w-3xl",
  showBackButton = false,
  headerActions,
  className = "",
  bare = false,
}: PageLayoutProps) {
  return (
    <div className="soc-shell relative min-h-screen bg-background flex flex-col">
      <div className="soc-grid pointer-events-none absolute inset-0 z-0" />
      <Header showBackButton={showBackButton} actions={headerActions} />
      <NavTabs />
      {bare ? (
        <div className="relative z-10 flex-1">{children}</div>
      ) : (
        <main className={`relative z-10 flex-1 container mx-auto px-4 py-12 ${width} ${className}`}>
          {children}
        </main>
      )}
      <Footer />
    </div>
  );
}
