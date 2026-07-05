import { ReactNode } from "react";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { useSidebar } from "@/contexts/SidebarContext";

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
   * Chrome-only mode: render just the shell (Header/Footer + sidebar-aware
   * padding) and let the page supply its own body — for full-bleed or
   * self-laying-out pages that don't want the centered content column.
   */
  bare?: boolean;
}

/**
 * Standard page shell, extracted from the ThreatBrief (DailyBulletin) design:
 * a calm, centered column with generous vertical rhythm, sidebar-aware left
 * padding, and the shared Header/Footer. All pages render inside this so the
 * chrome, spacing and background stay consistent site-wide.
 */
export function PageLayout({
  children,
  width = "max-w-3xl",
  showBackButton = true,
  headerActions,
  className = "",
  bare = false,
}: PageLayoutProps) {
  const { isCollapsed } = useSidebar();
  return (
    <div
      className={`min-h-screen bg-background flex flex-col transition-all duration-300 ${
        isCollapsed ? "lg:pl-20" : "lg:pl-64"
      }`}
    >
      <Header showBackButton={showBackButton} actions={headerActions} />
      {bare ? (
        children
      ) : (
        <main className={`flex-1 container mx-auto px-4 py-12 ${width} ${className}`}>
          {children}
        </main>
      )}
      <Footer />
    </div>
  );
}
