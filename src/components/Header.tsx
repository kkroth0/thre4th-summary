import { Link, useLocation } from "react-router-dom";
import { BookOpen, Shield, Mail, Activity, Terminal, ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/ThemeToggle";
import { LanguageToggle } from "@/components/LanguageToggle";
import { useLanguage } from "@/contexts/LanguageContext";
import { cn } from "@/lib/utils";

interface HeaderProps {
  actions?: React.ReactNode;
  logoAddon?: React.ReactNode;
  onLogoClick?: () => void;
  showBackButton?: boolean;
}

export function Header({ actions, logoAddon, onLogoClick, showBackButton = false }: HeaderProps) {
  const { t } = useLanguage();
  const location = useLocation();
  const pathname = location.pathname;

  const handleLogoClick = (e: React.MouseEvent) => {
    if (onLogoClick) {
      e.preventDefault();
      onLogoClick();
    }
  };

  const navItems = [
    { path: "/", label: t("appName") || "ThreatSumm4ry", icon: Activity, isHome: true },
    { path: "/vendors", label: t("vendors") || "Vendors", icon: BookOpen },
    { path: "/dnsbl", label: t("dnsblCheck") || "DNSBL", icon: Shield },
    { path: "/newsletter", label: t("newsletter") || "CTI Feed", icon: Mail },
  ];

  return (
    <header className="sticky top-0 z-50 w-full border-b border-primary/10 bg-background/60 backdrop-blur-md supports-[backdrop-filter]:bg-background/40">
      <div className="container max-w-7xl mx-auto flex h-16 items-center justify-between px-4">
        {/* Brand Logo & Back Button */}
        <div className="flex items-center gap-2">
          {showBackButton && pathname !== "/" && (
            <Link to="/">
              <Button variant="ghost" size="sm" className="gap-1.5 h-8 px-2.5 rounded-full hover:bg-muted font-medium">
                <ArrowLeft className="h-4 w-4" />
                <span className="hidden sm:inline">{t('back') || "Back"}</span>
              </Button>
            </Link>
          )}
          {showBackButton && pathname !== "/" && (
            <div className="h-4 w-px bg-border/60 mx-1" />
          )}
          <Link
            to="/"
            onClick={handleLogoClick}
            className="flex items-center gap-2"
          >
            <Terminal className="h-5 w-5 text-primary animate-pulse" />
            <span className="font-bold tracking-tight text-xl bg-gradient-to-r from-primary via-primary/80 to-primary/50 bg-clip-text text-transparent hover:opacity-95 transition-all">
              {t("appName") || "ThreatSumm4ry"}
            </span>
          </Link>
          {logoAddon}
        </div>

        {/* Center Navigation Links (Desktop) */}
        <div className="hidden md:flex items-center justify-center flex-1 max-w-md mx-auto">
          <nav className="flex items-center gap-1 bg-muted/40 p-1 rounded-full border border-border/40">
            {navItems.map((item) => {
              const isActive = item.isHome ? pathname === "/" : pathname === item.path;
              const Icon = item.icon;
              return (
                <Link key={item.path} to={item.path}>
                  <Button
                    variant="ghost"
                    size="sm"
                    className={cn(
                      "gap-1.5 h-8 px-4 rounded-full text-sm font-semibold transition-all",
                      isActive
                        ? "bg-background text-primary shadow-sm hover:bg-background"
                        : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
                    )}
                  >
                    <Icon className="h-4 w-4" />
                    <span>{item.label}</span>
                  </Button>
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Right Side Actions Container */}
        <div className="flex items-center gap-2">
          {/* Mobile Quick Navigation Icons (only on smaller screens) */}
          <div className="flex md:hidden items-center gap-0.5 mr-1 bg-muted/30 p-0.5 rounded-full border border-border/30">
            {navItems.map((item) => {
              const isActive = item.isHome ? pathname === "/" : pathname === item.path;
              const Icon = item.icon;
              return (
                <Link key={item.path} to={item.path}>
                  <Button
                    variant="ghost"
                    size="icon"
                    className={cn(
                      "h-7 w-7 rounded-full p-0 transition-all",
                      isActive
                        ? "bg-background text-primary shadow-sm hover:bg-background"
                        : "text-muted-foreground hover:text-foreground"
                    )}
                    title={item.label}
                  >
                    <Icon className="h-3.5 w-3.5" />
                    <span className="sr-only">{item.label}</span>
                  </Button>
                </Link>
              );
            })}
          </div>

          {/* Custom actions passed from page */}
          {actions && <div className="flex items-center gap-1.5">{actions}</div>}

          {/* Divider if actions exist */}
          {actions && <div className="hidden sm:block w-px h-4 bg-border/60 mx-1" />}

          {/* Global Language and Theme Toggles */}
          <div className="flex items-center gap-1">
            <LanguageToggle />
            <ThemeToggle />
          </div>
        </div>
      </div>
    </header>
  );
}
