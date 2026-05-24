import { Link, useLocation } from "react-router-dom";
import { BookOpen, Shield, Mail, Activity, Terminal, ArrowLeft, ShieldAlert, MailWarning, ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/ThemeToggle";
import { LanguageToggle } from "@/components/LanguageToggle";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

interface HeaderProps {
  actions?: React.ReactNode;
  logoAddon?: React.ReactNode;
  onLogoClick?: () => void;
  showBackButton?: boolean;
}

export function Header({ actions, logoAddon, onLogoClick, showBackButton = false }: HeaderProps) {
  const { t, language } = useLanguage();
  const { isCollapsed, toggleSidebar } = useSidebar();
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
    { path: "/dnsbl", label: t("dnsblCheck") || "DNSBL Check", icon: ShieldAlert },
    { path: "/phishing-analyzer", label: language === "pt" ? "Análise de Phishing" : "Phishing Analyzer", icon: MailWarning },
    { path: "/newsletter", label: language === "pt" ? "Feed de Advisories" : "Advisory Feed", icon: Mail },
    { path: "/cves", label: language === "pt" ? "Painel de CVEs" : "CVE Dashboard", icon: Shield },
  ];

  const renderNavItem = (item: typeof navItems[0], isActive: boolean) => {
    const Icon = item.icon;
    const buttonElement = (
      <Button
        variant="ghost"
        className={cn(
          "w-full gap-2.5 h-8.5 rounded-lg text-[11px] font-semibold transition-all duration-200",
          isCollapsed ? "justify-center px-0 w-9 h-9 rounded-full mx-auto" : "justify-start px-3",
          isActive
            ? "bg-primary/10 text-primary hover:bg-primary/15 hover:text-primary"
            : "text-muted-foreground/80 hover:text-foreground hover:bg-muted/20"
        )}
      >
        <Icon className={cn("h-4 w-4 shrink-0", isActive ? "text-primary" : "text-muted-foreground")} />
        {!isCollapsed && <span>{item.label}</span>}
      </Button>
    );

    return (
      <Link key={item.path} to={item.path} className="w-full relative block">
        {isActive && (
          <div className={cn(
            "absolute bg-primary rounded-r transition-all duration-300", 
            isCollapsed ? "left-0 top-2 bottom-2 w-1" : "left-0 top-1 bottom-1 w-0.5"
          )} />
        )}
        {isCollapsed ? (
          <Tooltip delayDuration={150}>
            <TooltipTrigger asChild>
              {buttonElement}
            </TooltipTrigger>
            <TooltipContent side="right" className="font-semibold text-xs bg-popover border border-primary/10 text-popover-foreground shadow-md backdrop-blur-md">
              {item.label}
            </TooltipContent>
          </Tooltip>
        ) : (
          buttonElement
        )}
      </Link>
    );
  };

  return (
    <>
      {/* Mobile/Tablet Header (lg:hidden) */}
      <header className="lg:hidden sticky top-0 z-50 w-full border-b border-primary/10 bg-background/60 backdrop-blur-md supports-[backdrop-filter]:bg-background/40">
        <div className="container max-w-7xl mx-auto flex h-16 items-center justify-between px-4 relative">
          {/* Back Button */}
          {showBackButton && pathname !== "/" && (
            <Link to="/" className="absolute left-4 top-1/2 -translate-y-1/2 z-20">
              <Button variant="ghost" size="icon" className="h-8 w-8 rounded-full hover:bg-muted">
                <ArrowLeft className="h-4 w-4" />
                <span className="sr-only">{t('back') || "Back"}</span>
              </Button>
            </Link>
          )}

          {/* Brand Logo Container */}
          <div className="flex items-center pl-12">
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

          {/* Right Side Actions Container */}
          <div className="flex items-center gap-2">
            {/* Mobile Quick Navigation Icons */}
            <div className="flex lg:hidden items-center gap-0.5 mr-1 bg-muted/30 p-0.5 rounded-full border border-border/30">
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

      {/* Desktop Sidebar (lg:flex) */}
      <aside className="hidden lg:flex lg:flex-col lg:fixed lg:left-0 lg:top-0 lg:h-screen lg:w-56 lg:border-r lg:border-primary/10 lg:bg-card/45 lg:backdrop-blur-md lg:p-4 lg:z-30 lg:justify-between lg:overflow-y-auto">
        {/* Top Part */}
        <div className="flex flex-col gap-6">
          {/* Brand Logo Container */}
          <div className="flex items-center gap-2 relative pl-2 py-2">
            <Link
              to="/"
              onClick={handleLogoClick}
              className="flex items-center gap-2"
            >
              <Terminal className="h-4.5 w-4.5 text-primary animate-pulse" />
              <span className="font-bold tracking-tight text-[15px] bg-gradient-to-r from-primary via-primary/80 to-primary/50 bg-clip-text text-transparent hover:opacity-95 transition-all">
                {t("appName") || "ThreatSumm4ry"}
              </span>
            </Link>
            {logoAddon}
          </div>

          {/* Navigation Links Grouped by Categories */}
          <div className="flex flex-col gap-4">
            {/* Category 1: SCAN & SEARCH */}
            <div>
              <div className="px-3 mb-1.5 text-[10px] font-bold text-muted-foreground/45 uppercase tracking-widest">
                {language === 'pt' ? 'Escaneamento' : 'Scan & Search'}
              </div>
              <div className="flex flex-col gap-0.5">
                {navItems.filter(item => item.isHome).map((item) => {
                  const isActive = pathname === "/";
                  const Icon = item.icon;
                  return (
                    <Link key={item.path} to={item.path} className="w-full relative block">
                      {isActive && (
                        <div className="absolute left-0 top-1 bottom-1 w-0.5 bg-primary rounded-r" />
                      )}
                      <Button
                        variant="ghost"
                        className={cn(
                          "w-full justify-start gap-2.5 h-8.5 px-3 rounded-lg text-xs font-semibold transition-all duration-200",
                          isActive
                            ? "bg-primary/10 text-primary hover:bg-primary/15 hover:text-primary"
                            : "text-muted-foreground/80 hover:text-foreground hover:bg-muted/20"
                        )}
                      >
                        <Icon className={cn("h-4 w-4 shrink-0", isActive ? "text-primary" : "text-muted-foreground")} />
                        <span>{item.label}</span>
                      </Button>
                    </Link>
                  );
                })}
              </div>
            </div>

            {/* Category 2: INTELLIGENCE TOOLS */}
            <div>
              <div className="px-3 mb-1.5 text-[10px] font-bold text-muted-foreground/45 uppercase tracking-widest">
                {language === 'pt' ? 'Ferramentas' : 'Intelligence Tools'}
              </div>
              <div className="flex flex-col gap-0.5">
                {navItems.filter(item => !item.isHome && item.path !== "/newsletter" && item.path !== "/cves").map((item) => {
                  const isActive = pathname === item.path;
                  const Icon = item.icon;
                  return (
                    <Link key={item.path} to={item.path} className="w-full relative block">
                      {isActive && (
                        <div className="absolute left-0 top-1 bottom-1 w-0.5 bg-primary rounded-r" />
                      )}
                      <Button
                        variant="ghost"
                        className={cn(
                          "w-full justify-start gap-2.5 h-8.5 px-3 rounded-lg text-xs font-semibold transition-all duration-200",
                          isActive
                            ? "bg-primary/10 text-primary hover:bg-primary/15 hover:text-primary"
                            : "text-muted-foreground/80 hover:text-foreground hover:bg-muted/20"
                        )}
                      >
                        <Icon className={cn("h-4 w-4 shrink-0", isActive ? "text-primary" : "text-muted-foreground")} />
                        <span>{item.label}</span>
                      </Button>
                    </Link>
                  );
                })}
              </div>
            </div>

            {/* Category 3: THREAT FEEDS */}
            <div>
              <div className="px-3 mb-1.5 text-[10px] font-bold text-muted-foreground/45 uppercase tracking-widest">
                {language === 'pt' ? 'Feeds de Ameaças' : 'Threat Feeds'}
              </div>
              <div className="flex flex-col gap-0.5">
                {navItems.filter(item => item.path === "/newsletter" || item.path === "/cves").map((item) => {
                  const isActive = pathname === item.path;
                  const Icon = item.icon;
                  return (
                    <Link key={item.path} to={item.path} className="w-full relative block">
                      {isActive && (
                        <div className="absolute left-0 top-1 bottom-1 w-0.5 bg-primary rounded-r" />
                      )}
                      <Button
                        variant="ghost"
                        className={cn(
                          "w-full justify-start gap-2.5 h-8.5 px-3 rounded-lg text-xs font-semibold transition-all duration-200",
                          isActive
                            ? "bg-primary/10 text-primary hover:bg-primary/15 hover:text-primary"
                            : "text-muted-foreground/80 hover:text-foreground hover:bg-muted/20"
                        )}
                      >
                        <Icon className={cn("h-4 w-4 shrink-0", isActive ? "text-primary" : "text-muted-foreground")} />
                        <span>{item.label}</span>
                      </Button>
                    </Link>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* Bottom Part */}
        <div className="flex flex-col gap-4 border-t border-primary/10 pt-4">
          {/* Custom actions passed from page */}
          {actions && (
            <div className="w-full">
              {actions}
            </div>
          )}

          {/* Theme & Language Toggles */}
          <div className="flex items-center justify-between gap-2 px-1">
            <div className="flex items-center gap-2">
              <LanguageToggle />
              <span className="text-[10px] font-bold text-muted-foreground/50 uppercase tracking-wider">
                {t('lang') || "Lang"}
              </span>
            </div>
            <ThemeToggle />
          </div>
        </div>
      </aside>
    </>
  );
}
