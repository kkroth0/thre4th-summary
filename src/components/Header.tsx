import { Link, useLocation } from "react-router-dom";
import { BookOpen, Shield, Mail, Activity, Terminal, ArrowLeft, ShieldAlert, MailWarning, ChevronLeft, ChevronRight, Globe } from "lucide-react";
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
    { path: "/dns-visualizer", label: t("dnsVisualizer") || "DNS Visualizer", icon: Globe },
    { path: "/phishing-analyzer", label: language === "pt" ? "Análise de Phishing" : "Phishing Analyzer", icon: MailWarning },
    { path: "/newsletter", label: language === "pt" ? "Feed de Advisories" : "Advisory Feed", icon: Mail },
    { path: "/cves", label: language === "pt" ? "Painel de CVEs" : "CVE Dashboard", icon: Shield },
    { path: "/features", label: language === "pt" ? "Funcionalidades" : "Features", icon: Terminal },
  ];

  const renderNavItem = (item: typeof navItems[0], isActive: boolean) => {
    const Icon = item.icon;
    const buttonElement = (
      <Button
        variant="ghost"
        className={cn(
          "w-full gap-3 h-10.5 rounded-xl text-[13px] font-semibold transition-all duration-200",
          isCollapsed ? "justify-center px-0 w-11 h-11 rounded-xl mx-auto" : "justify-start px-3.5",
          isActive
            ? "bg-primary/10 text-primary hover:bg-primary/15 hover:text-primary"
            : "text-muted-foreground/80 hover:text-foreground hover:bg-muted/20"
        )}
      >
        <Icon className={cn("h-5 w-5 shrink-0", isActive ? "text-primary" : "text-muted-foreground")} />
        {!isCollapsed && <span>{item.label}</span>}
      </Button>
    );

    return (
      <Link key={item.path} to={item.path} className="w-full relative block">
        {isActive && (
          <div className={cn(
            "absolute bg-primary rounded-r transition-all duration-300", 
            isCollapsed ? "left-0 top-2 bottom-2 w-1" : "left-0 top-1.5 bottom-1.5 w-0.5"
          )} />
        )}
        {isCollapsed ? (
          <Tooltip delayDuration={150}>
            <TooltipTrigger asChild>
              {buttonElement}
            </TooltipTrigger>
            <TooltipContent side="right" className="font-semibold text-xs bg-popover border border-primary/10 text-popover-foreground shadow-md backdrop-blur-md py-1.5 px-2.5">
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
              <div className="h-6 w-6 rounded bg-indigo-600 flex items-center justify-center font-black text-white text-[10px] shadow-sm shadow-indigo-600/30 select-none shrink-0">T</div>
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
      <aside className={cn(
        "hidden lg:flex lg:flex-col lg:fixed lg:left-0 lg:top-0 lg:h-screen lg:border-r lg:border-primary/10 lg:bg-card/45 lg:backdrop-blur-md lg:z-30 lg:justify-between lg:overflow-y-auto transition-all duration-300",
        isCollapsed ? "lg:w-20 lg:p-3" : "lg:w-64 lg:p-4.5"
      )}>
        {/* Top Part */}
        <div className="flex flex-col gap-6">
          {/* Brand Logo Container */}
          <div className={cn("flex items-center gap-2 relative py-2", isCollapsed ? "justify-center" : "pl-2")}>
            <Link
              to="/"
              onClick={handleLogoClick}
              className="flex items-center gap-2.5"
            >
              <div className="h-6 w-6 rounded bg-indigo-600 flex items-center justify-center font-black text-white text-[10px] shadow-sm shadow-indigo-600/30 select-none shrink-0">T</div>
              {!isCollapsed && (
                <span className="font-bold tracking-tight text-[17px] bg-gradient-to-r from-primary via-primary/80 to-primary/50 bg-clip-text text-transparent hover:opacity-95 transition-all">
                  {t("appName") || "ThreatSumm4ry"}
                </span>
              )}
            </Link>
            {!isCollapsed && logoAddon}
          </div>

          {/* Navigation Links Grouped by Categories */}
          <div className="flex flex-col gap-5">
            {/* Category 1: SCAN & SEARCH */}
            <div>
              {!isCollapsed ? (
                <div className="px-3 mb-2.5 text-[11px] font-bold text-muted-foreground/50 uppercase tracking-wider">
                  {language === 'pt' ? 'Escaneamento' : 'Scan & Search'}
                </div>
              ) : (
                <div className="h-px bg-primary/10 my-3.5 mx-2" />
              )}
              <div className="flex flex-col gap-1">
                {navItems.filter(item => item.isHome).map((item) => renderNavItem(item, pathname === "/"))}
              </div>
            </div>

            {/* Category 2: INTELLIGENCE TOOLS */}
            <div>
              {!isCollapsed ? (
                <div className="px-3 mb-2.5 text-[11px] font-bold text-muted-foreground/50 uppercase tracking-wider">
                  {language === 'pt' ? 'Ferramentas' : 'Intelligence Tools'}
                </div>
              ) : (
                <div className="h-px bg-primary/10 my-3.5 mx-2" />
              )}
              <div className="flex flex-col gap-1">
                {navItems.filter(item => !item.isHome && item.path !== "/newsletter" && item.path !== "/cves").map((item) => renderNavItem(item, pathname === item.path))}
              </div>
            </div>

            {/* Category 3: THREAT FEEDS */}
            <div>
              {!isCollapsed ? (
                <div className="px-3 mb-2.5 text-[11px] font-bold text-muted-foreground/50 uppercase tracking-wider">
                  {language === 'pt' ? 'Feeds de Ameaças' : 'Threat Feeds'}
                </div>
              ) : (
                <div className="h-px bg-primary/10 my-3.5 mx-2" />
              )}
              <div className="flex flex-col gap-1">
                {navItems.filter(item => item.path === "/newsletter" || item.path === "/cves").map((item) => renderNavItem(item, pathname === item.path))}
              </div>
            </div>
          </div>
        </div>

        {/* Bottom Part */}
        <div className="flex flex-col gap-4 border-t border-primary/10 pt-4">
          {/* Collapse Trigger Button */}
          <Button
            variant="ghost"
            onClick={toggleSidebar}
            className={cn(
              "w-full h-10 rounded-xl text-muted-foreground/80 hover:text-foreground hover:bg-muted/20 flex items-center gap-3 transition-all duration-200",
              isCollapsed ? "justify-center px-0 w-11 h-11 rounded-xl mx-auto" : "px-3.5 justify-start"
            )}
            title={isCollapsed ? (language === "pt" ? "Expandir" : "Expand") : (language === "pt" ? "Colapsar" : "Collapse")}
          >
            {isCollapsed ? (
              <ChevronRight className="h-5 w-5 text-muted-foreground" />
            ) : (
              <>
                <ChevronLeft className="h-5 w-5 text-muted-foreground" />
                <span className="text-xs font-semibold">{language === "pt" ? "Recolher Menu" : "Collapse Sidebar"}</span>
              </>
            )}
          </Button>

          {/* Custom actions passed from page */}
          {actions && (
            <div className="w-full">
              {actions}
            </div>
          )}

          {/* Theme & Language Toggles */}
          <div className={cn("flex items-center justify-between gap-2", isCollapsed ? "flex-col justify-center px-0 gap-3" : "px-1")}>
            <div className={cn("flex items-center gap-2", isCollapsed && "flex-col")}>
              <LanguageToggle />
              {!isCollapsed && (
                <span className="text-[10px] font-bold text-muted-foreground/50 uppercase tracking-wider">
                  {t('lang') || "Lang"}
                </span>
              )}
            </div>
            <ThemeToggle />
          </div>
        </div>
      </aside>
    </>
  );
}
