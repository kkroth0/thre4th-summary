import { Link, useLocation } from "react-router-dom";
import { BookOpen, Shield, Mail, Activity, Terminal, ArrowLeft, ShieldAlert, MailWarning, ChevronLeft, ChevronRight, Globe, CalendarCheck, Crosshair, FileText, LogIn, Settings as SettingsIcon, Megaphone } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { ThemeToggle } from "@/components/ThemeToggle";
import { LanguageToggle } from "@/components/LanguageToggle";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";
import { useAuth } from "@/contexts/AuthContext";
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
  const { auth, loading: authLoading } = useAuth();
  const location = useLocation();
  const pathname = location.pathname;

  // Bloco de usuário (sidebar): avatar -> /profile, ou botão "Entrar" -> /login.
  const renderUser = () => {
    if (authLoading) {
      return <div className={cn("h-11 rounded-xl bg-muted/30 animate-pulse", isCollapsed ? "w-11 mx-auto" : "w-full")} />;
    }
    if (auth.authenticated) {
      const chip = (
        <Button
          variant="ghost"
          className={cn(
            "w-full transition-all duration-200",
            isCollapsed ? "justify-center px-0 w-11 h-11 rounded-xl mx-auto" : "justify-start px-2.5 gap-2.5 h-12 rounded-xl",
            pathname === "/profile"
              ? "bg-primary/15 ring-1 ring-inset ring-primary/20 hover:bg-primary/20"
              : "hover:bg-muted/20"
          )}
        >
          <Avatar className="h-7 w-7 ring-1 ring-primary/20 shrink-0">
            <AvatarImage src={`https://github.com/${auth.login}.png?size=64`} alt={auth.login} />
            <AvatarFallback className="text-xs font-semibold bg-primary/10 text-primary">{auth.login?.[0]?.toUpperCase() ?? "?"}</AvatarFallback>
          </Avatar>
          {!isCollapsed && (
            <div className="flex flex-col items-start leading-tight min-w-0">
              <span className="text-[13px] font-semibold truncate max-w-[150px]">{auth.login}</span>
              <span className="text-[10px] text-muted-foreground">{language === "pt" ? "Ver perfil" : "View profile"}</span>
            </div>
          )}
        </Button>
      );
      return (
        <Link to="/profile" className="w-full block">
          {isCollapsed ? (
            <Tooltip delayDuration={150}>
              <TooltipTrigger asChild>{chip}</TooltipTrigger>
              <TooltipContent side="right" className="font-semibold text-xs">{auth.login}</TooltipContent>
            </Tooltip>
          ) : chip}
        </Link>
      );
    }
    const signInBtn = (
      <Button
        variant="outline"
        className={cn("gap-2 rounded-xl font-semibold", isCollapsed ? "px-0 w-11 h-11 mx-auto" : "w-full h-10 text-[13px]")}
      >
        <LogIn className="h-4 w-4" />
        {!isCollapsed && <span>{language === "pt" ? "Entrar" : "Sign in"}</span>}
      </Button>
    );
    return (
      <Link to="/login" className="w-full block">
        {isCollapsed ? (
          <Tooltip delayDuration={150}>
            <TooltipTrigger asChild>{signInBtn}</TooltipTrigger>
            <TooltipContent side="right" className="font-semibold text-xs">{language === "pt" ? "Entrar" : "Sign in"}</TooltipContent>
          </Tooltip>
        ) : signInBtn}
      </Link>
    );
  };

  const handleLogoClick = (e: React.MouseEvent) => {
    if (onLogoClick) {
      e.preventDefault();
      onLogoClick();
    }
  };

  const navItems = [
    { path: "/", label: t("appName") || "ThreatSumm4ry", icon: Activity, isHome: true },
    { path: "/advisories", label: "Advisories", icon: Megaphone },
    { path: "/vendors", label: t("vendors") || "Vendors", icon: BookOpen },
    { path: "/dnsbl", label: t("dnsblCheck") || "DNSBL Check", icon: ShieldAlert },
    { path: "/dns-visualizer", label: t("dnsVisualizer") || "DNS Visualizer", icon: Globe },
    { path: "/phishing-analyzer", label: language === "pt" ? "Análise de Phishing" : "Phishing Analyzer", icon: MailWarning },
    { path: "/threat-hunting", label: language === "pt" ? "Threat Hunting" : "Threat Hunting", icon: Crosshair, premium: true },
    { path: "/threat-brief", label: "Threat Brief", icon: FileText, premium: true },
    { path: "/newsletter", label: language === "pt" ? "Coletor de Intel" : "Intel Collector", icon: Mail, premium: true },
    { path: "/cves", label: language === "pt" ? "Painel de CVEs" : "CVE Dashboard", icon: Shield },
    { path: "/patch-tuesday", label: language === "pt" ? "Patch Tuesday" : "Patch Tuesday", icon: CalendarCheck },
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
            ? "bg-primary/15 text-primary ring-1 ring-inset ring-primary/20 hover:bg-primary/20 hover:text-primary"
            : "text-muted-foreground/80 hover:text-foreground hover:bg-muted/20"
        )}
      >
        <Icon strokeWidth={isActive ? 2.25 : 1.9} className={cn("h-[18px] w-[18px] shrink-0", isActive ? "text-primary" : "text-muted-foreground")} />
        {!isCollapsed && <span className="flex-1 text-left truncate">{item.label}</span>}
        {!isCollapsed && (item as { premium?: boolean }).premium && (
          <span className="ml-auto shrink-0 text-[9px] font-bold tracking-wider px-1.5 py-0.5 rounded-md bg-amber-500/15 text-amber-600 dark:text-amber-400 ring-1 ring-inset ring-amber-500/20">PRO</span>
        )}
      </Button>
    );

    return (
      <Link key={item.path} to={item.path} className="w-full relative block">
        {isActive && (
          <div className={cn(
            "absolute bg-primary rounded-r-full transition-all duration-300",
            isCollapsed ? "left-0 top-2 bottom-2 w-1" : "left-0 top-1.5 bottom-1.5 w-1"
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

  const renderCategory = (label: string, paths: string[]) => {
    const items = navItems.filter((i) => paths.includes(i.path));
    if (!items.length) return null;
    return (
      <div>
        {!isCollapsed ? (
          <div className="px-3 mb-2 text-[11px] font-bold text-muted-foreground/70 uppercase tracking-wider">
            {label}
          </div>
        ) : (
          <div className="h-px bg-primary/10 my-3 mx-2" />
        )}
        <div className="flex flex-col gap-1">
          {items.map((item) => renderNavItem(item, pathname === item.path))}
        </div>
      </div>
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
              <div className="h-6 w-6 rounded bg-primary flex items-center justify-center font-black text-primary-foreground text-[10px] shadow-sm shadow-primary/30 select-none shrink-0">T</div>
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

            {/* User / auth (mobile) */}
            {!authLoading && (
              auth.authenticated ? (
                <Link to="/profile" className="shrink-0 ml-0.5">
                  <Avatar className="h-7 w-7 ring-1 ring-primary/20">
                    <AvatarImage src={`https://github.com/${auth.login}.png?size=48`} alt={auth.login} />
                    <AvatarFallback className="text-[10px] font-semibold bg-primary/10 text-primary">{auth.login?.[0]?.toUpperCase() ?? "?"}</AvatarFallback>
                  </Avatar>
                </Link>
              ) : (
                <Link to="/login" className="shrink-0 ml-0.5">
                  <Button variant="ghost" size="icon" className="h-7 w-7 rounded-full text-muted-foreground hover:text-foreground">
                    <LogIn className="h-4 w-4" />
                  </Button>
                </Link>
              )
            )}
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
              <div className="h-6 w-6 rounded bg-primary flex items-center justify-center font-black text-primary-foreground text-[10px] shadow-sm shadow-primary/30 select-none shrink-0">T</div>
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
            {/* Home — sem header de categoria */}
            <div className="flex flex-col gap-1">
              {navItems.filter((item) => item.isHome).map((item) => renderNavItem(item, pathname === "/"))}
            </div>

            {renderCategory(language === 'pt' ? 'Investigar' : 'Investigate',
              ["/vendors", "/dnsbl", "/dns-visualizer", "/phishing-analyzer", "/threat-hunting"])}

            {renderCategory(language === 'pt' ? 'Inteligência' : 'Intelligence',
              ["/newsletter", "/cves", "/patch-tuesday"])}

            {renderCategory(language === 'pt' ? 'Relatórios' : 'Reports',
              ["/threat-brief"])}

            {/* Features — discreto, sem categoria */}
            <div className="flex flex-col gap-1">
              {navItems.filter((item) => item.path === "/features").map((item) => renderNavItem(item, pathname === item.path))}
            </div>
          </div>
        </div>

        {/* Bottom Part */}
        <div className="flex flex-col gap-4 border-t border-primary/10 pt-4">
          {/* User / auth */}
          {renderUser()}

          {/* Settings (signed-in only) */}
          {!authLoading && auth.authenticated && (
            <Link to="/settings" className="w-full block -mt-2">
              {isCollapsed ? (
                <Tooltip delayDuration={150}>
                  <TooltipTrigger asChild>
                    <Button variant="ghost" className={cn("w-11 h-11 rounded-xl mx-auto justify-center px-0", pathname === "/settings" ? "bg-primary/15 text-primary ring-1 ring-inset ring-primary/20" : "text-muted-foreground/80 hover:text-foreground hover:bg-muted/20")}>
                      <SettingsIcon className="h-[18px] w-[18px]" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent side="right" className="font-semibold text-xs">{language === "pt" ? "Configurações" : "Settings"}</TooltipContent>
                </Tooltip>
              ) : (
                <Button variant="ghost" className={cn("w-full h-10 rounded-xl justify-start px-3.5 gap-3 text-[13px] font-semibold", pathname === "/settings" ? "bg-primary/15 text-primary ring-1 ring-inset ring-primary/20" : "text-muted-foreground/80 hover:text-foreground hover:bg-muted/20")}>
                  <SettingsIcon className="h-[18px] w-[18px]" /> {language === "pt" ? "Configurações" : "Settings"}
                </Button>
              )}
            </Link>
          )}

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
