import { Link, useLocation } from "react-router-dom";
import { BookOpen, Shield, Mail, Activity, Terminal, ArrowLeft, ShieldAlert, MailWarning, ChevronLeft, ChevronRight, CalendarCheck, Crosshair, FileText, LogIn, Settings as SettingsIcon, Megaphone, ShieldCheck, Users, Menu } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Sheet, SheetClose, SheetContent, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
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
  const { t, language, tr } = useLanguage();
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
              <span className="text-[10px] text-muted-foreground">{tr({ pt: "Ver perfil", en: "View profile", es: "Ver perfil", fr: "Voir le profil" })}</span>
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
        {!isCollapsed && <span>{tr({ pt: "Entrar", en: "Sign in", es: "Iniciar sesión", fr: "Se connecter" })}</span>}
      </Button>
    );
    return (
      <Link to="/login" className="w-full block">
        {isCollapsed ? (
          <Tooltip delayDuration={150}>
            <TooltipTrigger asChild>{signInBtn}</TooltipTrigger>
            <TooltipContent side="right" className="font-semibold text-xs">{tr({ pt: "Entrar", en: "Sign in", es: "Iniciar sesión", fr: "Se connecter" })}</TooltipContent>
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
    { path: "/phishing-analyzer", label: tr({ pt: "Análise de Phishing", en: "Phishing Analyzer", es: "Análisis de Phishing", fr: "Analyse de Phishing" }), icon: MailWarning },
    { path: "/threat-hunting", label: "Threat Hunting", icon: Crosshair, premium: true },
    { path: "/threat-brief", label: "Threat Brief", icon: FileText, premium: true },
    { path: "/newsletter", label: tr({ pt: "Coletor de Intel", en: "Intel Collector", es: "Colector de Intel", fr: "Collecteur d'Intel" }), icon: Mail, premium: true },
    { path: "/cves", label: tr({ pt: "Painel de CVEs", en: "CVE Dashboard", es: "Panel de CVEs", fr: "Tableau de bord CVE" }), icon: Shield },
    { path: "/atores", label: tr({ pt: "Atores", en: "Threat Actors", es: "Actores", fr: "Acteurs" }), icon: Users },
    { path: "/patch-tuesday", label: "Patch Tuesday", icon: CalendarCheck },
    { path: "/features", label: tr({ pt: "Funcionalidades", en: "Features", es: "Funciones", fr: "Fonctionnalités" }), icon: Terminal },
  ];

  const isRouteActive = (path: string) => (path === "/" ? pathname === "/" : pathname === path || pathname.startsWith(`${path}/`));

  const renderNavItem = (item: typeof navItems[0], isActive: boolean) => {
    const Icon = item.icon;
    const buttonElement = (
      <Button
        variant="ghost"
        className={cn(
          "w-full gap-3 h-10 rounded-xl text-[13px] font-semibold transition-all duration-200",
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
            <TooltipContent side="right" className="font-semibold text-xs bg-popover border border-border/50 text-popover-foreground shadow-md py-1.5 px-2.5">
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
          {items.map((item) => renderNavItem(item, isRouteActive(item.path)))}
        </div>
      </div>
    );
  };

  const renderMobileNavItem = (item: typeof navItems[0]) => {
    const Icon = item.icon;
    const isActive = isRouteActive(item.path);

    return (
      <SheetClose asChild key={item.path}>
        <Link to={item.path} className="block">
          <Button
            variant="ghost"
            className={cn(
              "w-full h-11 justify-start gap-3 rounded-xl px-3 text-[13px] font-semibold",
              isActive
                ? "bg-primary/15 text-primary ring-1 ring-inset ring-primary/20 hover:bg-primary/20 hover:text-primary"
                : "text-muted-foreground hover:bg-muted/40 hover:text-foreground"
            )}
          >
            <Icon className={cn("h-[18px] w-[18px] shrink-0", isActive ? "text-primary" : "text-muted-foreground")} />
            <span className="flex-1 text-left">{item.label}</span>
            {(item as { premium?: boolean }).premium && (
              <span className="shrink-0 rounded-md bg-amber-500/15 px-1.5 py-0.5 text-[9px] font-bold tracking-wider text-amber-600 ring-1 ring-inset ring-amber-500/20 dark:text-amber-400">
                PRO
              </span>
            )}
          </Button>
        </Link>
      </SheetClose>
    );
  };

  return (
    <>
      {/* Mobile/Tablet Header (lg:hidden) */}
      <header className="lg:hidden sticky top-0 z-50 w-full border-b border-border/50 bg-background/60 supports-[backdrop-filter]:bg-background/40">
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
          <div className={cn("flex min-w-0 items-center", showBackButton && pathname !== "/" ? "pl-12" : "")}>
            <Link
              to="/"
              onClick={handleLogoClick}
              className="flex min-w-0 items-center gap-2"
            >
              <div className="h-6 w-6 rounded bg-primary flex items-center justify-center font-black text-primary-foreground text-[10px] shadow-sm shadow-primary/30 select-none shrink-0">T</div>
              <span className="truncate text-lg font-bold tracking-tight bg-gradient-to-r from-primary via-primary/80 to-primary/50 bg-clip-text text-transparent hover:opacity-95 transition-all">
                {t("appName") || "ThreatSumm4ry"}
              </span>
            </Link>
            {logoAddon}
          </div>

          {/* Right Side Actions Container */}
          <div className="flex items-center gap-2">
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

            <Sheet>
              <SheetTrigger asChild>
                <Button variant="outline" size="icon" className="h-8 w-8 rounded-full border-border/50 px-0 shadow-sm">
                  <Menu className="h-4 w-4" />
                  <span className="sr-only">Open navigation</span>
                </Button>
              </SheetTrigger>
              <SheetContent side="left" className="flex w-[86vw] max-w-sm flex-col overflow-y-auto p-4">
                <SheetHeader className="mb-4 text-left">
                  <SheetTitle className="flex items-center gap-2">
                    <span className="grid h-7 w-7 place-items-center rounded bg-primary text-[11px] font-black text-primary-foreground">T</span>
                    ThreatSumm4ry
                  </SheetTitle>
                </SheetHeader>

                <nav className="flex flex-1 flex-col gap-5">
                  <div className="flex flex-col gap-1">
                    {navItems.filter((item) => item.isHome).map(renderMobileNavItem)}
                  </div>

                  <MobileSection label={language === "pt" ? "Investigar" : "Investigate"}>
                    {navItems.filter((item) => ["/vendors", "/dnsbl", "/phishing-analyzer", "/threat-hunting"].includes(item.path)).map(renderMobileNavItem)}
                  </MobileSection>

                  <MobileSection label={language === "pt" ? "Inteligência" : "Intelligence"}>
                    {navItems.filter((item) => ["/advisories", "/newsletter", "/cves", "/atores", "/patch-tuesday"].includes(item.path)).map(renderMobileNavItem)}
                  </MobileSection>

                  <MobileSection label={language === "pt" ? "Relatórios" : "Reports"}>
                    {navItems.filter((item) => ["/threat-brief", "/features"].includes(item.path)).map(renderMobileNavItem)}
                  </MobileSection>
                </nav>
              </SheetContent>
            </Sheet>
          </div>
        </div>
      </header>

      {/* Desktop Sidebar (lg:flex) */}
      <aside className={cn(
        "hidden lg:fixed lg:left-0 lg:top-0 lg:z-30 lg:flex lg:h-screen lg:flex-col lg:justify-between lg:overflow-y-auto lg:border-r lg:border-border/50 lg:bg-muted/40 transition-all duration-300",
        isCollapsed ? "lg:w-20 lg:p-3" : "lg:w-64 lg:p-4"
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
              {navItems.filter((item) => item.isHome).map((item) => renderNavItem(item, isRouteActive(item.path)))}
            </div>

            {renderCategory(language === 'pt' ? 'Investigar' : 'Investigate',
              ["/vendors", "/dnsbl", "/phishing-analyzer", "/threat-hunting"])}

            {renderCategory(language === 'pt' ? 'Inteligência' : 'Intelligence',
              ["/advisories", "/newsletter", "/cves", "/atores", "/patch-tuesday"])}

            {renderCategory(language === 'pt' ? 'Relatórios' : 'Reports',
              ["/threat-brief"])}

            {/* Features — discreto, sem categoria */}
            <div className="flex flex-col gap-1">
              {navItems.filter((item) => item.path === "/features").map((item) => renderNavItem(item, isRouteActive(item.path)))}
            </div>
          </div>
        </div>

        {/* Bottom Part */}
        <div className="flex flex-col gap-4 border-t border-border/50 pt-4">
          {/* User / auth */}
          {renderUser()}

          {/* Admin (admin only) */}
          {!authLoading && auth.authenticated && auth.isAdmin && (
            <Link to="/admin" className="w-full block -mt-2">
              {isCollapsed ? (
                <Tooltip delayDuration={150}>
                  <TooltipTrigger asChild>
                    <Button variant="ghost" className={cn("w-11 h-11 rounded-xl mx-auto justify-center px-0", pathname === "/admin" ? "bg-primary/15 text-primary ring-1 ring-inset ring-primary/20" : "text-muted-foreground/80 hover:text-foreground hover:bg-muted/20")}>
                      <ShieldCheck className="h-[18px] w-[18px]" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent side="right" className="font-semibold text-xs">Admin</TooltipContent>
                </Tooltip>
              ) : (
                <Button variant="ghost" className={cn("w-full h-10 rounded-xl justify-start px-3.5 gap-3 text-[13px] font-semibold", pathname === "/admin" ? "bg-primary/15 text-primary ring-1 ring-inset ring-primary/20" : "text-muted-foreground/80 hover:text-foreground hover:bg-muted/20")}>
                  <ShieldCheck className="h-[18px] w-[18px]" /> Admin
                </Button>
              )}
            </Link>
          )}

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
                  <TooltipContent side="right" className="font-semibold text-xs">{tr({ pt: "Configurações", en: "Settings", es: "Configuración", fr: "Paramètres" })}</TooltipContent>
                </Tooltip>
              ) : (
                <Button variant="ghost" className={cn("w-full h-10 rounded-xl justify-start px-3.5 gap-3 text-[13px] font-semibold", pathname === "/settings" ? "bg-primary/15 text-primary ring-1 ring-inset ring-primary/20" : "text-muted-foreground/80 hover:text-foreground hover:bg-muted/20")}>
                  <SettingsIcon className="h-[18px] w-[18px]" /> {tr({ pt: "Configurações", en: "Settings", es: "Configuración", fr: "Paramètres" })}
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
            title={isCollapsed ? tr({ pt: "Expandir", en: "Expand", es: "Expandir", fr: "Développer" }) : tr({ pt: "Colapsar", en: "Collapse", es: "Contraer", fr: "Réduire" })}
          >
            {isCollapsed ? (
              <ChevronRight className="h-5 w-5 text-muted-foreground" />
            ) : (
              <>
                <ChevronLeft className="h-5 w-5 text-muted-foreground" />
                <span className="text-xs font-semibold">{tr({ pt: "Recolher Menu", en: "Collapse Sidebar", es: "Contraer Menú", fr: "Réduire le Menu" })}</span>
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
                  LANG
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

function MobileSection({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <div className="px-3 text-[11px] font-bold uppercase tracking-wider text-muted-foreground/70">{label}</div>
      <div className="flex flex-col gap-1">{children}</div>
    </div>
  );
}
