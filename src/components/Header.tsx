import { Link, useLocation } from "react-router-dom";
import {
  ArrowLeft,
  BookOpen,
  CalendarCheck,
  ChevronLeft,
  ChevronRight,
  Crosshair,
  Database,
  FileSearch,
  Github,
  LogIn,
  Mail,
  MapPinned,
  Menu,
  Megaphone,
  Radar,
  RadioTower,
  Search,
  Settings as SettingsIcon,
  Shield,
  ShieldAlert,
  User,
  Users,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Sheet, SheetClose, SheetContent, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { BrandMark } from "@/components/BrandMark";
import { useLanguage } from "@/contexts/LanguageContext";
import { useSidebar } from "@/contexts/SidebarContext";
import { useAuth } from "@/contexts/AuthContext";
import { cn } from "@/lib/utils";

interface HeaderProps {
  actions?: React.ReactNode;
  logoAddon?: React.ReactNode;
  onLogoClick?: () => void;
  showBackButton?: boolean;
}

type NavItem = {
  path: string;
  label: string;
  description?: string;
  icon: React.ElementType;
  premium?: boolean;
};

type NavGroup = {
  label: string;
  items: NavItem[];
};

export function Header({ actions, logoAddon, onLogoClick, showBackButton = false }: HeaderProps) {
  const { t, language, tr } = useLanguage();
  const { isCollapsed, toggleSidebar } = useSidebar();
  const { auth, loading: authLoading } = useAuth();
  const { pathname } = useLocation();

  const pt = language === "pt";

  const homeItem: NavItem = {
    path: "/analyzer",
    label: pt ? "Busca ThreatSumm4ry" : "ThreatSumm4ry Search",
    description: pt ? "IOC, dominio, URL, hash ou CVE em 21 fontes." : "IOC, domain, URL, hash or CVE across 21 sources.",
    icon: Search,
  };

  const navGroups: NavGroup[] = [
    {
      label: pt ? "Analise" : "Analysis",
      items: [
        {
          path: "/phishing-analyzer",
          label: tr({ pt: "Phishing Analyzer", en: "Phishing Analyzer", es: "Análisis de Phishing", fr: "Analyse de Phishing" }),
          description: pt ? "Headers, URLs, anexos e IOCs." : "Headers, URLs, attachments and IOCs.",
          icon: Mail,
        },
        {
          path: "/dnsbl",
          label: "DNSBL",
          description: pt ? "Blocklists por IP, dominio ou range." : "Blocklists by IP, domain or range.",
          icon: ShieldAlert,
        },
        {
          path: "/attack-surface",
          label: "Attack Surface",
          description: pt
            ? "Scan externo, XLSX e monitoramento de exposicao."
            : "External scan, XLSX export, and exposure monitoring.",
          icon: Radar,
        },
        {
          path: "/relatorios",
          label: pt ? "Gerador de Relatorios" : "Report Generator",
          description: pt ? "URL, PDF ou relatorio em uma analise CTI." : "URL, PDF or report into CTI analysis.",
          icon: FileSearch,
          premium: true,
        },
      ],
    },
    {
      label: "Intel",
      items: [
        {
          path: "/cves",
          label: tr({ pt: "CVEs", en: "CVEs", es: "CVEs", fr: "CVE" }),
          description: pt ? "EPSS, KEV e exploit publico." : "EPSS, KEV and public exploit context.",
          icon: Shield,
        },
        {
          path: "/atores",
          label: tr({ pt: "Atores", en: "Threat Actors", es: "Actores", fr: "Acteurs" }),
          description: pt ? "Aliases, TTPs e setores alvo." : "Aliases, TTPs and target sectors.",
          icon: Users,
        },
        {
          path: "/advisories",
          label: "Advisories",
          description: pt ? "Boletim diario, KPIs e avisos normalizados." : "Daily brief, KPIs and normalized advisories.",
          icon: Megaphone,
        },
        {
          path: "/latam-threats",
          label: "Latam Threats",
          description: pt ? "Ransomware e IOCs recentes na America Latina." : "Recent ransomware and IOCs across Latin America.",
          icon: RadioTower,
        },
        {
          path: "/threat-map",
          label: pt ? "Mapa de Ameacas" : "Threat Map",
          description: pt ? "Vitimas de ransomware por pais." : "Ransomware victims by country.",
          icon: MapPinned,
        },
        {
          path: "/patch-tuesday",
          label: "Patch Tuesday",
          description: pt ? "Timeline mensal Microsoft." : "Monthly Microsoft timeline.",
          icon: CalendarCheck,
        },
        {
          path: "/newsletter",
          label: "Newsletter",
          description: pt ? "Recorte semanal curado." : "Curated weekly digest.",
          icon: Database,
          premium: true,
        },
        {
          path: "/vendors",
          label: pt ? "Fontes" : "Sources",
          description: pt ? "Fontes, integracoes e cobertura." : "Sources, integrations and coverage.",
          icon: BookOpen,
        },
      ],
    },
    {
      label: "Hunting",
      items: [
        {
          path: "/threat-hunting",
          label: "Threat Hunting",
          description: pt ? "Hipoteses e queries por tecnica." : "Hypotheses and queries by technique.",
          icon: Crosshair,
          premium: true,
        },
      ],
    },
  ];

  const isRouteActive = (path: string) => {
    const cleanPath = path.split("#")[0] || "/";
    return cleanPath === "/" ? pathname === "/" : pathname === cleanPath || pathname.startsWith(`${cleanPath}/`);
  };

  const handleLogoClick = () => {
    onLogoClick?.();
  };

  const renderDesktopItem = (item: NavItem) => {
    const Icon = item.icon;
    const active = isRouteActive(item.path);
    const link = (
      <Link
        key={item.path}
        to={item.path}
        className={cn(
          "group relative flex items-center rounded-md text-[13px] font-medium transition-colors",
          isCollapsed ? "h-10 w-10 justify-center px-0" : "h-9 gap-2.5 px-2.5",
          active
            ? "bg-primary/10 text-foreground"
            : "text-muted-foreground hover:bg-secondary hover:text-foreground"
        )}
      >
        {active && (
          <span className={cn("absolute rounded-full bg-primary", isCollapsed ? "left-0 top-2 h-6 w-0.5" : "left-0 top-2 h-5 w-0.5")} />
        )}
        <Icon className={cn("h-4 w-4 shrink-0", active ? "text-primary" : "text-muted-foreground group-hover:text-foreground")} />
        {!isCollapsed && (
          <>
            <span className="min-w-0 flex-1 truncate">{item.label}</span>
            {item.premium && (
              <span className="rounded border border-border bg-background px-1.5 py-0.5 text-[9px] font-bold leading-none text-muted-foreground">
                PRO
              </span>
            )}
          </>
        )}
      </Link>
    );

    if (!isCollapsed) return link;

    return (
      <Tooltip key={item.path} delayDuration={100}>
        <TooltipTrigger asChild>{link}</TooltipTrigger>
        <TooltipContent side="right" className="max-w-64">
          <div className="font-medium">{item.label}</div>
          {item.description && <div className="mt-1 text-xs text-muted-foreground">{item.description}</div>}
        </TooltipContent>
      </Tooltip>
    );
  };

  const renderDesktopGroup = (group: NavGroup) => (
    <div key={group.label} className="space-y-1.5">
      {isCollapsed ? (
        <div className="mx-auto my-2 h-px w-8 bg-border" />
      ) : (
        <div className="px-2.5 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
          {group.label}
        </div>
      )}
      <div className="space-y-1">{group.items.map(renderDesktopItem)}</div>
    </div>
  );

  const renderMobileItem = (item: NavItem) => {
    const Icon = item.icon;
    const active = isRouteActive(item.path);

    return (
      <SheetClose asChild key={item.path}>
        <Link
          to={item.path}
          className={cn(
            "flex items-start gap-3 rounded-lg border border-transparent px-2.5 py-2.5 transition-colors hover:border-border hover:bg-secondary/70",
            active && "border-border bg-secondary"
          )}
        >
          <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border bg-background text-foreground">
            <Icon className={cn("h-4 w-4", active && "text-primary")} />
          </span>
          <span className="min-w-0 flex-1">
            <span className="flex items-center gap-2 text-sm font-semibold text-foreground">
              {item.label}
              {item.premium && (
                <span className="rounded border border-border bg-background px-1.5 py-0.5 text-[9px] font-bold text-muted-foreground">
                  PRO
                </span>
              )}
            </span>
            {item.description && <span className="mt-0.5 block text-xs text-muted-foreground">{item.description}</span>}
          </span>
        </Link>
      </SheetClose>
    );
  };

  const renderMobileGroup = (group: NavGroup) => (
    <div key={group.label} className="space-y-2">
      <div className="px-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">{group.label}</div>
      <div className="grid gap-1">{group.items.map(renderMobileItem)}</div>
    </div>
  );

  const renderDesktopAccount = () => {
    if (authLoading) {
      return <div className={cn("h-10 animate-pulse rounded-md bg-secondary", isCollapsed ? "w-10" : "w-full")} />;
    }

    if (!auth.authenticated) {
      const signIn = (
        <Link
          to="/login"
          className={cn(
            "flex h-10 items-center rounded-md border border-border bg-background text-sm font-medium transition-colors hover:bg-secondary",
            isCollapsed ? "w-10 justify-center" : "w-full gap-2 px-3"
          )}
        >
          <LogIn className="h-4 w-4" />
          {!isCollapsed && <span>{pt ? "Entrar" : "Sign in"}</span>}
        </Link>
      );

      if (!isCollapsed) return signIn;

      return (
        <Tooltip delayDuration={100}>
          <TooltipTrigger asChild>{signIn}</TooltipTrigger>
          <TooltipContent side="right">{pt ? "Entrar" : "Sign in"}</TooltipContent>
        </Tooltip>
      );
    }

    const profile = (
      <Link
        to="/profile"
        className={cn(
          "flex items-center rounded-md text-sm transition-colors hover:bg-secondary",
          isCollapsed ? "h-10 w-10 justify-center" : "h-11 w-full gap-2.5 px-2"
        )}
      >
        <Avatar className="h-7 w-7 border border-border">
          <AvatarImage src={`https://github.com/${auth.login}.png?size=64`} alt={auth.login} />
          <AvatarFallback className="text-[10px] font-semibold">{auth.login?.[0]?.toUpperCase() ?? "?"}</AvatarFallback>
        </Avatar>
        {!isCollapsed && (
          <span className="min-w-0">
            <span className="block max-w-40 truncate font-semibold text-foreground">{auth.login}</span>
            <span className="block text-xs text-muted-foreground">{pt ? "Perfil" : "Profile"}</span>
          </span>
        )}
      </Link>
    );

    if (!isCollapsed) return profile;

    return (
      <Tooltip delayDuration={100}>
        <TooltipTrigger asChild>{profile}</TooltipTrigger>
        <TooltipContent side="right">{auth.login}</TooltipContent>
      </Tooltip>
    );
  };

  return (
    <>
      <header className="sticky top-0 z-50 border-b border-border bg-background/95 backdrop-blur lg:hidden">
        <div className="flex h-14 items-center justify-between px-4">
          <div className="flex min-w-0 items-center gap-2.5">
            {showBackButton && pathname !== "/" && (
              <Button variant="ghost" size="icon" asChild className="h-8 w-8 rounded-md">
                <Link to="/">
                  <ArrowLeft className="h-4 w-4" />
                  <span className="sr-only">{t("back") || "Back"}</span>
                </Link>
              </Button>
            )}
            <Link to="/" onClick={handleLogoClick} className="flex min-w-0 items-center gap-2">
              <BrandMark className="h-7 w-7 rounded-md" />
              <span className="truncate text-sm font-bold tracking-tight text-foreground">threatsumm4ry</span>
            </Link>
            {logoAddon}
          </div>

          <div className="flex items-center gap-2">
            {!auth.authenticated && (
              <Button variant="ghost" size="sm" asChild className="hidden h-8 px-2 text-xs sm:inline-flex">
                <Link to="/cadastro">{pt ? "Cadastrar" : "Sign up"}</Link>
              </Button>
            )}
            <Sheet>
              <SheetTrigger asChild>
                <Button variant="outline" size="icon" className="h-8 w-8 rounded-md px-0">
                  <Menu className="h-4 w-4" />
                  <span className="sr-only">Open navigation</span>
                </Button>
              </SheetTrigger>
              <SheetContent side="left" className="flex w-[92vw] max-w-sm flex-col overflow-y-auto border-border bg-background p-4">
                <SheetHeader className="mb-5 text-left">
                  <SheetTitle className="flex items-center gap-2">
                    <BrandMark className="h-7 w-7 rounded-md" />
                    threatsumm4ry
                  </SheetTitle>
                </SheetHeader>

                <nav className="flex flex-1 flex-col gap-5">
                  {renderMobileItem(homeItem)}
                  {navGroups.map(renderMobileGroup)}

                  <div className="mt-auto border-t border-border pt-4">
                    <div className="grid gap-2">
                      {auth.authenticated ? (
                        <>
                          <SheetClose asChild>
                            <Button variant="outline" asChild className="justify-start">
                              <Link to="/profile"><User className="h-4 w-4" /> {pt ? "Perfil" : "Profile"}</Link>
                            </Button>
                          </SheetClose>
                          <SheetClose asChild>
                            <Button variant="outline" asChild className="justify-start">
                              <Link to="/settings"><SettingsIcon className="h-4 w-4" /> {pt ? "Configuracoes" : "Settings"}</Link>
                            </Button>
                          </SheetClose>
                        </>
                      ) : (
                        <>
                          <SheetClose asChild>
                            <Button variant="outline" asChild className="justify-start">
                              <Link to="/login"><LogIn className="h-4 w-4" /> {pt ? "Entrar" : "Sign in"}</Link>
                            </Button>
                          </SheetClose>
                          <SheetClose asChild>
                            <Button asChild className="justify-start">
                              <Link to="/cadastro"><Github className="h-4 w-4" /> {pt ? "Cadastrar" : "Sign up"}</Link>
                            </Button>
                          </SheetClose>
                        </>
                      )}
                    </div>
                  </div>
                </nav>
              </SheetContent>
            </Sheet>
          </div>
        </div>
      </header>

      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 hidden border-r border-border bg-sidebar text-sidebar-foreground transition-[width] duration-200 lg:flex lg:flex-col",
          isCollapsed ? "w-[72px]" : "w-[264px]"
        )}
      >
        <div className="flex h-full min-h-0 flex-col">
          <div className={cn("border-b border-border p-3", isCollapsed ? "px-3" : "px-4")}>
            <div className={cn("flex h-9 items-center", isCollapsed ? "justify-center" : "justify-between gap-2")}>
              <Link to="/" onClick={handleLogoClick} className="flex min-w-0 items-center gap-2">
                <BrandMark className="h-8 w-8 rounded-md" />
                {!isCollapsed && (
                  <span className="min-w-0">
                    <span className="block truncate text-sm font-bold tracking-tight text-foreground">threatsumm4ry</span>
                    <span className="block truncate text-[11px] text-muted-foreground">SOC & CTI console</span>
                  </span>
                )}
              </Link>
              {!isCollapsed && logoAddon}
            </div>
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto px-3 py-4">
            <nav className="space-y-4">
              {renderDesktopItem(homeItem)}
              {navGroups.map(renderDesktopGroup)}
            </nav>
          </div>

          <div className={cn("border-t border-border p-3", isCollapsed ? "space-y-2" : "space-y-3")}>
            {actions && !isCollapsed && <div className="grid gap-2">{actions}</div>}

            {renderDesktopAccount()}

            {!isCollapsed && !authLoading && !auth.authenticated && (
              <Button asChild className="h-9 w-full justify-start rounded-md">
                <Link to="/cadastro">
                  <Github className="h-4 w-4" />
                  {pt ? "Cadastrar" : "Sign up"}
                </Link>
              </Button>
            )}

            {!authLoading && auth.authenticated && (
              <div className={cn("grid gap-1", isCollapsed ? "justify-items-center" : "")}>
                {renderDesktopItem({
                  path: "/settings",
                  label: tr({ pt: "Configuracoes", en: "Settings", es: "Configuración", fr: "Paramètres" }),
                  icon: SettingsIcon,
                })}
              </div>
            )}

            <div className={cn("flex", isCollapsed ? "justify-center" : "justify-end")}>
              <Button
                variant="ghost"
                size="icon"
                onClick={toggleSidebar}
                className="h-8 w-8 rounded-md text-muted-foreground hover:text-foreground"
                title={isCollapsed ? (pt ? "Expandir menu" : "Expand sidebar") : (pt ? "Recolher menu" : "Collapse sidebar")}
              >
                {isCollapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
                <span className="sr-only">{pt ? "Alternar menu" : "Toggle sidebar"}</span>
              </Button>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
}
