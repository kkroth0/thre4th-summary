import { Link, useLocation } from "react-router-dom";
import {
  ArrowLeft,
  BookOpen,
  CalendarCheck,
  Crosshair,
  Database,
  FileSearch,
  Github,
  LayoutGrid,
  Lightbulb,
  LogIn,
  LogOut,
  Mail,
  MapPinned,
  Radar,
  Search,
  Settings as SettingsIcon,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Users,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { BrandMark } from "@/components/BrandMark";
import { useLanguage } from "@/contexts/LanguageContext";
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

const isRouteActive = (path: string, pathname: string) => {
  const cleanPath = path.split("#")[0] || "/";
  return cleanPath === "/" ? pathname === "/" : pathname === cleanPath || pathname.startsWith(`${cleanPath}/`);
};

// Um único catálogo de navegação alimenta o launcher, as abas de irmãs e o
// título da barra. Hook em vez de const porque os rótulos são traduzidos.
export function useNavCatalog() {
  const { language, tr } = useLanguage();
  const pt = language === "pt";

  const homeItem: NavItem = {
    path: "/analyzer",
    label: pt ? "Busca ThreatSumm4ry" : "ThreatSumm4ry Search",
    description: pt ? "IP, dominio, link ou hash em 21 fontes." : "IP, domain, link or hash across 21 sources.",
    icon: Search,
  };

  const navGroups: NavGroup[] = [
    {
      label: "Tools",
      items: [
        {
          path: "/dnsbl",
          label: "DNSBL",
          description: pt ? "IPs e dominios em listas de bloqueio." : "IPs and domains on blocklists.",
          icon: ShieldAlert,
        },
        {
          path: "/phishing-analyzer",
          label: tr({ pt: "Phishing Analyzer", en: "Phishing Analyzer", es: "Análisis de Phishing", fr: "Analyse de Phishing" }),
          description: pt ? "E-mails suspeitos, links e anexos." : "Suspicious emails, links and attachments.",
          icon: Mail,
        },
        {
          path: "/attack-surface",
          label: "Attack Surface",
          description: pt ? "Ativos expostos na internet." : "Assets exposed to the internet.",
          icon: Radar,
        },
      ],
    },
    {
      label: "Intel & Hunting",
      items: [
        {
          path: "/knowledge",
          label: "Knowledge",
          description: pt ? "Noticias e relatorios salvos." : "Saved news and reports.",
          icon: Lightbulb,
          premium: true,
        },
        {
          path: "/relatorios",
          label: "Threat Feed Generator",
          description: pt ? "Resumo pronto a partir de um link." : "Ready-made summary from a link.",
          icon: FileSearch,
          premium: true,
        },
        {
          path: "/hunting",
          label: "Hunting",
          description: pt ? "Buscas prontas para os seus logs." : "Ready-made searches for your logs.",
          icon: Crosshair,
          premium: true,
        },
        {
          path: "/newsletter",
          label: "Intel Scrapping",
          description: pt ? "Noticias de seguranca da semana." : "This week's security news.",
          icon: Database,
          premium: true,
        },
        {
          path: "/atores",
          label: tr({ pt: "Atores", en: "Threat Actors", es: "Actores", fr: "Acteurs" }),
          description: pt ? "Grupos de ataque, alvos e apelidos." : "Attack groups, targets and aliases.",
          icon: Users,
        },
        {
          path: "/threat-map",
          label: pt ? "Mapa de Ameacas" : "Threat Map",
          description: pt ? "Vitimas de ransomware por pais." : "Ransomware victims by country.",
          icon: MapPinned,
        },
        {
          path: "/vendors",
          label: pt ? "Fontes" : "Sources",
          description: pt ? "Origem e cobertura dos dados." : "Data origin and coverage.",
          icon: BookOpen,
        },
      ],
    },
    {
      label: "Vulnerability Management",
      items: [
        {
          path: "/cves",
          label: tr({ pt: "CVEs", en: "CVEs", es: "CVEs", fr: "CVE" }),
          description: pt ? "Falhas criticas e risco de exploracao." : "Critical flaws and exploitation risk.",
          icon: Shield,
        },
        {
          path: "/patch-tuesday",
          label: "Microsoft Patch Tuesday",
          description: pt ? "Correcoes mensais da Microsoft." : "Monthly Microsoft fixes.",
          icon: CalendarCheck,
        },
        {
          path: "/sap-patch",
          label: "SAP Monthly Patch",
          description: pt ? "Correcoes mensais da SAP." : "Monthly SAP fixes.",
          icon: ShieldCheck,
        },
      ],
    },
  ];

  return { homeItem, navGroups };
}

// Abas das funcionalidades irmãs: quem está numa página do grupo vê as outras
// do mesmo grupo como seletor, no lugar de voltar pro menu.
export function NavTabs() {
  const { pathname } = useLocation();
  const { navGroups } = useNavCatalog();
  const group = navGroups.find((g) => g.items.some((i) => isRouteActive(i.path, pathname)));
  if (!group || group.items.length < 2) return null;

  return (
    <div className="border-b border-border bg-background/60">
      <div className="scrollbar-none flex items-center gap-1 overflow-x-auto px-4 lg:px-6">
        {group.items.map((item) => {
          const active = isRouteActive(item.path, pathname);
          return (
            <Link
              key={item.path}
              to={item.path}
              className={cn(
                "whitespace-nowrap border-b-2 px-3 py-2.5 text-[13px] font-medium transition-colors",
                active
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              )}
            >
              {item.label}
            </Link>
          );
        })}
      </div>
    </div>
  );
}

export function Header({ actions, logoAddon, onLogoClick, showBackButton = false }: HeaderProps) {
  const { t, language } = useLanguage();
  const { auth, loading: authLoading, signOut } = useAuth();
  const { pathname } = useLocation();
  const { homeItem, navGroups } = useNavCatalog();

  const pt = language === "pt";
  const current = [homeItem, ...navGroups.flatMap((g) => g.items)].find((i) => isRouteActive(i.path, pathname));

  const launcherCard = (item: NavItem) => {
    const Icon = item.icon;
    const active = isRouteActive(item.path, pathname);
    return (
      <Link
        key={item.path}
        to={item.path}
        className={cn(
          "flex items-start gap-2.5 rounded-lg border p-2.5 transition-colors",
          active ? "border-border bg-secondary" : "border-transparent hover:border-border hover:bg-secondary/70"
        )}
      >
        <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-border bg-background">
          <Icon className={cn("h-3.5 w-3.5", active ? "text-primary" : "text-muted-foreground")} />
        </span>
        <span className="min-w-0">
          <span className="flex items-center gap-1.5 text-[13px] font-semibold text-foreground">
            {item.label}
            {item.premium && !auth.isPremium && (
              <span className="rounded border border-border px-1 py-0.5 text-[8px] font-bold leading-none text-muted-foreground">
                PRO
              </span>
            )}
          </span>
          {item.description && (
            <span className="mt-0.5 block text-[11px] leading-snug text-muted-foreground">{item.description}</span>
          )}
        </span>
      </Link>
    );
  };

  return (
    <header className="sticky top-0 z-50 border-b border-border bg-background/95 backdrop-blur">
      <div className="flex h-14 items-center gap-3 px-4 lg:px-6">
        {showBackButton && pathname !== "/" && (
          <Button variant="ghost" size="icon" asChild className="h-8 w-8 shrink-0 rounded-md">
            <Link to="/">
              <ArrowLeft className="h-4 w-4" />
              <span className="sr-only">{t("back") || "Back"}</span>
            </Link>
          </Button>
        )}

        <Link to="/" onClick={() => onLogoClick?.()} className="flex shrink-0 items-center gap-2">
          <BrandMark className="h-7 w-7 rounded-md" />
          <span className="hidden text-sm font-bold tracking-tight text-foreground sm:inline">threatsumm4ry</span>
        </Link>

        {current && (
          <>
            <span className="hidden h-5 w-px bg-border sm:block" />
            <span className="min-w-0 truncate text-sm font-semibold text-foreground">{current.label}</span>
          </>
        )}

        {logoAddon}

        <div className="ml-auto flex shrink-0 items-center gap-1.5">
          {actions}

          {/* Engrenagem: administracao em cima, conta embaixo, sair por ultimo */}
          {!authLoading && auth.authenticated && (
            <DropdownMenu>
              <Tooltip delayDuration={100}>
                <TooltipTrigger asChild>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="icon" className="h-8 w-8 rounded-md text-muted-foreground">
                      <SettingsIcon className="h-4 w-4" />
                      <span className="sr-only">{pt ? "Configuracoes" : "Settings"}</span>
                    </Button>
                  </DropdownMenuTrigger>
                </TooltipTrigger>
                <TooltipContent>{pt ? "Configuracoes" : "Settings"}</TooltipContent>
              </Tooltip>
              <DropdownMenuContent align="end" className="w-60">
                {auth.isAdmin && (
                  <>
                    <DropdownMenuItem asChild>
                      <Link to="/settings?section=admin">{pt ? "Acesso premium" : "Premium access"}</Link>
                    </DropdownMenuItem>
                    <DropdownMenuItem asChild>
                      <Link to="/vendors">{pt ? "Fontes e integracoes" : "Sources and integrations"}</Link>
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                  </>
                )}
                <DropdownMenuItem asChild>
                  <Link to="/settings?section=api-keys">{pt ? "Chaves de API" : "API keys"}</Link>
                </DropdownMenuItem>
                <DropdownMenuItem asChild>
                  <Link to="/settings">{pt ? "Minhas preferencias" : "My preferences"}</Link>
                </DropdownMenuItem>
                <DropdownMenuItem asChild>
                  <Link to="/profile">{pt ? "Perfil" : "Profile"}</Link>
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onSelect={() => signOut()}>
                  <LogOut className="h-4 w-4" /> {pt ? "Sair" : "Sign out"}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          )}

          {!authLoading &&
            (auth.authenticated ? (
              <Link to="/profile" className="flex items-center rounded-md px-1 py-1 hover:bg-secondary">
                <Avatar className="h-7 w-7 border border-border">
                  <AvatarImage src={`https://github.com/${auth.login}.png?size=64`} alt={auth.login} />
                  <AvatarFallback className="text-[10px] font-semibold">{auth.login?.[0]?.toUpperCase() ?? "?"}</AvatarFallback>
                </Avatar>
              </Link>
            ) : (
              <>
                <Button variant="ghost" size="sm" asChild className="h-8 px-2 text-xs">
                  <Link to="/login"><LogIn className="h-4 w-4" /> {pt ? "Entrar" : "Sign in"}</Link>
                </Button>
                <Button size="sm" asChild className="hidden h-8 px-2 text-xs sm:inline-flex">
                  <Link to="/cadastro"><Github className="h-4 w-4" /> {pt ? "Cadastrar" : "Sign up"}</Link>
                </Button>
              </>
            ))}

          {/* Launcher: todas as funcionalidades em boxes, ancorado na direita */}
          <Popover>
            <PopoverTrigger asChild>
              <Button variant="ghost" size="icon" className="h-8 w-8 rounded-md text-muted-foreground">
                <LayoutGrid className="h-4 w-4" />
                <span className="sr-only">{pt ? "Abrir menu" : "Open menu"}</span>
              </Button>
            </PopoverTrigger>
            <PopoverContent
              align="end"
              className="max-h-[80vh] w-[min(92vw,44rem)] overflow-y-auto p-3"
            >
              <div className="grid gap-1">{launcherCard(homeItem)}</div>
              {navGroups.map((group) => (
                <div key={group.label} className="mt-3">
                  <div className="px-2.5 pb-1 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                    {group.label}
                  </div>
                  <div className="grid gap-1 sm:grid-cols-2">{group.items.map(launcherCard)}</div>
                </div>
              ))}
            </PopoverContent>
          </Popover>
        </div>
      </div>
    </header>
  );
}
