import { Link, useLocation } from "react-router-dom";
import {
  ArrowLeft,
  Rss,
  BookOpen,
  CalendarCheck,
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
import { actorPageCopy } from "@/pages/actorsView";
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

// Catálogo compartilhado pelo menu e pelo título da página.
export function useNavCatalog() {
  const { language, tr } = useLanguage();
  const pt = language === "pt";

  const homeItem: NavItem = {
    path: "/newsletter",
    label: tr({ pt: "Feed de inteligência", en: "Intelligence feed", es: "Feed de inteligencia", fr: "Flux de renseignement" }),
    description: pt ? "Notícias, advisories e pesquisas de segurança." : "Security news, advisories and research.",
    icon: Rss,
    premium: true,
  };

  const navGroups: NavGroup[] = [
    {
      label: pt ? "Pesquisa e contexto" : "Research and context",
      items: [
        {
          path: "/knowledge",
          label: tr({ pt: "Coleções", en: "Collections", es: "Colecciones", fr: "Collections" }),
          description: pt ? "Notícias e relatórios salvos." : "Saved news and reports.",
          icon: Lightbulb,
          premium: true,
        },
        {
          path: "/relatorios",
          label: tr({ pt: "Relatórios", en: "Reports", es: "Informes", fr: "Rapports" }),
          description: pt ? "Resumo pronto a partir de um link." : "Ready-made summary from a link.",
          icon: FileSearch,
          premium: true,
        },
        {
          path: "/atores",
          label: actorPageCopy(language).title,
          description: pt ? "Como agem, quem visam e por quais nomes aparecem." : "How they operate, who they target, what names they use.",
          icon: Users,
        },
        {
          path: "/threat-map",
          label: tr({ pt: "Vítimas de Ransomware", en: "Ransomware Victims", es: "Víctimas de Ransomware", fr: "Victimes de rançongiciels" }),
          description: pt ? "Vítimas de ransomware por país." : "Ransomware victims by country.",
          icon: MapPinned,
        },
        {
          path: "/vendors",
          label: tr({ pt: "Fontes de Dados", en: "Data Sources", es: "Fuentes de Datos", fr: "Sources de Données" }),
          description: pt ? "Origem e cobertura dos dados." : "Data origin and coverage.",
          icon: BookOpen,
        },
      ],
    },
    {
      label: pt ? "Vulnerabilidades e correções" : "Vulnerabilities and patches",
      items: [
        {
          path: "/cves",
          label: tr({ pt: "Vulnerabilidades", en: "Vulnerabilities", es: "Vulnerabilidades", fr: "Vulnérabilités" }),
          description: pt ? "Falhas críticas (CVEs) e risco de exploração." : "Critical flaws (CVEs) and exploitation risk.",
          icon: Shield,
        },
        {
          path: "/patch-tuesday",
          label: pt ? "Patch Tuesday Microsoft" : "Microsoft Patch Tuesday",
          description: pt ? "Correções mensais da Microsoft." : "Monthly Microsoft fixes.",
          icon: CalendarCheck,
        },
        {
          path: "/sap-patch",
          label: tr({ pt: "Correções SAP", en: "SAP Fixes", es: "Correcciones SAP", fr: "Correctifs SAP" }),
          description: pt ? "Notas de segurança mensais da SAP." : "Monthly SAP security notes.",
          icon: ShieldCheck,
        },
      ],
    },
    {
      label: pt ? "Ferramentas de apoio" : "Supporting tools",
      items: [
        { path: "/analyzer", label: pt ? "Consulta de indicadores" : "Indicator lookup", description: pt ? "IPs, domínios, URLs e hashes." : "IPs, domains, URLs and hashes.", icon: Search },
        {
          path: "/phishing-analyzer",
          label: tr({ pt: "Análise de Phishing", en: "Phishing Analysis", es: "Análisis de Phishing", fr: "Analyse de Phishing" }),
          description: pt ? "E-mails suspeitos, links e anexos." : "Suspicious emails, links and attachments.",
          icon: Mail,
        },
        {
          path: "/attack-surface",
          label: tr({ pt: "Superfície de Ataque", en: "Attack Surface", es: "Superficie de Ataque", fr: "Surface d'Attaque" }),
          description: pt ? "Ativos expostos na internet." : "Assets exposed to the internet.",
          icon: Radar,
        },
      ],
    },
  ];

  return { homeItem, navGroups };
}

export function Header({ actions, logoAddon, onLogoClick, showBackButton = false }: HeaderProps) {
  const { t, language } = useLanguage();
  const { auth, loading: authLoading, signOut } = useAuth();
  const { pathname } = useLocation();
  const { homeItem, navGroups } = useNavCatalog();

  const pt = language === "pt";
  const current = [homeItem, ...navGroups.flatMap((g) => g.items)].find((i) => isRouteActive(i.path, pathname));
  // Autenticado, a entrada principal é o feed de inteligência.
  const homePath = auth.authenticated ? homeItem.path : "/";

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
        {showBackButton && pathname !== homePath && (
          <Button variant="ghost" size="icon" asChild className="h-8 w-8 shrink-0 rounded-md">
            <Link to={homePath}>
              <ArrowLeft className="h-4 w-4" />
              <span className="sr-only">{t("back") || "Back"}</span>
            </Link>
          </Button>
        )}

        <Link to={homePath} onClick={() => onLogoClick?.()} className="flex shrink-0 items-center gap-2">
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
          <nav aria-label={pt ? "Fluxo de inteligência" : "Intelligence workflow"} className="mr-2 hidden items-center gap-4 text-xs font-semibold lg:flex">
            {[
              ["/newsletter", pt ? "Feed" : "Feed"],
              ["/knowledge", pt ? "Coleções" : "Collections"],
              ["/relatorios", pt ? "Relatórios" : "Reports"],
            ].map(([path, label]) => (
              <Link key={path} to={path} className={cn("transition-colors hover:text-primary", isRouteActive(path, pathname) ? "text-primary" : "text-muted-foreground")}>{label}</Link>
            ))}
          </nav>
          {actions}

          {/* Configurações tem uma única entrada; as seções ficam na própria página. */}
          {!authLoading && auth.authenticated && (
            <Tooltip delayDuration={100}>
              <TooltipTrigger asChild>
                <Button asChild variant="ghost" size="icon" className="h-8 w-8 rounded-md text-muted-foreground">
                  <Link to="/settings">
                    <SettingsIcon className="h-4 w-4" />
                    <span className="sr-only">{pt ? "Configurações" : "Settings"}</span>
                  </Link>
                </Button>
              </TooltipTrigger>
              <TooltipContent>{pt ? "Configurações" : "Settings"}</TooltipContent>
            </Tooltip>
          )}

          {!authLoading &&
            (auth.authenticated ? (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <button type="button" aria-label={pt ? "Conta" : "Account"} className="flex items-center rounded-md p-1 hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
                    <Avatar className="h-7 w-7 border border-border">
                      <AvatarImage src={`https://github.com/${auth.login}.png?size=64`} alt={auth.login} />
                      <AvatarFallback className="text-[10px] font-semibold">{auth.login?.[0]?.toUpperCase() ?? "?"}</AvatarFallback>
                    </Avatar>
                  </button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-40 rounded-sm">
                  <DropdownMenuItem asChild><Link to="/profile">{pt ? "Conta" : "Account"}</Link></DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onSelect={() => signOut()}><LogOut className="h-4 w-4" />{pt ? "Sair" : "Sign out"}</DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
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
