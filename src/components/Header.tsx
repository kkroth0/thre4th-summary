import { Link, useLocation } from "react-router-dom";
import {
  ArrowLeft,
  Menu,
  Sun,
  Moon,
  Github,
  LayoutGrid,
  LogIn,
  LogOut,
  Settings as SettingsIcon,
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
import { useNavCatalog, type NavItem } from "./useNavCatalog";
import { isRouteActive } from "@/lib/navigation";
import { useWorkspaceNavigation } from "@/contexts/WorkspaceNavigationContext";
import { useTheme } from "./theme-provider";
import { useLanguage } from "@/contexts/LanguageContext";
import { useAuth } from "@/contexts/AuthContext";
import { cn } from "@/lib/utils";
import { WorkspaceBreadcrumbs, type WorkspaceBreadcrumbItem } from './WorkspaceBreadcrumbs';

interface HeaderProps {
  actions?: React.ReactNode;
  logoAddon?: React.ReactNode;
  onLogoClick?: () => void;
  showBackButton?: boolean;
  breadcrumbItems?: WorkspaceBreadcrumbItem[];
}

export function Header({ actions, logoAddon, onLogoClick, showBackButton = false, breadcrumbItems = [] }: HeaderProps) {
  const { t, language } = useLanguage();
  const { auth, loading: authLoading, signOut } = useAuth();
  const { pathname } = useLocation();
  const { homeItem, navGroups } = useNavCatalog();
  const workspace = useWorkspaceNavigation();
  const { theme, setTheme } = useTheme();
  const dark = theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);

  const pt = language === "pt";
  const current = [homeItem, ...navGroups.flatMap((g) => g.items)].find((i) => isRouteActive(i.path, pathname));
  // Autenticado, a entrada principal é o feed de inteligência.
  const homePath = auth.authenticated ? homeItem.path : "/";
  const pageLabel = current?.label || (pathname === '/settings' ? (pt ? 'Configurações' : 'Settings') : pathname === '/profile' ? (pt ? 'Conta' : 'Account') : pathname === '/admin' ? (pt ? 'Administração' : 'Administration') : pathname === '/exposure-watchlist' ? (pt ? 'Monitoramento de exposição' : 'Exposure monitoring') : (pt ? 'Inteligência de ameaças' : 'Threat intelligence'));
  const breadcrumbs: WorkspaceBreadcrumbItem[] = pathname === '/dashboard'
    ? [{ label: 'Dashboard' }]
    : [{ label: 'Dashboard', to: '/dashboard' }, { label: pageLabel, to: breadcrumbItems.length ? pathname : undefined }, ...breadcrumbItems];

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
      <div className={cn("flex items-center gap-3 px-4 lg:px-6", workspace ? 'h-16' : 'h-14')}>
        {workspace && <Button type="button" variant="ghost" size="icon" className="h-8 w-8 shrink-0 md:hidden" onClick={workspace.openMenu} aria-label={pt ? 'Abrir navegação' : 'Open navigation'}><Menu className="h-4 w-4" /></Button>}
        {showBackButton && pathname !== homePath && (
          <Button variant="ghost" size="icon" asChild className="h-8 w-8 shrink-0 rounded-md">
            <Link to={homePath}>
              <ArrowLeft className="h-4 w-4" />
              <span className="sr-only">{t("back") || "Back"}</span>
            </Link>
          </Button>
        )}

        {!workspace && <Link to={homePath} onClick={() => onLogoClick?.()} className="flex shrink-0 items-center gap-2">
          <BrandMark className="h-7 w-7 rounded-md" />
          <span className="hidden text-sm font-bold tracking-tight text-foreground sm:inline">threatsumm4ry</span>
        </Link>}

        {workspace && <WorkspaceBreadcrumbs items={breadcrumbs} pt={pt} />}
        {!workspace && current && (
          <>
            {!workspace && <span className="hidden h-5 w-px bg-border sm:block" />}
            <span className="min-w-0 truncate text-sm font-semibold text-foreground">{current.label}</span>
          </>
        )}

        {logoAddon}

        <div className="ml-auto flex shrink-0 items-center gap-1.5">
          {!workspace && <nav aria-label={pt ? "Fluxo de inteligência" : "Intelligence workflow"} className="mr-2 hidden items-center gap-4 text-xs font-semibold lg:flex">
            {[
              ["/newsletter", pt ? "Feed" : "Feed"],
              ["/knowledge", pt ? "Publicações salvas" : "Saved publications"],
              ["/relatorios", pt ? "Relatórios" : "Reports"],
            ].map(([path, label]) => (
              <Link key={path} to={path} className={cn("transition-colors hover:text-primary", isRouteActive(path, pathname) ? "text-primary" : "text-muted-foreground")}>{label}</Link>
            ))}
          </nav>}
          {actions}
          {workspace && <Button type="button" variant="ghost" size="icon" className="h-8 w-8 rounded text-muted-foreground" onClick={() => setTheme(dark ? 'light' : 'dark')} aria-label={dark ? (pt ? 'Usar tema claro' : 'Use light theme') : (pt ? 'Usar tema escuro' : 'Use dark theme')} title={dark ? (pt ? 'Usar tema claro' : 'Use light theme') : (pt ? 'Usar tema escuro' : 'Use dark theme')}>{dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}</Button>}

          {/* Configurações tem uma única entrada; as seções ficam na própria página. */}
          {!workspace && !authLoading && auth.authenticated && (
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
                  <button type="button" aria-label={pt ? "Conta" : "Account"} className="flex items-center gap-2 rounded-md p-1 hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
                    {workspace && <span className="hidden max-w-40 truncate text-xs font-medium text-muted-foreground sm:block">{auth.login}</span>}
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
          {!workspace && <Popover>
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
          </Popover>}
        </div>
      </div>
    </header>
  );
}
