import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { ChevronDown, Github, PanelLeftClose, PanelLeftOpen, Settings } from 'lucide-react';
import { BrandMark } from './BrandMark';
import { useNavCatalog } from './useNavCatalog';
import { Sheet, SheetContent, SheetDescription, SheetTitle } from './ui/sheet';
import { useIsMobile } from '@/hooks/use-mobile';
import { useAuth } from '@/contexts/AuthContext';
import { useLanguage } from '@/contexts/LanguageContext';
import { WorkspaceNavigationContext } from '@/contexts/WorkspaceNavigationContext';
import { isRouteActive, isWorkspaceRoute } from '@/lib/navigation';
import { cn } from '@/lib/utils';

const STORAGE_KEY = 'threatsumm4ry-sidebar-collapsed';

export function WorkspaceShell({ children }: { children: ReactNode }) {
  const { pathname, search } = useLocation();
  const { language } = useLanguage();
  const { auth } = useAuth();
  const { homeItem, navGroups } = useNavCatalog();
  const pt = language === 'pt';
  const mobile = useIsMobile();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [phishingOpen, setPhishingOpen] = useState(pathname === '/phishing-analyzer');
  const [actorsOpen, setActorsOpen] = useState(pathname === '/atores');
  const [vulnerabilitiesOpen, setVulnerabilitiesOpen] = useState(pathname === '/cves');
  const menuOpener = useRef<HTMLElement | null>(null);
  const [collapsed, setCollapsed] = useState(() => { try { return localStorage.getItem(STORAGE_KEY) === 'true'; } catch { return false; } });
  useEffect(() => { setMobileOpen(false); window.scrollTo({ top: 0, left: 0 }); }, [pathname]);
  useEffect(() => { if (pathname === '/phishing-analyzer') setPhishingOpen(true); }, [pathname]);
  useEffect(() => { if (pathname === '/atores') setActorsOpen(true); }, [pathname]);
  useEffect(() => { if (pathname === '/cves') setVulnerabilitiesOpen(true); }, [pathname]);
  useEffect(() => { if (!mobile) setMobileOpen(false); }, [mobile]);
  if (!isWorkspaceRoute(pathname)) return <>{children}</>;
  const catalog = [homeItem, ...navGroups.flatMap(group => group.items)];
  const sections = [
    { label: pt ? 'Plataforma' : 'Platform', paths: ['/dashboard', '/analyzer', '/bulk', '/knowledge', '/relatorios'] },
    { label: pt ? 'Inteligência de ameaças' : 'Threat hunting', paths: ['/newsletter', '/atores', '/malware', '/cves', '/phishing-analyzer', '/domain-monitoring', '/attack-surface', '/threat-map'] },
    { label: pt ? 'Correções' : 'Patches', paths: ['/patch-tuesday', '/sap-patch'] },
  ];
  const toggle = () => setCollapsed(value => {
    try { localStorage.setItem(STORAGE_KEY, String(!value)); } catch { /* navigation remains usable without storage */ }
    return !value;
  });
  const navigation = (rail: boolean) => <>
    <div className={cn('flex h-16 shrink-0 items-center gap-2 border-b border-sidebar-border px-3', rail && 'justify-center')}>
      {!rail && <Link to="/dashboard" onClick={() => setMobileOpen(false)} className="flex min-w-0 items-center gap-2.5"><BrandMark className="h-7 w-7 shrink-0 rounded" /><span className="text-sm font-semibold tracking-tight">threatsumm4ry</span></Link>}
      {!mobile && <button type="button" onClick={toggle} className={cn('rounded p-1.5 text-muted-foreground hover:bg-sidebar-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring', !rail && 'ml-auto')} aria-label={rail ? (pt ? 'Expandir barra lateral' : 'Expand sidebar') : (pt ? 'Recolher barra lateral' : 'Collapse sidebar')} title={rail ? (pt ? 'Expandir barra lateral' : 'Expand sidebar') : (pt ? 'Recolher barra lateral' : 'Collapse sidebar')}>{rail ? <PanelLeftOpen className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}</button>}
    </div>
    <nav aria-label={pt ? 'Navegação principal' : 'Main navigation'} className="min-h-0 flex-1 overflow-y-auto px-2 py-3">
      {sections.map(section => <div key={section.label} className="mb-4 last:mb-0">
        <p className={cn('mb-1.5 px-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground', rail && 'sr-only')}>{section.label}</p>
        <div className="space-y-0.5">{section.paths.map(path => {
          const item = catalog.find(value => value.path === path);
          if (!item) return null;
          const Icon = item.icon;
          const active = isRouteActive(path, pathname);
          const expanded = path === '/atores' ? actorsOpen : path === '/cves' ? vulnerabilitiesOpen : phishingOpen;
          const linkClass = cn('flex min-h-9 items-center gap-2 rounded-md px-2 py-1.5 text-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring', rail && 'justify-center px-0', active ? 'bg-primary font-medium text-primary-foreground' : 'text-muted-foreground hover:bg-sidebar-accent hover:text-foreground');
          return <div key={path}>
            {['/phishing-analyzer', '/atores', '/cves'].includes(path) && !rail ? <button type="button" className={cn(linkClass, 'w-full')} onClick={() => path === '/atores' ? setActorsOpen(value => !value) : path === '/cves' ? setVulnerabilitiesOpen(value => !value) : setPhishingOpen(value => !value)} aria-expanded={expanded} aria-controls={path === '/atores' ? 'sidebar-actor-views' : path === '/cves' ? 'sidebar-vulnerability-views' : 'sidebar-phishing-views'}><Icon className="h-4 w-4 shrink-0" /><span>{path === '/phishing-analyzer' ? 'Phishing' : item.label}</span><ChevronDown className={cn('ml-auto h-3.5 w-3.5 transition-transform', expanded && 'rotate-180')} /></button> : <Link to={path === '/phishing-analyzer' ? '/phishing-analyzer?view=dashboard' : path} onClick={() => setMobileOpen(false)} aria-current={active ? 'page' : undefined} aria-label={item.label} title={rail ? item.label : undefined} className={linkClass}><Icon className="h-4 w-4 shrink-0" />{!rail && <span className="min-w-0 truncate">{item.label}</span>}</Link>}
            {path === '/atores' && !rail && actorsOpen && <div id="sidebar-actor-views" className="ml-4 mt-0.5 space-y-0.5 border-l border-sidebar-border pl-2">{[
              ['overview', pt ? 'Visão geral' : 'Overview'], ['catalog', pt ? 'Lista' : 'Listing'], ['global', 'Global'], ['model', pt ? 'Modelagem de ameaças' : 'Threat modelling'],
            ].map(([view, label]) => { const selected = active && !new URLSearchParams(search).has('actor') && (new URLSearchParams(search).get('view') || 'overview') === view; return <Link key={view} to={`/atores?view=${view}`} onClick={() => setMobileOpen(false)} aria-current={selected ? 'page' : undefined} className={cn('block rounded-md px-2 py-1.5 text-xs hover:bg-sidebar-accent focus-visible:ring-2 focus-visible:ring-ring', selected ? 'bg-primary font-medium text-primary-foreground' : 'text-muted-foreground')}>{label}</Link>; })}</div>}
            {path === '/cves' && !rail && vulnerabilitiesOpen && <div id="sidebar-vulnerability-views" className="ml-4 mt-0.5 space-y-0.5 border-l border-sidebar-border pl-2">{[
              ['overview', pt ? 'Visão geral' : 'Overview'], ['top', 'Top Threats'], ['weaponized', 'Weaponized'], ['listing', pt ? 'Listagem' : 'Listing'],
            ].map(([view, label]) => { const selected = active && !new URLSearchParams(search).has('cve') && (new URLSearchParams(search).get('view') || 'overview') === view; return <Link key={view} to={`/cves?view=${view}`} onClick={() => setMobileOpen(false)} aria-current={selected ? 'page' : undefined} className={cn('block rounded-md px-2 py-1.5 text-xs hover:bg-sidebar-accent focus-visible:ring-2 focus-visible:ring-ring', selected ? 'bg-primary font-medium text-primary-foreground' : 'text-muted-foreground')}>{label}</Link>; })}</div>}
            {path === '/phishing-analyzer' && !rail && phishingOpen && <div id="sidebar-phishing-views" className="ml-4 mt-0.5 space-y-0.5 border-l border-sidebar-border pl-2">{[
              ['dashboard', 'Dashboard'], ['campaigns', pt ? 'Campanhas' : 'Campaigns'], ['email', pt ? 'Analisar e-mail' : 'Analyze email'],
            ].map(([view, label]) => { const selected = active && (new URLSearchParams(search).get('view') || 'dashboard') === view; return <Link key={view} to={`/phishing-analyzer?view=${view}`} onClick={() => setMobileOpen(false)} aria-current={selected ? 'page' : undefined} className={cn('block rounded-md px-2 py-1.5 text-xs hover:bg-sidebar-accent focus-visible:ring-2 focus-visible:ring-ring', selected ? 'font-medium text-foreground' : 'text-muted-foreground')}>{label}</Link>; })}</div>}
          </div>;
        })}</div>
      </div>)}
    </nav>
    <div className="shrink-0 space-y-0.5 border-t border-sidebar-border p-2">
      {[catalog.find(item => item.path === '/vendors'), auth.authenticated ? { path: '/settings', label: pt ? 'Configurações' : 'Settings', icon: Settings } : null].filter(Boolean).map(item => {
        const Icon = item!.icon; const active = isRouteActive(item!.path, pathname);
        return <Link key={item!.path} to={item!.path} onClick={() => setMobileOpen(false)} aria-current={active ? 'page' : undefined} aria-label={item!.label} title={rail ? item!.label : undefined} className={cn('flex min-h-8 items-center gap-2 rounded px-2 py-1.5 text-xs hover:bg-sidebar-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring', rail && 'justify-center px-0', active ? 'bg-primary/10 font-semibold text-primary' : 'text-muted-foreground')}><Icon className="h-4 w-4 shrink-0" />{!rail && <span>{item!.label}</span>}</Link>;
      })}
      {!rail && <a href="https://github.com/kkroth0/thre4th-summary" target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 px-2 py-2 text-[10px] text-muted-foreground hover:text-foreground"><Github className="h-3.5 w-3.5" />Open source · AGPL-3.0</a>}
    </div>
  </>;
  return <WorkspaceNavigationContext.Provider value={{ openMenu: () => {
    menuOpener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setMobileOpen(true);
  } }}>
    <a href="#workspace-content" className="sr-only z-[60] rounded bg-background p-3 text-sm focus:not-sr-only focus:fixed focus:left-4 focus:top-4">{pt ? 'Ir para o conteúdo' : 'Skip to content'}</a>
    <div className="workbench min-h-screen bg-background">
      <aside aria-label={pt ? 'Barra lateral' : 'Sidebar'} className={cn('fixed inset-y-0 left-0 z-40 hidden flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground md:flex', collapsed ? 'w-14' : 'w-[224px]')}>{navigation(collapsed)}</aside>
      {mobile && <Sheet open={mobileOpen} onOpenChange={setMobileOpen}><SheetContent side="left" closeLabel={pt ? 'Fechar navegação' : 'Close navigation'} onCloseAutoFocus={event => {
        event.preventDefault();
        if (menuOpener.current?.isConnected) menuOpener.current.focus();
      }} className="workbench flex w-[248px] max-w-[85vw] flex-col gap-0 bg-sidebar p-0 text-sidebar-foreground"><SheetTitle className="sr-only">{pt ? 'Navegação principal' : 'Main navigation'}</SheetTitle><SheetDescription className="sr-only">{pt ? 'Navegue pelas áreas de inteligência de ameaças.' : 'Navigate threat intelligence areas.'}</SheetDescription>{navigation(false)}</SheetContent></Sheet>}
      <div id="workspace-content" tabIndex={-1} className={cn('min-w-0 outline-none', collapsed ? 'md:pl-14' : 'md:pl-[224px]')}>{children}</div>
    </div>
  </WorkspaceNavigationContext.Provider>;
}
