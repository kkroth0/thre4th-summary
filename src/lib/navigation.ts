const WORKSPACE_ROUTES = [
  '/dashboard', '/bulk', '/malware', '/newsletter', '/knowledge', '/relatorios', '/analyzer', '/atores', '/cves',
  '/patch-tuesday', '/sap-patch', '/ot-patch-day', '/ai-patch-day', '/threat-map', '/vendors', '/attack-surface',
  '/exposure-watchlist', '/phishing-analyzer', '/domain-monitoring', '/settings', '/profile', '/admin',
];
export const isRouteActive = (path: string, pathname: string) => {
  const clean = path.split(/[?#]/)[0] || '/';
  return clean === '/' ? pathname === '/' : pathname === clean || pathname.startsWith(`${clean}/`);
};
export const isWorkspaceRoute = (pathname: string) => WORKSPACE_ROUTES.some(path => isRouteActive(path, pathname));
