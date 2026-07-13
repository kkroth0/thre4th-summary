# Settings Navigation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move language, light/dark appearance, and the permission-gated Admin panel into segmented Settings while simplifying desktop and mobile sidebars.

**Architecture:** `Settings.tsx` owns authentication, URL-backed section selection, and the tabs shell. Focused `PreferencesSettings`, `ApiKeysSettings`, and `AdminSettings` components own their current contexts and network effects. The legacy `/admin` page becomes a permission-aware redirect.

**Tech Stack:** React 18, TypeScript, React Router 7, Tailwind CSS, shadcn/ui Tabs and form controls, next-themes-compatible local theme context.

## Global Constraints

- Keep the existing visual system; this is a small UI change inside the established design.
- Show Admin only when `auth.isAdmin === true`.
- Keep `/admin` compatible by redirecting to `/settings?section=admin` for administrators.
- Reuse `LanguageContext` and `ThemeProvider`; do not create duplicate preference state.
- Do not change authentication, API formats, admin operations, or BYOK behavior.
- Load BYOK and Admin data only while their sections are mounted.
- Preserve unrelated user changes, including the untracked `.superpowers/` directory.

---

### Task 1: Extract the BYOK settings section

**Files:**
- Create: `src/components/settings/ApiKeysSettings.tsx`
- Modify: `src/pages/Settings.tsx`

**Interfaces:**
- Consumes: `useLanguage()`, `useAuth().refresh`, and the existing `fetchApiKeys`, `saveApiKey`, and `deleteApiKey` functions.
- Produces: `export function ApiKeysSettings(): JSX.Element`, mounted only by the API keys tab.

- [ ] **Step 1: Establish the failing compile state**

Temporarily add this import to `Settings.tsx` before the component exists:

```tsx
import { ApiKeysSettings } from "@/components/settings/ApiKeysSettings";
```

- [ ] **Step 2: Verify the missing module fails**

Run: `npm run typecheck`

Expected: FAIL with `Cannot find module '@/components/settings/ApiKeysSettings'`.

- [ ] **Step 3: Move the existing BYOK implementation into the focused component**

Create `ApiKeysSettings.tsx` by moving `Provider`, `Group`, `CATALOG`, `KeyRow`, the `keys/loading/load/onChanged` state, the security notice, count badge, and catalog cards out of `Settings.tsx`. Export this entry point:

```tsx
export function ApiKeysSettings() {
  const { language } = useLanguage();
  const { refresh } = useAuth();
  const pt = language === "pt";
  const [keys, setKeys] = useState<ApiKeysState>({});
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setKeys(await fetchApiKeys());
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);
  const onChanged = () => { load(); refresh(); };

  return <>{/* existing BYOK notice, loading state, and catalog cards */}</>;
}
```

Keep the existing save, change, delete, toast, encryption notice, and provider link behavior verbatim. Remove BYOK network state and catalog markup from `Settings.tsx`.

- [ ] **Step 4: Verify the extraction**

Run: `npm run typecheck`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/components/settings/ApiKeysSettings.tsx src/pages/Settings.tsx
git commit -m "refactor: extract api key settings"
```

### Task 2: Extract the reusable Admin section and preserve `/admin`

**Files:**
- Create: `src/components/settings/AdminSettings.tsx`
- Modify: `src/pages/Admin.tsx`

**Interfaces:**
- Consumes: an authenticated admin mount from `Settings.tsx`; existing admin service calls and manager/editor components.
- Produces: `export function AdminSettings(): JSX.Element`; default `Admin` route component redirects according to auth state.

- [ ] **Step 1: Establish the failing compile state**

Add this unresolved import to `Admin.tsx`:

```tsx
import { AdminSettings } from "@/components/settings/AdminSettings";
```

- [ ] **Step 2: Verify the missing module fails**

Run: `npm run typecheck`

Expected: FAIL with `Cannot find module '@/components/settings/AdminSettings'`.

- [ ] **Step 3: Extract the panel without changing its workflows**

Move integration state, post state, effects, `loadPosts`, allowlist, publications, integration status, and feed-source markup into `AdminSettings.tsx`. Its public entry point starts as:

```tsx
export function AdminSettings() {
  const { language } = useLanguage();
  const pt = language === "pt";
  const [integrations, setIntegrations] = useState<IntegrationStatus[]>([]);
  const [keyless, setKeyless] = useState<string[]>([]);
  const [posts, setPosts] = useState<PostCard[]>([]);

  // Keep the current loadPosts and mount-time integration requests.
  return <div className="space-y-5">{/* existing admin cards */}</div>;
}
```

Replace `Admin.tsx` with the legacy route guard:

```tsx
import { Navigate } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { PageLayout } from "@/components/PageLayout";
import { useAuth } from "@/contexts/AuthContext";

export default function Admin() {
  const { auth, loading } = useAuth();
  if (loading) return (
    <PageLayout width="max-w-3xl">
      <Card><CardContent className="flex items-center gap-2 p-6 text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" /> Checking session…
      </CardContent></Card>
    </PageLayout>
  );
  if (!auth.authenticated) return <Navigate to="/login" replace />;
  return <Navigate to={auth.isAdmin ? "/settings?section=admin" : "/settings"} replace />;
}
```

- [ ] **Step 4: Verify extraction and route guard**

Run: `npm run typecheck`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/components/settings/AdminSettings.tsx src/pages/Admin.tsx
git commit -m "refactor: embed admin panel in settings"
```

### Task 3: Add General preferences and URL-backed Settings tabs

**Files:**
- Create: `src/components/settings/PreferencesSettings.tsx`
- Modify: `src/pages/Settings.tsx`

**Interfaces:**
- Consumes: `useLanguage().language/setLanguage`, `useTheme().theme/setTheme`, `useSearchParams`, `useAuth`.
- Produces: General, API keys, and conditional Admin tabs; canonical query values `general | api-keys | admin`.

- [ ] **Step 1: Establish the failing compile state**

Import the unresolved preferences component in `Settings.tsx`:

```tsx
import { PreferencesSettings } from "@/components/settings/PreferencesSettings";
```

- [ ] **Step 2: Verify the missing module fails**

Run: `npm run typecheck`

Expected: FAIL with `Cannot find module '@/components/settings/PreferencesSettings'`.

- [ ] **Step 3: Implement explicit language and appearance controls**

Create `PreferencesSettings.tsx` with labeled radio-style button groups. Use these exact option values:

```tsx
const languages = [
  { value: "pt", label: "Português", detail: "Brasil" },
  { value: "en", label: "English", detail: "United States" },
  { value: "es", label: "Español", detail: "España" },
  { value: "fr", label: "Français", detail: "France" },
] as const;

const themes = [
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
] as const;
```

Each option must be a real `Button` with `aria-pressed`, visible selected state, text label, and at least `h-11`. Call `setLanguage(option.value)` and `setTheme(option.value)` directly so existing storage remains authoritative.

- [ ] **Step 4: Build the authenticated tab shell**

In `Settings.tsx`, retain session loading and Login redirect. Normalize URL state before rendering:

```tsx
type SettingsSection = "general" | "api-keys" | "admin";

const requested = searchParams.get("section");
const section: SettingsSection =
  requested === "api-keys" ? "api-keys" :
  requested === "admin" && auth.isAdmin ? "admin" :
  "general";

const selectSection = (value: string) => {
  const next = value as SettingsSection;
  setSearchParams(next === "general" ? {} : { section: next }, { replace: true });
};
```

Render shadcn `Tabs` with triggers `Geral/General`, `Chaves de API/API Keys`, and conditional `Admin`. Mount each section inside its own `TabsContent`; use `overflow-x-auto` around `TabsList` for narrow screens. Keep the Settings page heading generic because each section owns its description.

- [ ] **Step 5: Verify URL state, types, and production build**

Run: `npm run typecheck && npm run build`

Expected: both commands PASS.

- [ ] **Step 6: Commit**

```bash
git add src/components/settings/PreferencesSettings.tsx src/pages/Settings.tsx
git commit -m "feat: segment account settings"
```

### Task 4: Simplify desktop and mobile sidebar actions

**Files:**
- Modify: `src/components/Header.tsx`
- Modify: `src/components/ThemeToggle.tsx` (delete if unused)
- Modify: `src/components/LanguageToggle.tsx` (delete if unused)

**Interfaces:**
- Consumes: existing auth state and sidebar collapse state.
- Produces: a single Settings entry for authenticated users and no loose preference/admin controls.

- [ ] **Step 1: Remove loose controls and expose the expected lint failures**

Remove `LanguageToggle`, `ThemeToggle`, and the separate `/admin` links from mobile and desktop markup, but leave their imports temporarily.

- [ ] **Step 2: Verify stale imports fail lint**

Run: `npm run lint`

Expected: FAIL for unused `LanguageToggle`, `ThemeToggle`, or `ShieldCheck` imports.

- [ ] **Step 3: Finish sidebar cleanup**

Remove the stale imports. Keep Settings rendered through `renderDesktopItem` for authenticated users. Change the final desktop row to contain only the collapse button, aligned to the right when expanded and centered when collapsed:

```tsx
<div className={cn("flex", isCollapsed ? "justify-center" : "justify-end")}>
  <Button onClick={toggleSidebar} /* retain current accessible title and icon */ />
</div>
```

In the mobile sheet, keep Profile and Settings for authenticated users. Do not render Admin, Language, or Theme actions. Search for remaining component usage:

Run: `rg -n 'LanguageToggle|ThemeToggle' src`

Expected: only component definitions remain. Delete both definition files because Settings now uses explicit controls.

- [ ] **Step 4: Verify static quality gates**

Run: `npm run lint && npm run typecheck && npm run build`

Expected: all commands PASS.

- [ ] **Step 5: Commit**

```bash
git add src/components/Header.tsx src/components/ThemeToggle.tsx src/components/LanguageToggle.tsx
git commit -m "feat: simplify sidebar settings access"
```

### Task 5: Browser verification and final regression check

**Files:**
- Modify only files required to fix observed regressions.

**Interfaces:**
- Consumes: the completed Settings and sidebar behavior.
- Produces: verified desktop, collapsed, mobile, preference, permission, and legacy-route flows.

- [ ] **Step 1: Start the app and record the browser fallback if no Browser plugin is callable**

Run: `npm run dev -- --host 127.0.0.1`

Expected: Vite serves the app at the reported local URL.

- [ ] **Step 2: Verify authenticated Settings behavior**

Using the available browser tool, check:

```text
/settings                         -> General selected
/settings?section=api-keys        -> API Keys selected; keys request starts here
/settings?section=admin (admin)   -> Admin selected; admin requests start here
/settings?section=admin (member)  -> General selected; no admin UI/request
/admin (admin)                    -> redirects to /settings?section=admin
/admin (member)                   -> redirects to /settings
```

Change language and theme, reload, and confirm both persist. Confirm the sidebar contains Settings but no standalone Admin, language, or theme control.

- [ ] **Step 3: Verify responsive navigation**

At desktop width, test expanded and collapsed sidebar. At a mobile viewport such as `390x844`, open the sheet and confirm Profile and Settings remain readable, the tab row scrolls if needed, and no horizontal page overflow appears.

- [ ] **Step 4: Run the complete frontend gate**

Run: `npm run ci`

Expected: lint, typecheck, and build PASS.

- [ ] **Step 5: Commit any QA repairs**

```bash
git add <only-the-files-changed-for-qa>
git commit -m "fix: polish segmented settings"
```

Skip this commit when QA requires no repairs.
