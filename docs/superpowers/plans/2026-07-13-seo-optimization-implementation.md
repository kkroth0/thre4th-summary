# SEO Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a centralized SEO layer for `https://threatsumm4ry.app/` that improves crawlability, canonical metadata, route-specific titles/descriptions, sitemap discovery, and PT-BR/English metadata support.

**Architecture:** Keep SEO data in a small config module that both tests and runtime code can consume. Static crawler-facing files live in `public/` and `index.html`; SPA route changes are handled by a React `Seo` component that updates document metadata from the same catalog.

**Tech Stack:** React 18, Vite, TypeScript, `react-router-dom`, Node built-in test runner, esbuild-based test bundling.

## Global Constraints

- Canonical site URL is exactly `https://threatsumm4ry.app/`.
- Supported SEO languages for this change are Portuguese Brazil (`pt-BR`, app language key `pt`) and English (`en`).
- Do not create URL parameters or artificial locale URLs.
- Do not include private, admin, auth, profile, settings, or premium-protected routes in `public/sitemap.xml`.
- Keep `/advisories/:slug` dynamic metadata handled by `functions/advisories/[slug].js`.
- Do not migrate the SPA to SSR/SSG.
- Do not implement JSON-LD schema in this change.
- Use ASCII in edited files unless the file already contains non-ASCII text.

---

### Task 1: SEO Catalog

**Files:**
- Create: `src/config/seo.ts`
- Create: `src/config/seo.test.ts`

**Interfaces:**
- Produces: `SITE_URL: "https://threatsumm4ry.app"`
- Produces: `DEFAULT_OG_IMAGE: "/threatsumm4ry-og-image-1200x630.png"`
- Produces: `PUBLIC_SEO_ROUTES: SeoRoute[]`
- Produces: `getCanonicalUrl(path: string): string`
- Produces: `getSeoRoute(path: string): SeoRoute`
- Produces: `getSeoMetadata(path: string, language: "pt" | "en" | string): LocalizedSeo`
- Consumes: no previous task outputs.

- [ ] **Step 1: Write the failing catalog tests**

Create `src/config/seo.test.ts`:

```ts
import assert from "node:assert/strict";
import test from "node:test";
import {
  PUBLIC_SEO_ROUTES,
  SITE_URL,
  getCanonicalUrl,
  getSeoMetadata,
  getSeoRoute,
} from "./seo";

const expectedRoutes = [
  "/",
  "/analyzer",
  "/cves",
  "/atores",
  "/advisories",
  "/latam-threats",
  "/threat-map",
  "/patch-tuesday",
  "/vendors",
  "/dnsbl",
  "/attack-surface",
  "/phishing-analyzer",
];

test("defines the canonical production site URL", () => {
  assert.equal(SITE_URL, "https://threatsumm4ry.app");
});

test("lists the approved public SEO routes only", () => {
  assert.deepEqual(PUBLIC_SEO_ROUTES.map((route) => route.path), expectedRoutes);
  assert.equal(PUBLIC_SEO_ROUTES.some((route) => route.path === "/login"), false);
  assert.equal(PUBLIC_SEO_ROUTES.some((route) => route.path === "/settings"), false);
  assert.equal(PUBLIC_SEO_ROUTES.some((route) => route.path === "/newsletter"), false);
});

test("builds stable absolute canonical URLs", () => {
  assert.equal(getCanonicalUrl("/"), "https://threatsumm4ry.app/");
  assert.equal(getCanonicalUrl("/cves"), "https://threatsumm4ry.app/cves");
  assert.equal(getCanonicalUrl("dnsbl"), "https://threatsumm4ry.app/dnsbl");
  assert.equal(getCanonicalUrl("/dnsbl/"), "https://threatsumm4ry.app/dnsbl");
});

test("returns localized metadata and falls back to English for unsupported app languages", () => {
  const pt = getSeoMetadata("/phishing-analyzer", "pt");
  const en = getSeoMetadata("/phishing-analyzer", "en");
  const fallback = getSeoMetadata("/phishing-analyzer", "fr");

  assert.match(pt.title, /ThreatSumm4ry/);
  assert.match(pt.description, /phishing/i);
  assert.match(en.description, /phishing/i);
  assert.equal(fallback.title, en.title);
  assert.equal(pt.canonicalUrl, "https://threatsumm4ry.app/phishing-analyzer");
});

test("falls back to homepage metadata for unknown routes", () => {
  const unknown = getSeoRoute("/not-a-real-page");
  assert.equal(unknown.path, "/");
});

test("keeps every public route fully described in both SEO languages", () => {
  const titles = new Set<string>();
  const descriptions = new Set<string>();

  for (const route of PUBLIC_SEO_ROUTES) {
    for (const lang of ["pt", "en"] as const) {
      const metadata = getSeoMetadata(route.path, lang);
      assert.ok(metadata.title.length >= 20, `${route.path} ${lang} title is too short`);
      assert.ok(metadata.description.length >= 80, `${route.path} ${lang} description is too short`);
      assert.ok(metadata.description.length <= 180, `${route.path} ${lang} description is too long`);
      assert.match(metadata.canonicalUrl, /^https:\/\/threatsumm4ry\.app\//);
      titles.add(metadata.title);
      descriptions.add(metadata.description);
    }
  }

  assert.equal(titles.size, PUBLIC_SEO_ROUTES.length * 2);
  assert.equal(descriptions.size, PUBLIC_SEO_ROUTES.length * 2);
});
```

- [ ] **Step 2: Run the catalog tests to verify RED**

Run:

```bash
npm run test:unit
```

Expected: FAIL because `src/config/seo.ts` does not exist or does not export the expected symbols.

- [ ] **Step 3: Implement the SEO catalog**

Create `src/config/seo.ts`:

```ts
export const SITE_URL = "https://threatsumm4ry.app";
export const DEFAULT_OG_IMAGE = "/threatsumm4ry-og-image-1200x630.png";
export const DEFAULT_OG_IMAGE_URL = `${SITE_URL}${DEFAULT_OG_IMAGE}`;

export type SeoLanguage = "pt" | "en";

export type LocalizedSeoCopy = {
  title: string;
  description: string;
};

export type LocalizedSeo = LocalizedSeoCopy & {
  canonicalUrl: string;
  imageUrl: string;
  locale: "pt_BR" | "en_US";
  htmlLang: "pt-BR" | "en";
};

export type SeoRoute = {
  path: string;
  priority: string;
  changefreq: "daily" | "weekly" | "monthly";
  metadata: Record<SeoLanguage, LocalizedSeoCopy>;
};

const trimTrailingSlash = (value: string) => value.replace(/\/+$/, "");

const normalizePath = (path: string) => {
  if (!path || path === "/") return "/";
  const withSlash = path.startsWith("/") ? path : `/${path}`;
  return trimTrailingSlash(withSlash);
};

export const PUBLIC_SEO_ROUTES: SeoRoute[] = [
  {
    path: "/",
    priority: "1.0",
    changefreq: "weekly",
    metadata: {
      pt: {
        title: "ThreatSumm4ry | Plataforma CTI para SOC e Threat Hunting",
        description:
          "ThreatSumm4ry centraliza enriquecimento de IOCs, CVEs, advisories, ransomware e hunting para analistas SOC e times de inteligencia de ameacas.",
      },
      en: {
        title: "ThreatSumm4ry | CTI Platform for SOC and Threat Hunting",
        description:
          "ThreatSumm4ry centralizes IOC enrichment, CVE tracking, advisories, ransomware intelligence, and hunting workflows for SOC and CTI teams.",
      },
    },
  },
  {
    path: "/analyzer",
    priority: "0.95",
    changefreq: "weekly",
    metadata: {
      pt: {
        title: "Busca de IOCs em 21 fontes | ThreatSumm4ry",
        description:
          "Analise IPv4, IPv6, dominios, URLs e hashes em fontes CTI como VirusTotal, AbuseIPDB, Shodan, OTX e abuse.ch em uma unica busca.",
      },
      en: {
        title: "IOC Search Across 21 Sources | ThreatSumm4ry",
        description:
          "Analyze IPv4, IPv6, domains, URLs, and hashes across CTI sources such as VirusTotal, AbuseIPDB, Shodan, OTX, and abuse.ch in one search.",
      },
    },
  },
  {
    path: "/cves",
    priority: "0.9",
    changefreq: "daily",
    metadata: {
      pt: {
        title: "Painel de CVEs, EPSS e CISA KEV | ThreatSumm4ry",
        description:
          "Acompanhe CVEs com contexto de EPSS, CISA KEV, exploracao publica, fabricantes afetados e priorizacao para times de seguranca.",
      },
      en: {
        title: "CVE, EPSS, and CISA KEV Dashboard | ThreatSumm4ry",
        description:
          "Track CVEs with EPSS, CISA KEV, public exploit context, affected vendors, and prioritization signals for security teams.",
      },
    },
  },
  {
    path: "/atores",
    priority: "0.75",
    changefreq: "weekly",
    metadata: {
      pt: {
        title: "Atores de Ameaca, TTPs e Malware | ThreatSumm4ry",
        description:
          "Consulte perfis de atores de ameaca com aliases, tecnicas MITRE ATT&CK, malware associado, setores alvo e referencias de pesquisa.",
      },
      en: {
        title: "Threat Actors, TTPs, and Malware | ThreatSumm4ry",
        description:
          "Browse threat actor profiles with aliases, MITRE ATT&CK techniques, associated malware, target sectors, and research references.",
      },
    },
  },
  {
    path: "/advisories",
    priority: "0.85",
    changefreq: "daily",
    metadata: {
      pt: {
        title: "Advisories e Boletim Diario de Seguranca | ThreatSumm4ry",
        description:
          "Leia advisories normalizados, boletins diarios, KPIs e alertas de fornecedores para acompanhar riscos relevantes de seguranca.",
      },
      en: {
        title: "Security Advisories and Daily Brief | ThreatSumm4ry",
        description:
          "Read normalized advisories, daily briefs, KPIs, and vendor alerts to track relevant security risks in one operational feed.",
      },
    },
  },
  {
    path: "/latam-threats",
    priority: "0.75",
    changefreq: "daily",
    metadata: {
      pt: {
        title: "Ameacas na America Latina | ThreatSumm4ry",
        description:
          "Monitore ransomware, vitimas recentes, IOCs e sinais de atividade maliciosa relevantes para organizacoes na America Latina.",
      },
      en: {
        title: "Latin America Threat Intelligence | ThreatSumm4ry",
        description:
          "Monitor ransomware, recent victims, IOCs, and malicious activity signals relevant to organizations across Latin America.",
      },
    },
  },
  {
    path: "/threat-map",
    priority: "0.7",
    changefreq: "daily",
    metadata: {
      pt: {
        title: "Mapa de Ameacas e Ransomware | ThreatSumm4ry",
        description:
          "Visualize vitimas de ransomware por pais e acompanhe distribuicao geografica de incidentes para analise de inteligencia.",
      },
      en: {
        title: "Threat Map and Ransomware Activity | ThreatSumm4ry",
        description:
          "Visualize ransomware victims by country and follow geographic incident distribution for threat intelligence analysis.",
      },
    },
  },
  {
    path: "/patch-tuesday",
    priority: "0.7",
    changefreq: "monthly",
    metadata: {
      pt: {
        title: "Patch Tuesday Microsoft e CVEs Criticas | ThreatSumm4ry",
        description:
          "Acompanhe o Patch Tuesday da Microsoft com CVEs criticas, familias de produtos afetadas, impacto e links oficiais de correcao.",
      },
      en: {
        title: "Microsoft Patch Tuesday and Critical CVEs | ThreatSumm4ry",
        description:
          "Follow Microsoft Patch Tuesday with critical CVEs, affected product families, impact context, and official remediation links.",
      },
    },
  },
  {
    path: "/vendors",
    priority: "0.65",
    changefreq: "monthly",
    metadata: {
      pt: {
        title: "Fontes CTI e Integracoes de Seguranca | ThreatSumm4ry",
        description:
          "Veja fontes, integracoes e cobertura de dados usadas pelo ThreatSumm4ry para enriquecimento de IOCs, CVEs e advisories.",
      },
      en: {
        title: "CTI Sources and Security Integrations | ThreatSumm4ry",
        description:
          "Review the sources, integrations, and data coverage ThreatSumm4ry uses for IOC enrichment, CVE tracking, and advisories.",
      },
    },
  },
  {
    path: "/dnsbl",
    priority: "0.8",
    changefreq: "weekly",
    metadata: {
      pt: {
        title: "Consulta DNSBL para IPs e Dominios | ThreatSumm4ry",
        description:
          "Consulte reputacao de IPs, dominios e ranges em blocklists DNSBL paralelas com resultados exportaveis para analise SOC.",
      },
      en: {
        title: "DNSBL Lookup for IPs and Domains | ThreatSumm4ry",
        description:
          "Check reputation for IPs, domains, and ranges across parallel DNSBL blocklists with exportable results for SOC analysis.",
      },
    },
  },
  {
    path: "/attack-surface",
    priority: "0.8",
    changefreq: "weekly",
    metadata: {
      pt: {
        title: "Monitoramento de Superficie de Ataque | ThreatSumm4ry",
        description:
          "Mapeie dominios, certificados, servicos expostos e riscos externos com exportacao XLSX e monitoramento de exposicao.",
      },
      en: {
        title: "Attack Surface Monitoring | ThreatSumm4ry",
        description:
          "Map domains, certificates, exposed services, and external risks with XLSX export and exposure monitoring workflows.",
      },
    },
  },
  {
    path: "/phishing-analyzer",
    priority: "0.8",
    changefreq: "weekly",
    metadata: {
      pt: {
        title: "Analisador de Phishing, Headers e URLs | ThreatSumm4ry",
        description:
          "Analise emails suspeitos com verificacao de headers, SPF, DKIM, DMARC, URLs, anexos, IOCs e sinais de phishing.",
      },
      en: {
        title: "Phishing Analyzer for Headers and URLs | ThreatSumm4ry",
        description:
          "Analyze suspicious emails with header checks, SPF, DKIM, DMARC, URLs, attachments, IOCs, and phishing indicators.",
      },
    },
  },
];

export const DEFAULT_SEO_ROUTE = PUBLIC_SEO_ROUTES[0];

export const getCanonicalUrl = (path: string) => {
  const normalizedPath = normalizePath(path);
  return normalizedPath === "/" ? `${SITE_URL}/` : `${SITE_URL}${normalizedPath}`;
};

export const getSeoRoute = (path: string) => {
  const normalizedPath = normalizePath(path);
  return PUBLIC_SEO_ROUTES.find((route) => route.path === normalizedPath) ?? DEFAULT_SEO_ROUTE;
};

export const getSeoLanguage = (language: string): SeoLanguage => (language === "pt" ? "pt" : "en");

export const getSeoMetadata = (path: string, language: string): LocalizedSeo => {
  const route = getSeoRoute(path);
  const seoLanguage = getSeoLanguage(language);
  const copy = route.metadata[seoLanguage];

  return {
    ...copy,
    canonicalUrl: getCanonicalUrl(route.path),
    imageUrl: DEFAULT_OG_IMAGE_URL,
    locale: seoLanguage === "pt" ? "pt_BR" : "en_US",
    htmlLang: seoLanguage === "pt" ? "pt-BR" : "en",
  };
};
```

- [ ] **Step 4: Run the catalog tests to verify GREEN**

Run:

```bash
npm run test:unit
```

Expected: PASS for `src/config/seo.test.ts`. Existing unrelated tests should remain green.

- [ ] **Step 5: Commit Task 1**

```bash
git add src/config/seo.ts src/config/seo.test.ts
git commit -m "feat: add seo metadata catalog"
```

---

### Task 2: Static SEO Files and Base HTML

**Files:**
- Modify: `index.html`
- Modify: `public/robots.txt`
- Create: `public/sitemap.xml`
- Modify: `src/brandAssets.test.ts`
- Test: `src/config/seo.test.ts`

**Interfaces:**
- Consumes: `PUBLIC_SEO_ROUTES`, `SITE_URL`, `getCanonicalUrl` from Task 1.
- Produces: crawler-facing `public/sitemap.xml`.
- Produces: base HTML metadata for `/`.

- [ ] **Step 1: Add failing static SEO tests**

Append to `src/brandAssets.test.ts`:

```ts
test("declares canonical production SEO metadata in the base HTML", async () => {
  const html = await read("index.html");

  assert.match(html, /<html lang="pt-BR">/);
  assert.match(html, /<link rel="canonical" href="https:\/\/threatsumm4ry\.app\/" \/>/);
  assert.match(html, /property="og:url" content="https:\/\/threatsumm4ry\.app\/"/);
  assert.match(html, /property="og:image" content="https:\/\/threatsumm4ry\.app\/threatsumm4ry-og-image-1200x630\.png"/);
  assert.match(html, /name="twitter:image" content="https:\/\/threatsumm4ry\.app\/threatsumm4ry-og-image-1200x630\.png"/);
  assert.match(html, /name="language" content="pt-BR"/);
});

test("publishes robots sitemap discovery", async () => {
  const robots = await read("public/robots.txt");

  assert.match(robots, /User-agent: \*/);
  assert.match(robots, /Allow: \//);
  assert.match(robots, /Sitemap: https:\/\/threatsumm4ry\.app\/sitemap\.xml/);
});

test("publishes the approved static sitemap", async () => {
  const sitemap = await read("public/sitemap.xml");
  const expectedRoutes = [
    "/",
    "/analyzer",
    "/cves",
    "/atores",
    "/advisories",
    "/latam-threats",
    "/threat-map",
    "/patch-tuesday",
    "/vendors",
    "/dnsbl",
    "/attack-surface",
    "/phishing-analyzer",
  ];

  assert.match(sitemap, /<urlset xmlns="http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9">/);
  for (const route of expectedRoutes) {
    const url = route === "/" ? "https://threatsumm4ry.app/" : `https://threatsumm4ry.app${route}`;
    assert.match(sitemap, new RegExp(`<loc>${url.replace(/\//g, "\\/")}<\\/loc>`));
  }

  assert.doesNotMatch(sitemap, /\/login<\/loc>/);
  assert.doesNotMatch(sitemap, /\/settings<\/loc>/);
  assert.doesNotMatch(sitemap, /\/newsletter<\/loc>/);
});
```

- [ ] **Step 2: Run static tests to verify RED**

Run:

```bash
npm run test:brand
```

Expected: FAIL because `index.html` lacks canonical production metadata, `robots.txt` lacks the sitemap line, and `public/sitemap.xml` does not exist.

- [ ] **Step 3: Update `index.html` base metadata**

Change the `<html>` tag and base metadata in `index.html`:

```html
<html lang="pt-BR">
```

Use these values in `<head>`:

```html
  <title>ThreatSumm4ry | Plataforma CTI para SOC e Threat Hunting</title>
  <meta name="description" content="ThreatSumm4ry centraliza enriquecimento de IOCs, CVEs, advisories, ransomware e hunting para analistas SOC e times de inteligencia de ameacas." />
  <meta name="language" content="pt-BR" />
  <link rel="canonical" href="https://threatsumm4ry.app/" />

  <meta property="og:title" content="ThreatSumm4ry | Plataforma CTI para SOC e Threat Hunting" />
  <meta property="og:description" content="ThreatSumm4ry centraliza enriquecimento de IOCs, CVEs, advisories, ransomware e hunting para analistas SOC e times de inteligencia de ameacas." />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://threatsumm4ry.app/" />
  <meta property="og:image" content="https://threatsumm4ry.app/threatsumm4ry-og-image-1200x630.png" />
  <meta property="og:image:width" content="1200" />
  <meta property="og:image:height" content="630" />
  <meta property="og:locale" content="pt_BR" />
  <meta property="og:locale:alternate" content="en_US" />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="ThreatSumm4ry | Plataforma CTI para SOC e Threat Hunting" />
  <meta name="twitter:description" content="ThreatSumm4ry centraliza enriquecimento de IOCs, CVEs, advisories, ransomware e hunting para analistas SOC e times de inteligencia de ameacas." />
  <meta name="twitter:image" content="https://threatsumm4ry.app/threatsumm4ry-og-image-1200x630.png" />
```

Keep existing favicon, manifest, theme, analytics, font, and RSS tags.

- [ ] **Step 4: Update `public/robots.txt`**

Replace `public/robots.txt` with:

```txt
User-agent: Googlebot
Allow: /

User-agent: Bingbot
Allow: /

User-agent: Twitterbot
Allow: /

User-agent: facebookexternalhit
Allow: /

User-agent: *
Allow: /

Sitemap: https://threatsumm4ry.app/sitemap.xml
```

- [ ] **Step 5: Create `public/sitemap.xml`**

Create `public/sitemap.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://threatsumm4ry.app/</loc>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://threatsumm4ry.app/analyzer</loc>
    <changefreq>weekly</changefreq>
    <priority>0.95</priority>
  </url>
  <url>
    <loc>https://threatsumm4ry.app/cves</loc>
    <changefreq>daily</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>https://threatsumm4ry.app/atores</loc>
    <changefreq>weekly</changefreq>
    <priority>0.75</priority>
  </url>
  <url>
    <loc>https://threatsumm4ry.app/advisories</loc>
    <changefreq>daily</changefreq>
    <priority>0.85</priority>
  </url>
  <url>
    <loc>https://threatsumm4ry.app/latam-threats</loc>
    <changefreq>daily</changefreq>
    <priority>0.75</priority>
  </url>
  <url>
    <loc>https://threatsumm4ry.app/threat-map</loc>
    <changefreq>daily</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>https://threatsumm4ry.app/patch-tuesday</loc>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>https://threatsumm4ry.app/vendors</loc>
    <changefreq>monthly</changefreq>
    <priority>0.65</priority>
  </url>
  <url>
    <loc>https://threatsumm4ry.app/dnsbl</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://threatsumm4ry.app/attack-surface</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://threatsumm4ry.app/phishing-analyzer</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
</urlset>
```

- [ ] **Step 6: Run static tests to verify GREEN**

Run:

```bash
npm run test:brand
```

Expected: PASS.

- [ ] **Step 7: Commit Task 2**

```bash
git add index.html public/robots.txt public/sitemap.xml src/brandAssets.test.ts
git commit -m "feat: publish static seo metadata"
```

---

### Task 3: Runtime SEO Component

**Files:**
- Create: `src/components/Seo.tsx`
- Modify: `src/App.tsx`
- Test: `src/config/seo.test.ts`

**Interfaces:**
- Consumes: `getSeoMetadata(path, language)` from Task 1.
- Produces: React component `Seo` with signature `export function Seo(): null`.

- [ ] **Step 1: Add a failing helper assertion for metadata values used by the component**

Append this test to `src/config/seo.test.ts`:

```ts
test("provides metadata needed by the runtime SEO component", () => {
  const metadata = getSeoMetadata("/cves", "pt");

  assert.equal(metadata.htmlLang, "pt-BR");
  assert.equal(metadata.locale, "pt_BR");
  assert.equal(metadata.imageUrl, "https://threatsumm4ry.app/threatsumm4ry-og-image-1200x630.png");
  assert.match(metadata.title, /CVE/i);
  assert.match(metadata.description, /EPSS/);
});
```

- [ ] **Step 2: Run unit tests to verify RED if helpers are incomplete**

Run:

```bash
npm run test:unit
```

Expected: PASS if Task 1 already produced the required metadata shape. If it fails, update `src/config/seo.ts` before continuing.

- [ ] **Step 3: Create `src/components/Seo.tsx`**

Create:

```tsx
import { useEffect } from "react";
import { useLocation } from "react-router-dom";
import { getSeoMetadata } from "@/config/seo";
import { useLanguage } from "@/contexts/LanguageContext";

const upsertMeta = (selector: string, attributes: Record<string, string>) => {
  let element = document.head.querySelector<HTMLMetaElement>(selector);
  if (!element) {
    element = document.createElement("meta");
    document.head.appendChild(element);
  }

  for (const [name, value] of Object.entries(attributes)) {
    element.setAttribute(name, value);
  }
};

const upsertLink = (selector: string, attributes: Record<string, string>) => {
  let element = document.head.querySelector<HTMLLinkElement>(selector);
  if (!element) {
    element = document.createElement("link");
    document.head.appendChild(element);
  }

  for (const [name, value] of Object.entries(attributes)) {
    element.setAttribute(name, value);
  }
};

export function Seo() {
  const location = useLocation();
  const { language } = useLanguage();

  useEffect(() => {
    const metadata = getSeoMetadata(location.pathname, language);

    document.documentElement.lang = metadata.htmlLang;
    document.title = metadata.title;

    upsertMeta('meta[name="description"]', { name: "description", content: metadata.description });
    upsertMeta('meta[name="language"]', { name: "language", content: metadata.htmlLang });
    upsertMeta('meta[property="og:title"]', { property: "og:title", content: metadata.title });
    upsertMeta('meta[property="og:description"]', { property: "og:description", content: metadata.description });
    upsertMeta('meta[property="og:type"]', { property: "og:type", content: "website" });
    upsertMeta('meta[property="og:url"]', { property: "og:url", content: metadata.canonicalUrl });
    upsertMeta('meta[property="og:image"]', { property: "og:image", content: metadata.imageUrl });
    upsertMeta('meta[property="og:locale"]', { property: "og:locale", content: metadata.locale });
    upsertMeta('meta[name="twitter:card"]', { name: "twitter:card", content: "summary_large_image" });
    upsertMeta('meta[name="twitter:title"]', { name: "twitter:title", content: metadata.title });
    upsertMeta('meta[name="twitter:description"]', { name: "twitter:description", content: metadata.description });
    upsertMeta('meta[name="twitter:image"]', { name: "twitter:image", content: metadata.imageUrl });

    upsertLink('link[rel="canonical"]', { rel: "canonical", href: metadata.canonicalUrl });
  }, [language, location.pathname]);

  return null;
}
```

- [ ] **Step 4: Mount `Seo` in `src/App.tsx`**

Add:

```tsx
import { Seo } from "./components/Seo";
```

Inside `<BrowserRouter>`, before `<Suspense>`:

```tsx
            <Seo />
```

- [ ] **Step 5: Run unit tests and typecheck**

Run:

```bash
npm run test:unit
npm run typecheck
```

Expected: both PASS.

- [ ] **Step 6: Commit Task 3**

```bash
git add src/components/Seo.tsx src/App.tsx src/config/seo.test.ts
git commit -m "feat: update seo metadata on route changes"
```

---

### Task 4: Advisory Function Consistency and Final Verification

**Files:**
- Modify: `functions/advisories/[slug].js`
- Modify: `src/brandAssets.test.ts`

**Interfaces:**
- Consumes: static metadata decisions from Tasks 1-3.
- Produces: dynamic advisory metadata that uses absolute social image URL, canonical URL, and `og:locale`.

- [ ] **Step 1: Add failing advisory metadata assertions**

Append or update the dynamic advisory metadata test in `src/brandAssets.test.ts`:

```ts
test("dynamic advisory metadata stays aligned with production SEO defaults", async () => {
  const advisory = await read("functions/advisories/[slug].js");

  assert.match(advisory, /<meta property="og:type" content="article" \/>/);
  assert.match(advisory, /<meta property="og:locale" content="pt_BR" \/>/);
  assert.match(advisory, /<meta name="language" content="pt-BR" \/>/);
  assert.match(advisory, /\$\{url\.origin\}\/threatsumm4ry-og-image-1200x630\.png/);
  assert.match(advisory, /<link rel="canonical" href="\$\{esc\(canonical\)\}" \/>/);
});
```

- [ ] **Step 2: Run brand tests to verify RED**

Run:

```bash
npm run test:brand
```

Expected: FAIL until the advisory function includes `og:locale` and `language`.

- [ ] **Step 3: Update `functions/advisories/[slug].js` injected metadata**

Add these lines to the `injected` array after `og:image`:

```js
                        `<meta property="og:locale" content="pt_BR" />`,
                        `<meta name="language" content="pt-BR" />`,
```

Keep the existing canonical and article metadata.

- [ ] **Step 4: Run final verification**

Run:

```bash
npm run test:brand
npm run test:unit
npm run typecheck
npm run build
```

Expected: all commands PASS.

- [ ] **Step 5: Commit Task 4**

```bash
git add functions/advisories/[slug].js src/brandAssets.test.ts
git commit -m "feat: align advisory seo metadata"
```

---

## Self-Review

- Spec coverage: Task 1 covers centralized route metadata; Task 2 covers `index.html`, `robots.txt`, and `sitemap.xml`; Task 3 covers SPA runtime metadata updates; Task 4 covers dynamic advisory consistency and final verification.
- Placeholder scan: no task contains unresolved markers or unspecified validation.
- Type consistency: `getSeoMetadata(path, language)` returns the fields consumed by `Seo`; `PUBLIC_SEO_ROUTES` is the catalog used by tests and sitemap verification.
