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
        title: "ThreatSumm4ry | Plataforma CTI para SOC",
        description:
          "ThreatSumm4ry centraliza enriquecimento de IOCs, CVEs, advisories e ransomware para analistas SOC e times de inteligencia de ameacas.",
      },
      en: {
        title: "ThreatSumm4ry | CTI Platform for SOC Teams",
        description:
          "ThreatSumm4ry centralizes IOC enrichment, CVE tracking, advisories, and ransomware intelligence for SOC and CTI teams.",
      },
    },
  },
  {
    path: "/analyzer",
    priority: "0.95",
    changefreq: "weekly",
    metadata: {
      pt: {
        // Estático de propósito: título de SEO não pode variar a cada deploy, senão
        // o buscador reindexa por nada. Conferir contra IOC_SOURCE_COUNT ao mexer
        // na lista de vendors.
        title: "Busca de IOCs em 18 fontes | ThreatSumm4ry",
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
    path: "/threat-map",
    priority: "0.7",
    changefreq: "daily",
    metadata: {
      pt: {
        title: "Vitimas de Ransomware | ThreatSumm4ry",
        description:
          "Vitimas reivindicadas por grupos de ransomware, com grupo, pais, setor, data e a evidencia de cada reivindicacao.",
      },
      en: {
        title: "Ransomware Victims | ThreatSumm4ry",
        description:
          "Victims claimed by ransomware crews, with group, country, sector, date and the evidence behind each claim.",
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
    path: "/sap-patch",
    priority: "0.7",
    changefreq: "monthly",
    metadata: {
      pt: {
        title: "SAP Security Patch Day e Notas de Seguranca | ThreatSumm4ry",
        description:
          "Acompanhe o SAP Security Patch Day mensal: notas de seguranca, CVEs, prioridade (Hot News) e CVSS com links oficiais da SAP.",
      },
      en: {
        title: "SAP Security Patch Day and Security Notes | ThreatSumm4ry",
        description:
          "Track the monthly SAP Security Patch Day: security notes, CVEs, priority (Hot News) and CVSS with official SAP note links.",
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
        title: "Attack Surface e Monitoramento Externo | ThreatSumm4ry",
        description:
          "Mapeie servicos expostos via Shodan, importe alvos em massa, exporte XLSX e monitore drift em ativos externos salvos.",
      },
      en: {
        title: "Attack Surface and External Monitoring | ThreatSumm4ry",
        description:
          "Map exposed services with Shodan, bulk-import targets, export XLSX, and monitor drift across saved external assets.",
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
