import type React from "react";
import { Activity, Layers, Bug, Rss, Bookmark, FileSearch, Users, MapPinned, Shield, CalendarCheck, ShieldCheck, Search, Mail, Radar, Globe, Crosshair } from "lucide-react";
import { useLanguage } from "@/contexts/LanguageContext";
import { actorPageCopy } from "@/pages/actorsView";

export type NavItem = {
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

// Catálogo compartilhado pelo menu e pelo título da página.
export function useNavCatalog() {
  const { language, tr } = useLanguage();
  const pt = language === "pt";

  const homeItem: NavItem = {
    path: "/newsletter",
    label: tr({ pt: "Notícias e IOCs", en: "News and IOCs", es: "Noticias e IOCs", fr: "Actualités et IOCs" }),
    description: pt ? "Notícias, advisories e pesquisas de segurança." : "Security news, advisories and research.",
    icon: Rss,
    premium: true,
  };

  const navGroups: NavGroup[] = [
    {
      label: pt ? "Pesquisa e contexto" : "Research and context",
      items: [
        { path: '/dashboard', label: pt ? 'Visão geral' : 'Overview', icon: Activity },
        { path: '/hunting', label: 'Threat Hunting', description: pt ? 'O que caçar hoje, na semana e no mês.' : 'What to hunt today, this week and this month.', icon: Crosshair, premium: true },
        { path: '/bulk', label: pt ? 'Enriquecimento em lote' : 'Bulk enrichment', icon: Layers },
        { path: '/malware', label: 'Malware', icon: Bug },
        {
          path: "/knowledge",
          label: tr({ pt: "Publicações salvas", en: "Saved publications", es: "Publicaciones guardadas", fr: "Publications enregistrées" }),
          description: pt ? "Notícias e relatórios salvos." : "Saved news and reports.",
          icon: Bookmark,
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
          label: tr({ pt: "SAP Patch Day", en: "SAP Patch Day", es: "SAP Patch Day", fr: "SAP Patch Day" }),
          description: pt ? "Notas de segurança mensais da SAP." : "Monthly SAP security notes.",
          icon: ShieldCheck,
        },
        { path: '/ot-patch-day', label: 'OT/ICS Patch Day', description: pt ? 'Correções industriais por mês e fabricante.' : 'Industrial fixes by month and manufacturer.', icon: CalendarCheck },
        { path: '/ai-patch-day', label: 'AI Tools Patch Day', description: pt ? 'Segurança de LLMs, agentes, MCP e ferramentas de IA.' : 'LLM, agent, MCP and AI tool security.', icon: CalendarCheck },
      ],
    },
    {
      label: pt ? "Ferramentas de apoio" : "Supporting tools",
      items: [
        { path: "/analyzer", label: pt ? "Enriquecimento" : "Enrichment", description: pt ? "IPs, domínios, URLs e hashes." : "IPs, domains, URLs and hashes.", icon: Search },
        {
          path: "/phishing-analyzer",
          label: 'Phishing',
          description: pt ? "E-mails suspeitos, links e anexos." : "Suspicious emails, links and attachments.",
          icon: Mail,
        },
        { path: '/domain-monitoring', label: pt ? 'Monitoramento de domínios' : 'Domain monitoring', icon: Globe },
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
