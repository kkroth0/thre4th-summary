"import { Link, useLocation } from "react-router-dom";
import { BookOpen, Shield, Mail, Activity, Terminal } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/ThemeToggle";
import { LanguageToggle } from "@/components/LanguageToggle";
import { useLanguage } from "@/contexts/LanguageContext";
import { cn } from "@/lib/utils";

interface HeaderProps {
  actions?: React.ReactNode;
  onLogoClick?: () => void;
}

export function Header({ actions, onLogoClick }: HeaderProps) {
  const { t } = useLanguage();
  const location = useLocation();
  const pathname = location.pathname;

  const handleLogoClick = (e: React.MouseEvent) => {
    if (onLogoClick) {
      e.preventDefault();
      onLogoClick();
    }
  };

  const navItems = [
    { path: "/", label: t("appName"), icon: Activity, isHome: true },
    { path: "/vendors", label: t("vendors"), icon: BookOpen },
    { path: "/dnsbl", label: t("dnsblCheck"), icon: Shield },
    { path: "/newsletter", label: t("newsletter"), icon: Mail },
  ];

  return (
    <header className="sticky top-0 z-50 w-full border-b border-border/40 bg-background/60  supports-[backdrop-filter]:bg-background/40">
      <div className="container max-w-7xl mx-auto flex h-16 items-center justify-between px-4">
        {/* Brand Logo */}
        <div className="flex items-center gap-2 md:gap-6">
          <Link
            to="/"
            onClick={handleLogoClick}
            className="flex items-center gap-2 mr-2 md:mr-6"
          >
            <Terminal className="h-5 w-5 text-primary animate-pulse" />
            <span className="font-bold tracking-tight text-xl bg-gradient-to-r from-primary via-primary/80 to-primary/50 bg-clip-text text-transparent hover:opacity-95 transition-all">
              {t("appName")}
            </span>
          </Link>

          {/* Center Navigation Links (Desktop) */}
          <nav clas
<truncated 2894 bytes>