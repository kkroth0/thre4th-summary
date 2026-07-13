import { Loader2 } from "lucide-react";
import { Navigate } from "react-router-dom";
import { ApiKeysSettings } from "@/components/settings/ApiKeysSettings";
import { Card, CardContent } from "@/components/ui/card";
import { PageLayout } from "@/components/PageLayout";
import { useAuth } from "@/contexts/AuthContext";
import { useLanguage } from "@/contexts/LanguageContext";

export default function Settings() {
  const { language } = useLanguage();
  const { auth, loading } = useAuth();
  const pt = language === "pt";

  if (loading) {
    return (
      <PageLayout width="max-w-3xl">
        <Card><CardContent className="flex items-center gap-2 p-6 text-muted-foreground"><Loader2 className="animate-spin" /> {pt ? "Verificando sessão…" : "Checking session…"}</CardContent></Card>
      </PageLayout>
    );
  }

  if (!auth.authenticated) return <Navigate to="/login" replace />;

  return (
    <PageLayout width="max-w-3xl">
      <ApiKeysSettings />
    </PageLayout>
  );
}
