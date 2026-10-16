import { lazy, Suspense } from "react";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
const DomainMonitoring = lazy(() => import('./pages/DomainMonitoring'));
import { LanguageProvider } from "./contexts/LanguageContext";
import { AuthProvider } from "./contexts/AuthContext";
import { PremiumRoute } from "./components/PremiumRoute";
import { Seo } from "./components/Seo";
import { WorkspaceShell } from "./components/WorkspaceShell";

const Home = lazy(() => import("./pages/Home"));
const Index = lazy(() => import("./pages/Index"));
const BulkEnrichment = lazy(() => import("./pages/BulkEnrichment"));
const Login = lazy(() => import("./pages/Login"));
const Profile = lazy(() => import("./pages/Profile"));
const Settings = lazy(() => import("./pages/Settings"));
const VendorDirectory = lazy(() => import("./pages/VendorDirectory"));
const AttackSurface = lazy(() => import("./pages/AttackSurface"));
const ExposureWatchlist = lazy(() => import("./pages/ExposureWatchlist"));
const Newsletter = lazy(() => import("./pages/Newsletter"));
const IntelligenceOverview = lazy(() => import("./pages/IntelligenceOverview"));
const MalwareCatalog = lazy(() => import("./pages/MalwareCatalog"));
const CveDashboard = lazy(() => import("./pages/CveDashboard"));
const Actors = lazy(() => import("./pages/Actors"));
const PhishingAnalyzer = lazy(() => import("./pages/PhishingAnalyzer"));
const DailyBulletin = lazy(() => import("./pages/ReportsPage"));
const Knowledge = lazy(() => import("./pages/Knowledge"));
const PatchTuesday = lazy(() => import("./pages/PatchTuesday"));
const SapPatch = lazy(() => import("./pages/SapPatch"));
const OtPatchDay = lazy(() => import("./pages/OtPatchDay"));
const Admin = lazy(() => import("./pages/Admin"));
const ThreatMap = lazy(() => import("./pages/ThreatMap"));
const NotFound = lazy(() => import("./pages/NotFound"));

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <LanguageProvider>
        <AuthProvider>
        <TooltipProvider>
          <Sonner />
          <BrowserRouter>
            <Seo />
            <WorkspaceShell>
            <Suspense fallback={
              <div role="status" className="min-h-screen w-full flex flex-col items-center justify-center bg-background gap-3">
                <div className="h-10 w-10 border-4 border-primary border-t-transparent rounded-full animate-spin"></div>
                <span className="text-xs font-semibold text-muted-foreground tracking-wider animate-pulse">Loading ThreatSumm4ry...</span>
              </div>
            }>
              <Routes>
                {/* Public Routes (CTI & CVE Dashboard) */}
                <Route path="/" element={<Home />} />
                <Route path="/analyzer" element={<Index />} />
                <Route path="/bulk" element={<BulkEnrichment />} />
                <Route path="/dashboard" element={<PremiumRoute feature="advisory-feed"><IntelligenceOverview /></PremiumRoute>} />
                <Route path="/malware" element={<MalwareCatalog />} />
                <Route path="/cves" element={<CveDashboard />} />
                <Route path="/atores" element={<Actors />} />
                <Route path="/actors" element={<Navigate to="/atores" replace />} />
                <Route path="/patch-tuesday" element={<PatchTuesday />} />
                <Route path="/sap-patch" element={<SapPatch />} />
                <Route path="/ot-patch-day" element={<OtPatchDay />} />
                <Route path="/ai-patch-day" element={<OtPatchDay domain="ai" />} />
                <Route path="/latam-threats" element={<Navigate to="/threat-map" replace />} />
                <Route path="/threat-map" element={<ThreatMap />} />

                {/* Tool Routes */}
                <Route path="/vendors" element={<VendorDirectory />} />
                <Route path="/attack-surface" element={<AttackSurface />} />
                <Route path="/exposure-watchlist" element={<ExposureWatchlist />} />
                <Route path="/phishing-analyzer" element={<PhishingAnalyzer />} />
                <Route path="/domain-monitoring" element={<DomainMonitoring />} />

                {/* Premium Routes (require premium allow-list) */}
                <Route path="/knowledge" element={<PremiumRoute feature="knowledge"><Knowledge /></PremiumRoute>} />
                <Route path="/relatorios" element={<PremiumRoute feature="threat-brief"><DailyBulletin /></PremiumRoute>} />
                <Route path="/reports" element={<Navigate to="/relatorios" replace />} />
                <Route path="/threat-brief" element={<Navigate to="/relatorios" replace />} />
                <Route path="/newsletter" element={<PremiumRoute feature="advisory-feed"><Newsletter /></PremiumRoute>} />
                <Route path="/daily-bulletin" element={<Navigate to="/relatorios" replace />} />

                {/* Auth */}
                <Route path="/login" element={<Login />} />
                <Route path="/cadastro" element={<Login />} />
                <Route path="/signup" element={<Navigate to="/cadastro" replace />} />
                <Route path="/profile" element={<Profile />} />
                <Route path="/settings" element={<Settings />} />
                <Route path="/admin" element={<Admin />} />

                <Route path="*" element={<NotFound />} />
              </Routes>
            </Suspense>
            </WorkspaceShell>
          </BrowserRouter>
        </TooltipProvider>
        </AuthProvider>
    </LanguageProvider>
  </QueryClientProvider>
);

export default App;
