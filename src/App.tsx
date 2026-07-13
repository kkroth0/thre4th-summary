import { lazy, Suspense } from "react";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { LanguageProvider } from "./contexts/LanguageContext";
import { SidebarProvider } from "./contexts/SidebarContext";
import { AuthProvider } from "./contexts/AuthContext";
import { PremiumRoute } from "./components/PremiumRoute";
import { Seo } from "./components/Seo";

const Index = lazy(() => import("./pages/Index"));
const Login = lazy(() => import("./pages/Login"));
const Profile = lazy(() => import("./pages/Profile"));
const Settings = lazy(() => import("./pages/Settings"));
const VendorDirectory = lazy(() => import("./pages/VendorDirectory"));
const DnsblCheck = lazy(() => import("./pages/DnsblCheck"));
const AttackSurface = lazy(() => import("./pages/AttackSurface"));
const ExposureWatchlist = lazy(() => import("./pages/ExposureWatchlist"));
const Newsletter = lazy(() => import("./pages/Newsletter"));
const CveDashboard = lazy(() => import("./pages/CveDashboard"));
const Actors = lazy(() => import("./pages/Actors"));
const PhishingAnalyzer = lazy(() => import("./pages/PhishingAnalyzer"));
const ThreatHunting = lazy(() => import("./pages/ThreatHunting"));
const DailyBulletin = lazy(() => import("./pages/DailyBulletin"));
const PatchTuesday = lazy(() => import("./pages/PatchTuesday"));
const Advisories = lazy(() => import("./pages/Advisories"));
const AdvisoryPost = lazy(() => import("./pages/AdvisoryPost"));
const Admin = lazy(() => import("./pages/Admin"));
const LatamThreats = lazy(() => import("./pages/LatamThreats"));
const ThreatMap = lazy(() => import("./pages/ThreatMap"));
const NotFound = lazy(() => import("./pages/NotFound"));

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <LanguageProvider>
      <SidebarProvider>
        <AuthProvider>
        <TooltipProvider>
          <Toaster />
          <Sonner />
          <BrowserRouter>
            <Seo />
            <Suspense fallback={
              <div className="h-screen w-screen flex flex-col items-center justify-center bg-background gap-3">
                <div className="h-10 w-10 border-4 border-primary border-t-transparent rounded-full animate-spin"></div>
                <span className="text-xs font-semibold text-muted-foreground tracking-wider animate-pulse">Loading ThreatSumm4ry...</span>
              </div>
            }>
              <Routes>
                {/* Public Routes (CTI & CVE Dashboard) */}
                <Route path="/" element={<Index />} />
                <Route path="/analyzer" element={<Index />} />
                <Route path="/cves" element={<CveDashboard />} />
                <Route path="/atores" element={<Actors />} />
                <Route path="/actors" element={<Navigate to="/atores" replace />} />
                <Route path="/patch-tuesday" element={<PatchTuesday />} />
                <Route path="/advisories" element={<Advisories />} />
                <Route path="/advisories/:slug" element={<AdvisoryPost />} />
                <Route path="/latam-threats" element={<LatamThreats />} />
                <Route path="/threat-map" element={<ThreatMap />} />

                {/* Tool Routes */}
                <Route path="/vendors" element={<VendorDirectory />} />
                <Route path="/dnsbl" element={<DnsblCheck />} />
                <Route path="/attack-surface" element={<AttackSurface />} />
                <Route path="/exposure-watchlist" element={<ExposureWatchlist />} />
                <Route path="/phishing-analyzer" element={<PhishingAnalyzer />} />

                {/* Premium Routes (require premium allow-list) */}
                <Route path="/relatorios" element={<PremiumRoute feature="threat-brief"><DailyBulletin /></PremiumRoute>} />
                <Route path="/reports" element={<Navigate to="/relatorios" replace />} />
                <Route path="/threat-brief" element={<Navigate to="/relatorios" replace />} />
                <Route path="/newsletter" element={<PremiumRoute feature="advisory-feed"><Newsletter /></PremiumRoute>} />
                <Route path="/threat-hunting" element={<PremiumRoute feature="threat-hunting"><ThreatHunting /></PremiumRoute>} />
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
          </BrowserRouter>
        </TooltipProvider>
        </AuthProvider>
      </SidebarProvider>
    </LanguageProvider>
  </QueryClientProvider>
);

export default App;
