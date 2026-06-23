import { lazy, Suspense } from "react";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { LanguageProvider } from "./contexts/LanguageContext";
import { SidebarProvider } from "./contexts/SidebarContext";

const Index = lazy(() => import("./pages/Index"));
const VendorDirectory = lazy(() => import("./pages/VendorDirectory"));
const DnsblCheck = lazy(() => import("./pages/DnsblCheck"));
const Newsletter = lazy(() => import("./pages/Newsletter"));
const CveDashboard = lazy(() => import("./pages/CveDashboard"));
const PhishingAnalyzer = lazy(() => import("./pages/PhishingAnalyzer"));
const ThreatHunting = lazy(() => import("./pages/ThreatHunting"));
const DailyBulletin = lazy(() => import("./pages/DailyBulletin"));
const DnsVisualizer = lazy(() => import("./pages/DnsVisualizer"));
const PatchTuesday = lazy(() => import("./pages/PatchTuesday"));
const Features = lazy(() => import("./pages/Features"));
const NotFound = lazy(() => import("./pages/NotFound"));

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <LanguageProvider>
      <SidebarProvider>
        <TooltipProvider>
          <Toaster />
          <Sonner />
          <BrowserRouter>
            <Suspense fallback={
              <div className="h-screen w-screen flex flex-col items-center justify-center bg-background gap-3">
                <div className="h-10 w-10 border-4 border-primary border-t-transparent rounded-full animate-spin"></div>
                <span className="text-xs font-semibold text-muted-foreground tracking-wider animate-pulse">Loading ThreatSumm4ry...</span>
              </div>
            }>
              <Routes>
                {/* Public Routes (CTI & CVE Dashboard) */}
                <Route path="/" element={<Index />} />
                <Route path="/cves" element={<CveDashboard />} />
                <Route path="/dns-visualizer" element={<DnsVisualizer />} />
                <Route path="/patch-tuesday" element={<PatchTuesday />} />
                <Route path="/features" element={<Features />} />

                {/* Tool Routes */}
                <Route path="/vendors" element={<VendorDirectory />} />
                <Route path="/dnsbl" element={<DnsblCheck />} />
                <Route path="/newsletter" element={<Newsletter />} />
                <Route path="/phishing-analyzer" element={<PhishingAnalyzer />} />
                <Route path="/threat-hunting" element={<ThreatHunting />} />
                <Route path="/daily-bulletin" element={<DailyBulletin />} />

                <Route path="*" element={<NotFound />} />
              </Routes>
            </Suspense>
          </BrowserRouter>
        </TooltipProvider>
      </SidebarProvider>
    </LanguageProvider>
  </QueryClientProvider>
);

export default App;
