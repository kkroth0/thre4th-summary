import { lazy, Suspense } from "react";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { LanguageProvider } from "./contexts/LanguageContext";
import { SidebarProvider } from "./contexts/SidebarContext";
import { AuthProvider } from "./contexts/AuthContext";
import { ProtectedRoute } from "./components/ProtectedRoute";

const Index = lazy(() => import("./pages/Index"));
const VendorDirectory = lazy(() => import("./pages/VendorDirectory"));
const DnsblCheck = lazy(() => import("./pages/DnsblCheck"));
const Newsletter = lazy(() => import("./pages/Newsletter"));
const CveDashboard = lazy(() => import("./pages/CveDashboard"));
const PhishingAnalyzer = lazy(() => import("./pages/PhishingAnalyzer"));
const DnsVisualizer = lazy(() => import("./pages/DnsVisualizer"));
const Features = lazy(() => import("./pages/Features"));
const Login = lazy(() => import("./pages/Login"));
const AuthCallback = lazy(() => import("./pages/AuthCallback"));
const NotFound = lazy(() => import("./pages/NotFound"));

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <LanguageProvider>
      <SidebarProvider>
        <TooltipProvider>
          <Toaster />
          <Sonner />
          <AuthProvider>
            <BrowserRouter>
              <Suspense fallback={
                <div className="h-screen w-screen flex flex-col items-center justify-center bg-background gap-3">
                  <div className="h-10 w-10 border-4 border-primary border-t-transparent rounded-full animate-spin"></div>
                  <span className="text-xs font-semibold text-muted-foreground tracking-wider animate-pulse">Loading ThreatSumm4ry...</span>
                </div>
              }>
                <Routes>
                  {/* Protected Routes (CTI & CVE Dashboard) */}
                  <Route 
                    path="/" 
                    element={
                      <ProtectedRoute>
                        <Index />
                      </ProtectedRoute>
                    } 
                  />
                  <Route 
                    path="/cves" 
                    element={
                      <ProtectedRoute>
                        <CveDashboard />
                      </ProtectedRoute>
                    } 
                  />
                  <Route 
                    path="/dns-visualizer" 
                    element={
                      <ProtectedRoute>
                        <DnsVisualizer />
                      </ProtectedRoute>
                    } 
                  />
                  <Route 
                    path="/features" 
                    element={
                      <ProtectedRoute>
                        <Features />
                      </ProtectedRoute>
                    } 
                  />

                  {/* Authentication Routes */}
                  <Route path="/login" element={<Login />} />
                  <Route path="/auth/callback" element={<AuthCallback />} />

                  {/* Authenticated Tool Routes */}
                  <Route path="/vendors" element={<ProtectedRoute><VendorDirectory /></ProtectedRoute>} />
                  <Route path="/dnsbl" element={<ProtectedRoute><DnsblCheck /></ProtectedRoute>} />
                  <Route path="/newsletter" element={<ProtectedRoute><Newsletter /></ProtectedRoute>} />
                  <Route path="/phishing-analyzer" element={<ProtectedRoute><PhishingAnalyzer /></ProtectedRoute>} />
                  
                  <Route path="*" element={<NotFound />} />
                </Routes>
              </Suspense>
            </BrowserRouter>
          </AuthProvider>
        </TooltipProvider>
      </SidebarProvider>
    </LanguageProvider>
  </QueryClientProvider>
);

export default App;
