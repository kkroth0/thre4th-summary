import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Index from "./pages/Index";
import VendorDirectory from "./pages/VendorDirectory";
import DnsblCheck from "./pages/DnsblCheck";
import Newsletter from "./pages/Newsletter";
import CveDashboard from "./pages/CveDashboard";
import PhishingAnalyzer from "./pages/PhishingAnalyzer";
import DnsVisualizer from "./pages/DnsVisualizer";
import Login from "./pages/Login";
import AuthCallback from "./pages/AuthCallback";
import NotFound from "./pages/NotFound";
import { LanguageProvider } from "./contexts/LanguageContext";
import { SidebarProvider } from "./contexts/SidebarContext";
import { AuthProvider } from "./contexts/AuthContext";
import { ProtectedRoute } from "./components/ProtectedRoute";

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

                {/* Authentication Routes */}
                <Route path="/login" element={<Login />} />
                <Route path="/auth/callback" element={<AuthCallback />} />

                {/* Public Routes */}
                <Route path="/vendors" element={<VendorDirectory />} />
                <Route path="/dnsbl" element={<DnsblCheck />} />
                <Route path="/newsletter" element={<Newsletter />} />
                <Route path="/phishing-analyzer" element={<PhishingAnalyzer />} />
                
                <Route path="*" element={<NotFound />} />
              </Routes>
            </BrowserRouter>
          </AuthProvider>
        </TooltipProvider>
      </SidebarProvider>
    </LanguageProvider>
  </QueryClientProvider>
);

export default App;
