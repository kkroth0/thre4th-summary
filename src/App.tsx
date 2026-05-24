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
import NotFound from "./pages/NotFound";
import { LanguageProvider } from "./contexts/LanguageContext";
import { SidebarProvider } from "./contexts/SidebarContext";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <LanguageProvider>
      <SidebarProvider>
        <TooltipProvider>
          <Toaster />
          <Sonner />
          <BrowserRouter>
            <Routes>
              <Route path="/" element={<Index />} />
              <Route path="/vendors" element={<VendorDirectory />} />
              <Route path="/dnsbl" element={<DnsblCheck />} />
              <Route path="/newsletter" element={<Newsletter />} />
              <Route path="/cves" element={<CveDashboard />} />
              <Route path="/phishing-analyzer" element={<PhishingAnalyzer />} />
              {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
              <Route path="*" element={<NotFound />} />
            </Routes>
          </BrowserRouter>
        </TooltipProvider>
      </SidebarProvider>
    </LanguageProvider>
  </QueryClientProvider>
);

export default App;
