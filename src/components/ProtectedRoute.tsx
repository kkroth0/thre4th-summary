import React from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "@/contexts/AuthContext";
import { Loader2 } from "lucide-react";

interface ProtectedRouteProps {
  children: React.ReactNode;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center space-y-4">
        <div className="relative flex items-center justify-center">
          {/* Glowing pulse rings */}
          <div className="absolute w-16 h-16 rounded-full border border-primary/20 animate-ping opacity-70" />
          <div className="absolute w-24 h-24 rounded-full border border-primary/10 animate-pulse opacity-40" />
          {/* Main spinner */}
          <Loader2 className="h-10 w-10 text-primary animate-spin" />
        </div>
        <p className="text-muted-foreground text-sm font-semibold tracking-wider uppercase animate-pulse">
          Autenticando sessão...
        </p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to={`/login?redirect=${encodeURIComponent(location.pathname)}`} replace />;
  }

  return <>{children}</>;
};
