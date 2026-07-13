import { Navigate } from "react-router-dom";

export default function ExposureWatchlist() {
  return <Navigate to="/attack-surface?mode=monitor" replace />;
}
