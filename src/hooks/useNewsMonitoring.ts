import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@/contexts/AuthContext";
import { fetchNewsMonitoring, saveNewsMonitoring, type NewsMonitoringPreferences } from "@/services/threatApi";

export function useNewsMonitoring() {
  const { auth } = useAuth();
  const client = useQueryClient();
  const queryKey = ["news-monitoring", auth.login ?? ""];
  const query = useQuery({ queryKey, queryFn: fetchNewsMonitoring, enabled: auth.authenticated, staleTime: 0 });
  const save = async (preferences: Pick<NewsMonitoringPreferences, "mode" | "vendorIds">) => {
    const result = await saveNewsMonitoring(preferences);
    client.setQueryData(queryKey, { vendors: query.data?.vendors ?? [], preferences: result.preferences });
    return result.preferences;
  };
  return { ...query, save };
}
