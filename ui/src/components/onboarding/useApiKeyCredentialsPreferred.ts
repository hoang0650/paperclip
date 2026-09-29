import { useQuery } from "@tanstack/react-query";
import { healthApi } from "@/api/health";
import { queryKeys } from "@/lib/queryKeys";

/**
 * Hosted multi-tenant instances (authenticated, no local AI sign-in) cannot run a
 * provider subscription login for the user, so credential steps should open on
 * "enter your own API key". Users can still switch modes where a sign-in
 * environment exists.
 */
export function useApiKeyCredentialsPreferred(): boolean {
  const health = useQuery({ queryKey: queryKeys.health, queryFn: healthApi.get });
  return health.data?.deploymentMode === "authenticated" && health.data?.localAiLoginSupported !== true;
}
