"use client"

import { $api } from "@/lib/api"

export function useOrg() {
  const { data, isLoading, error } = $api.useQuery(
    "get",
    "/v1/me",
    {},
    { staleTime: 5 * 60 * 1000 } // 5 min — org membership rarely changes
  )

  // Use the first org membership (users typically belong to one org)
  const currentOrg = data?.orgs?.[0] ?? null

  return {
    orgSlug: currentOrg?.org_slug ?? null,
    orgName: currentOrg?.org_name ?? null,
    orgRole: currentOrg?.role ?? null,
    orgs: data?.orgs ?? [],
    userEmail: data?.email ?? null,
    userId: data?.id ?? null,
    isLoading,
    error,
    hasOrg: !!currentOrg,
  }
}
