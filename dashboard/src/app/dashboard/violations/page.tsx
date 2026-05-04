"use client"

import { useState, useRef, useEffect, useMemo } from "react"
import { useRouter } from "next/navigation"
import { useOrg } from "@/hooks/use-org"
import { $api } from "@/lib/api"
import { ViolationTable } from "@/components/dashboard/violation-table"
import { FilterBar } from "@/components/dashboard/filter-bar"
import { EmptyState } from "@/components/dashboard/empty-state"
import { Skeleton } from "@/components/ui/skeleton"
import { Button } from "@/components/ui/button"
import { AlertTriangle, ShieldAlert } from "lucide-react"
import gsap from "gsap"

const PAGE_SIZE = 25

function timeRangeToDate(range: string): Date | undefined {
  switch (range) {
    case "24h":
      return new Date(Date.now() - 24 * 60 * 60 * 1000)
    case "7d":
      return new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
    case "30d":
      return new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
    default:
      return undefined
  }
}

interface EventItem {
  id: number
  event_type: string
  ecosystem: string
  skill_id: string
  rule: string
  severity: string
  details: object | null
  event_timestamp: string
  created_at: string
}

export default function ViolationsPage() {
  const containerRef = useRef<HTMLDivElement>(null)
  const router = useRouter()
  const { orgSlug, isLoading: orgLoading, hasOrg } = useOrg()

  const [ecosystem, setEcosystem] = useState("all")
  const [severity, setSeverity] = useState("all")
  const [timeRange, setTimeRange] = useState("30d")
  const [page, setPage] = useState(0)

  const sinceDate = timeRangeToDate(timeRange)

  const { data, isLoading, error, refetch } = $api.useQuery(
    "get",
    "/ee/v1/orgs/{slug}/events",
    {
      params: {
        path: { slug: orgSlug! },
        query: {
          limit: 200,
          offset: 0,
          ...(sinceDate && { since: sinceDate.toISOString() }),
        },
      },
    },
    { staleTime: 30_000, enabled: !!orgSlug }
  )

  const events = (data ?? []) as EventItem[]

  const filtered = useMemo(() => {
    return events
      .filter((ev) => ecosystem === "all" || ev.ecosystem === ecosystem)
      .filter((ev) => severity === "all" || ev.severity === severity)
  }, [events, ecosystem, severity])

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const paginatedEvents = filtered.slice(
    page * PAGE_SIZE,
    (page + 1) * PAGE_SIZE
  )

  const showStart = filtered.length === 0 ? 0 : page * PAGE_SIZE + 1
  const showEnd = Math.min((page + 1) * PAGE_SIZE, filtered.length)

  const hasActiveFilters =
    ecosystem !== "all" || severity !== "all" || timeRange !== "30d"

  function handleClearAll() {
    setEcosystem("all")
    setSeverity("all")
    setTimeRange("30d")
    setPage(0)
  }

  function handleRowClick(skillId: string) {
    router.push(`/dashboard/skills/${skillId}`)
  }

  // Reset page when filters change
  useEffect(() => {
    setPage(0)
  }, [ecosystem, severity, timeRange])

  // GSAP page animation
  useEffect(() => {
    if (isLoading || orgLoading) return
    if (!containerRef.current) return

    gsap.from(containerRef.current, {
      opacity: 0,
      y: 8,
      duration: 0.3,
      ease: "power2.out",
    })
  }, [isLoading, orgLoading])

  if (orgLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-40" />
        <div className="flex items-center gap-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-9 w-[120px]" />
          ))}
        </div>
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      </div>
    )
  }

  if (!hasOrg) {
    return (
      <EmptyState
        icon={<ShieldAlert className="h-12 w-12" />}
        heading="No organization"
        body="You are not a member of any organization. Ask an admin to invite you."
      />
    )
  }

  if (error) {
    return (
      <div className="rounded-lg border border-destructive/50 bg-destructive/5 p-6 text-center">
        <AlertTriangle className="mx-auto h-8 w-8 text-destructive mb-3" />
        <p className="text-sm text-destructive font-medium">
          Failed to load violations. Check your connection and try again.
        </p>
        <Button
          variant="outline"
          size="sm"
          className="mt-4"
          onClick={() => refetch()}
        >
          Retry
        </Button>
      </div>
    )
  }

  return (
    <div ref={containerRef}>
      <h1 className="text-2xl font-semibold mb-6">Violations</h1>

      <div className="mb-6">
        <FilterBar
          ecosystem={ecosystem}
          severity={severity}
          timeRange={timeRange}
          onEcosystemChange={setEcosystem}
          onSeverityChange={setSeverity}
          onTimeRangeChange={setTimeRange}
          onClearAll={handleClearAll}
          hasActiveFilters={hasActiveFilters}
        />
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : events.length === 0 ? (
        <EmptyState
          icon={<ShieldAlert className="h-12 w-12" />}
          heading="No violations found"
          body="Your organization has no recorded violations. Events will appear here as CLIs report them."
        />
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={<ShieldAlert className="h-12 w-12" />}
          heading="No violations found"
          body="No violations match the current filters."
          action={
            <Button variant="ghost" size="sm" onClick={handleClearAll}>
              Clear filters
            </Button>
          }
        />
      ) : (
        <>
          <div className="overflow-x-auto">
            <div className="min-w-[640px]">
              <ViolationTable
                events={paginatedEvents}
                isLoading={false}
                onRowClick={handleRowClick}
              />
            </div>
          </div>

          <div className="flex items-center justify-between mt-4">
            <p className="text-sm text-muted-foreground">
              Showing {showStart}-{showEnd} of {filtered.length}
            </p>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={page === 0}
                onClick={() => setPage((p) => p - 1)}
              >
                Previous
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={page >= totalPages - 1}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
