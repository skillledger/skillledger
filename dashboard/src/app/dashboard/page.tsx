"use client"

import { useRef, useEffect, useMemo } from "react"
import { useOrg } from "@/hooks/use-org"
import { $api } from "@/lib/api"
import { StatCard } from "@/components/dashboard/stat-card"
import { ViolationTrendChart } from "@/components/charts/violation-trend"
import { EmptyState } from "@/components/dashboard/empty-state"
import { Skeleton } from "@/components/ui/skeleton"
import { Button } from "@/components/ui/button"
import { AlertTriangle, ShieldCheck } from "lucide-react"
import gsap from "gsap"

function getThirtyDaysAgo(): string {
  const d = new Date()
  d.setDate(d.getDate() - 30)
  return d.toISOString()
}

function getWeekAgo(): Date {
  const d = new Date()
  d.setDate(d.getDate() - 7)
  return d
}

function getTwoWeeksAgo(): Date {
  const d = new Date()
  d.setDate(d.getDate() - 14)
  return d
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

export default function DashboardPage() {
  const containerRef = useRef<HTMLDivElement>(null)
  const cardsRef = useRef<HTMLDivElement>(null)
  const { orgSlug, isLoading: orgLoading, hasOrg } = useOrg()

  const { data, isLoading, error, refetch } = $api.useQuery(
    "get",
    "/ee/v1/orgs/{slug}/events",
    {
      params: {
        path: { slug: orgSlug! },
        query: { limit: 200, since: getThirtyDaysAgo() },
      },
    },
    { staleTime: 30_000, enabled: !!orgSlug }
  )

  const events = (data ?? []) as EventItem[]

  const stats = useMemo(() => {
    const weekAgo = getWeekAgo()
    const twoWeeksAgo = getTwoWeeksAgo()

    const verifiedSkills = new Set(
      events
        .filter((e) => e.event_type === "verify_pass")
        .map((e) => e.skill_id)
    ).size

    const verifiedThisWeek = new Set(
      events
        .filter(
          (e) =>
            e.event_type === "verify_pass" &&
            new Date(e.event_timestamp) >= weekAgo
        )
        .map((e) => e.skill_id)
    ).size

    const verifiedPrevWeek = new Set(
      events
        .filter(
          (e) =>
            e.event_type === "verify_pass" &&
            new Date(e.event_timestamp) >= twoWeeksAgo &&
            new Date(e.event_timestamp) < weekAgo
        )
        .map((e) => e.skill_id)
    ).size

    const violations = events.filter(
      (e) =>
        e.event_type.includes("violation") ||
        ["critical", "high", "medium", "low"].includes(e.severity)
    )

    const violationsThisWeek = violations.filter(
      (e) => new Date(e.event_timestamp) >= weekAgo
    ).length
    const violationsPrevWeek = violations.filter(
      (e) =>
        new Date(e.event_timestamp) >= twoWeeksAgo &&
        new Date(e.event_timestamp) < weekAgo
    ).length

    const iocMatches = events.filter((e) => e.event_type.includes("ioc"))
    const iocThisWeek = iocMatches.filter(
      (e) => new Date(e.event_timestamp) >= weekAgo
    ).length
    const iocPrevWeek = iocMatches.filter(
      (e) =>
        new Date(e.event_timestamp) >= twoWeeksAgo &&
        new Date(e.event_timestamp) < weekAgo
    ).length

    const activePolicies = events.length > 0 ? 1 : 0

    return {
      verifiedSkills,
      verifiedTrend: verifiedThisWeek - verifiedPrevWeek,
      violations: violations.length,
      violationsTrend: violationsThisWeek - violationsPrevWeek,
      iocMatches: iocMatches.length,
      iocTrend: iocThisWeek - iocPrevWeek,
      activePolicies,
    }
  }, [events])

  const trendData = useMemo(() => {
    const byDate: Record<string, number> = {}
    const now = new Date()
    for (let i = 29; i >= 0; i--) {
      const d = new Date(now)
      d.setDate(d.getDate() - i)
      const key = d.toISOString().slice(0, 10)
      byDate[key] = 0
    }

    events
      .filter(
        (e) =>
          e.event_type.includes("violation") ||
          ["critical", "high", "medium", "low"].includes(e.severity)
      )
      .forEach((e) => {
        const key = new Date(e.event_timestamp).toISOString().slice(0, 10)
        if (key in byDate) {
          byDate[key]++
        }
      })

    return Object.entries(byDate).map(([date, violations]) => ({
      date,
      violations,
    }))
  }, [events])

  // GSAP animations
  useEffect(() => {
    if (isLoading || orgLoading) return
    if (!containerRef.current) return

    gsap.from(containerRef.current, {
      opacity: 0,
      y: 8,
      duration: 0.3,
      ease: "power2.out",
    })

    if (cardsRef.current && cardsRef.current.children.length > 0) {
      gsap.from(cardsRef.current.children, {
        opacity: 0,
        y: 16,
        stagger: 0.08,
        duration: 0.4,
        ease: "power2.out",
      })
    }
  }, [isLoading, orgLoading])

  if (orgLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-48" />
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-[104px] w-full" />
          ))}
        </div>
        <Skeleton className="h-[300px] w-full" />
      </div>
    )
  }

  if (!hasOrg) {
    return (
      <EmptyState
        icon={<ShieldCheck className="h-12 w-12" />}
        heading="No organization"
        body="You are not a member of any organization. Ask an admin to invite you, or create a new organization."
      />
    )
  }

  if (error) {
    return (
      <div className="rounded-lg border border-destructive/50 bg-destructive/5 p-6 text-center">
        <AlertTriangle className="mx-auto h-8 w-8 text-destructive mb-3" />
        <p className="text-sm text-destructive font-medium">
          Failed to load posture data. Check your connection and try again.
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

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-48" />
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-[104px] w-full" />
          ))}
        </div>
        <Skeleton className="h-[300px] w-full" />
      </div>
    )
  }

  if (events.length === 0) {
    return (
      <div ref={containerRef}>
        <h1 className="text-2xl font-semibold mb-6">Security Posture</h1>
        <EmptyState
          icon={<ShieldCheck className="h-12 w-12" />}
          heading="No security data yet"
          body="Connect your first CLI to start reporting security events. Run `skillledger login` to get started."
        />
      </div>
    )
  }

  return (
    <div ref={containerRef}>
      <h1 className="text-2xl font-semibold mb-6">Security Posture</h1>

      <div
        ref={cardsRef}
        className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4"
      >
        <StatCard
          label="Verified Skills"
          value={stats.verifiedSkills}
          trend={{ value: stats.verifiedTrend, label: "this week" }}
        />
        <StatCard
          label="Policy Violations"
          value={stats.violations}
          trend={{ value: stats.violationsTrend, label: "this week" }}
        />
        <StatCard
          label="IOC Matches"
          value={stats.iocMatches}
          trend={{ value: stats.iocTrend, label: "this week" }}
        />
        <StatCard
          label="Active Policies"
          value={stats.activePolicies}
        />
      </div>

      <div className="mt-12">
        <h2 className="text-lg font-semibold mb-4">
          Violations (Last 30 Days)
        </h2>
        <ViolationTrendChart data={trendData} isLoading={false} />
      </div>
    </div>
  )
}
