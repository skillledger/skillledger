"use client"

import { useRef, useEffect, useState } from "react"
import gsap from "gsap"
import { CreditCard } from "lucide-react"
import { $api } from "@/lib/api"
import { fetchClient } from "@/lib/api-client"
import { useOrg } from "@/hooks/use-org"
import { UsageChart } from "@/components/charts/usage-chart"
import { EmptyState } from "@/components/dashboard/empty-state"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

function formatRelativeDate(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24))
  if (diffDays === 0) return "Today"
  if (diffDays === 1) return "Yesterday"
  if (diffDays < 30) return `${diffDays} days ago`
  if (diffDays < 365) return `${Math.floor(diffDays / 30)} months ago`
  return `${Math.floor(diffDays / 365)} years ago`
}

function getRoleBadgeVariant(role: string): "default" | "secondary" | "outline" {
  switch (role) {
    case "owner":
      return "default"
    case "admin":
      return "secondary"
    default:
      return "outline"
  }
}

export default function BillingPage() {
  const containerRef = useRef<HTMLDivElement>(null)
  const { orgSlug, isLoading: orgLoading } = useOrg()
  const [checkoutLoading, setCheckoutLoading] = useState(false)

  useEffect(() => {
    if (containerRef.current) {
      gsap.from(containerRef.current, {
        opacity: 0,
        y: 8,
        duration: 0.3,
        ease: "power2.out",
      })
    }
  }, [])

  const {
    data: usageData,
    isLoading: usageLoading,
    error: usageError,
  } = $api.useQuery("get", "/v1/usage")

  const {
    data: billingInfo,
    isLoading: billingLoading,
  } = $api.useQuery(
    "get",
    "/ee/v1/orgs/{slug}/billing",
    { params: { path: { slug: orgSlug! } } },
    { enabled: !!orgSlug }
  )

  const {
    data: members,
    isLoading: membersLoading,
  } = $api.useQuery(
    "get",
    "/ee/v1/orgs/{slug}/members",
    { params: { path: { slug: orgSlug! } } },
    { enabled: !!orgSlug }
  )

  const isLoading = usageLoading || orgLoading

  function getPlanDisplay(): { label: string; variant: "outline" | "default" | "secondary" } {
    if (billingInfo?.subscription_status) {
      return { label: "Enterprise", variant: "secondary" }
    }
    const status = usageData?.billing_status
    if (status === "active") {
      return { label: "Pay-as-you-go", variant: "default" }
    }
    return { label: "Free", variant: "outline" }
  }

  async function handleUpgrade() {
    setCheckoutLoading(true)
    try {
      const { data } = await fetchClient.POST("/v1/billing/checkout")
      if (data?.url) {
        window.location.href = data.url
      }
    } catch {
      // Checkout redirect failed silently — user stays on page
    } finally {
      setCheckoutLoading(false)
    }
  }

  if (!isLoading && usageError) {
    return (
      <div ref={containerRef} className="space-y-6">
        <h1 className="text-2xl font-semibold">Usage &amp; Billing</h1>
        <div
          role="alert"
          className="rounded-lg border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          Failed to load usage data. Please try again later.
        </div>
      </div>
    )
  }

  if (!isLoading && !usageData) {
    return (
      <div ref={containerRef} className="space-y-6">
        <h1 className="text-2xl font-semibold">Usage &amp; Billing</h1>
        <EmptyState
          icon={<CreditCard className="size-10" />}
          heading="No usage data yet"
          body="Start using SkillLedger to see your usage statistics."
        />
      </div>
    )
  }

  const plan = getPlanDisplay()
  const currentMonth = new Date().toLocaleString("default", { month: "long" })
  const usageChartData = usageData
    ? [{ month: currentMonth, count: usageData.used }]
    : []
  const usedCount = usageData?.used ?? 0
  const limitCount = usageData?.limit
  const progressValue = limitCount ? (usedCount / limitCount) * 100 : 0
  const resetsAt = usageData?.resets_at
    ? new Date(usageData.resets_at).toLocaleDateString("default", {
        month: "long",
        day: "numeric",
        year: "numeric",
      })
    : null

  return (
    <div ref={containerRef} className="space-y-6">
      <h1 className="text-2xl font-semibold">Usage &amp; Billing</h1>

      {/* Loading state */}
      {isLoading ? (
        <>
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-[380px] w-full" />
          <Skeleton className="h-48 w-full" />
        </>
      ) : (
        <>
          {/* Section 1: Plan Status Card */}
          <Card>
            <CardContent className="flex items-center justify-between py-4">
              <div>
                <p className="text-xs text-muted-foreground">Current Plan</p>
                <div className="mt-1 flex items-center gap-2">
                  <span className="text-lg font-semibold">{plan.label}</span>
                  <Badge
                    variant={plan.variant}
                    className={
                      plan.label === "Pay-as-you-go"
                        ? "bg-green-500/10 text-green-500 border-green-500/20"
                        : plan.label === "Enterprise"
                          ? "bg-blue-500/10 text-blue-500 border-blue-500/20"
                          : undefined
                    }
                  >
                    {plan.label}
                  </Badge>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Section 2: Usage Chart */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg font-semibold">Monthly Usage</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <UsageChart data={usageChartData} isLoading={false} />

              {limitCount !== null && limitCount !== undefined ? (
                <div className="space-y-2">
                  <Progress value={progressValue}>
                    <span className="text-sm text-muted-foreground">
                      {usedCount} / {limitCount} operations this month
                    </span>
                  </Progress>
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">
                  {usedCount} / Unlimited operations this month
                </p>
              )}

              {resetsAt && (
                <p className="text-xs text-muted-foreground">
                  Resets on {resetsAt}
                </p>
              )}
            </CardContent>
          </Card>

          {/* Section 3: Seat Management Table (Enterprise only) */}
          {billingInfo && (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg font-semibold">Seats</CardTitle>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline">{billingInfo.seat_count} seats</Badge>
                    {billingInfo.out_of_sync && (
                      <Badge variant="destructive">Out of Sync</Badge>
                    )}
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {membersLoading ? (
                  <div className="space-y-3">
                    <Skeleton className="h-10 w-full" />
                    <Skeleton className="h-10 w-full" />
                    <Skeleton className="h-10 w-full" />
                  </div>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Email</TableHead>
                        <TableHead>Role</TableHead>
                        <TableHead>Joined</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {(members as Array<{ user_id: number; email: string; role: string; joined_at: string }>)?.map(
                        (member) => (
                          <TableRow key={member.user_id}>
                            <TableCell className="text-sm">
                              {member.email}
                            </TableCell>
                            <TableCell>
                              <Badge variant={getRoleBadgeVariant(member.role)}>
                                {member.role}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-sm text-muted-foreground">
                              {formatRelativeDate(member.joined_at)}
                            </TableCell>
                          </TableRow>
                        )
                      )}
                    </TableBody>
                  </Table>
                )}

                {billingInfo.portal_url && (
                  <Button
                    variant="secondary"
                    onClick={() => {
                      window.location.href = billingInfo.portal_url!
                    }}
                  >
                    Manage Seats
                  </Button>
                )}
              </CardContent>
            </Card>
          )}

          {/* Section 4: Action Buttons */}
          <div className="flex items-center gap-3">
            {billingInfo?.portal_url && (
              <Button
                variant="default"
                onClick={() => {
                  window.location.href = billingInfo.portal_url!
                }}
              >
                Manage Billing
              </Button>
            )}
            {usageData?.billing_status === "free" && (
              <Button
                variant="default"
                disabled={checkoutLoading}
                onClick={handleUpgrade}
              >
                {checkoutLoading ? "Redirecting..." : "Upgrade Plan"}
              </Button>
            )}
          </div>
        </>
      )}
    </div>
  )
}
