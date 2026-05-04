"use client"

import { useMemo, useRef, useEffect } from "react"
import { useParams } from "next/navigation"
import Link from "next/link"
import gsap from "gsap"
import { ArrowLeft, Package } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"
import { Skeleton } from "@/components/ui/skeleton"
import { ProvenanceStepper } from "@/components/dashboard/provenance-stepper"
import { StatusBadge } from "@/components/dashboard/status-badge"
import { ViolationTable } from "@/components/dashboard/violation-table"
import { SeverityBadge } from "@/components/dashboard/severity-badge"
import { EmptyState } from "@/components/dashboard/empty-state"
import { useOrg } from "@/hooks/use-org"
import { $api } from "@/lib/api"

function deriveVerificationStatus(
  events: Array<{ event_type: string }>
): "verified" | "unverified" | "failed" {
  const types = events.map((e) => e.event_type)
  if (types.some((t) => t.includes("verify_fail"))) return "failed"
  if (types.some((t) => t.includes("verify_pass"))) return "verified"
  return "unverified"
}

function buildProvenanceSteps(
  events: Array<{
    event_type: string
    event_timestamp: string
    details?: Record<string, unknown>
  }>
) {
  const findEvent = (keyword: string) =>
    events.find((e) => e.event_type.includes(keyword))

  const buildEv = findEvent("build")
  const signEv = findEvent("sign")
  const publishEv = findEvent("publish")
  const verifyEv = findEvent("verify")

  return [
    {
      label: "Build",
      status: buildEv ? ("complete" as const) : ("pending" as const),
      timestamp: buildEv?.event_timestamp,
      detail: (buildEv?.details as Record<string, string> | undefined)
        ?.content_address,
    },
    {
      label: "Sign",
      status: signEv ? ("complete" as const) : ("pending" as const),
      timestamp: signEv?.event_timestamp,
      detail: (signEv?.details as Record<string, string> | undefined)?.signer,
    },
    {
      label: "Publish",
      status: publishEv ? ("complete" as const) : ("pending" as const),
      timestamp: publishEv?.event_timestamp,
      detail: (publishEv?.details as Record<string, string> | undefined)
        ?.tlog_index
        ? `tlog index: ${(publishEv?.details as Record<string, string>).tlog_index}`
        : undefined,
    },
    {
      label: "Verify",
      status: verifyEv
        ? verifyEv.event_type.includes("fail")
          ? ("failed" as const)
          : ("complete" as const)
        : ("pending" as const),
      timestamp: verifyEv?.event_timestamp,
      detail: (verifyEv?.details as Record<string, string> | undefined)
        ?.policy_result,
    },
  ]
}

export default function SkillDetailPage() {
  const params = useParams<{ id: string }>()
  const skillId = decodeURIComponent(params.id)
  const { orgSlug } = useOrg()
  const pageRef = useRef<HTMLDivElement>(null)

  const { data: events, isLoading } = $api.useQuery(
    "get",
    "/ee/v1/orgs/{slug}/events",
    { params: { path: { slug: orgSlug! }, query: { limit: 200 } } },
    { staleTime: 30_000, enabled: !!orgSlug }
  )

  const skillEvents = useMemo(
    () => (events ?? []).filter((ev) => ev.skill_id === skillId),
    [events, skillId]
  )

  const verificationStatus = useMemo(
    () => deriveVerificationStatus(skillEvents),
    [skillEvents]
  )

  const provenanceSteps = useMemo(
    () => buildProvenanceSteps(skillEvents),
    [skillEvents]
  )

  const policyRules = useMemo(() => {
    const ruleMap = new Map<string, string>()
    for (const ev of skillEvents) {
      if (ev.rule && !ruleMap.has(ev.rule)) {
        ruleMap.set(ev.rule, ev.severity)
      }
    }
    return Array.from(ruleMap.entries()).map(([rule, severity]) => ({
      rule,
      severity,
    }))
  }, [skillEvents])

  useEffect(() => {
    if (pageRef.current) {
      gsap.fromTo(
        pageRef.current,
        { opacity: 0, y: 12 },
        { opacity: 1, y: 0, duration: 0.4, ease: "power2.out" }
      )
    }
  }, [])

  return (
    <div ref={pageRef} className="space-y-6" style={{ opacity: 0 }}>
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link
          href="/dashboard/skills"
          className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors"
        >
          <ArrowLeft className="size-4" />
          Back to Skills
        </Link>
      </div>

      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-semibold tracking-tight">{skillId}</h1>
        {!isLoading && <StatusBadge status={verificationStatus} />}
      </div>

      {isLoading ? (
        <div className="space-y-4">
          <Skeleton className="h-48 w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
      ) : (
        <Tabs defaultValue="provenance">
          <TabsList>
            <TabsTrigger value="provenance">Provenance</TabsTrigger>
            <TabsTrigger value="violations">Violations</TabsTrigger>
          </TabsList>

          <TabsContent value="provenance" className="mt-4 space-y-6">
            {/* Provenance chain */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Provenance Chain</CardTitle>
              </CardHeader>
              <CardContent>
                <ProvenanceStepper steps={provenanceSteps} />
              </CardContent>
            </Card>

            {/* Policy compliance */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Policy Compliance</CardTitle>
              </CardHeader>
              <CardContent>
                {policyRules.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    No policy rules evaluated for this skill.
                  </p>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {policyRules.map(({ rule, severity }) => (
                      <div
                        key={rule}
                        className="flex items-center gap-2 rounded-md border px-3 py-1.5"
                      >
                        <span className="text-sm font-medium">{rule}</span>
                        <SeverityBadge severity={severity} />
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="violations" className="mt-4">
            {skillEvents.length === 0 ? (
              <EmptyState
                icon={<Package className="size-10" />}
                heading="No violations"
                body="No violations recorded for this skill."
              />
            ) : (
              <ViolationTable events={skillEvents} isLoading={false} />
            )}
          </TabsContent>
        </Tabs>
      )}
    </div>
  )
}
