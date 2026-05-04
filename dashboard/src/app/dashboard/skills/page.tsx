"use client"

import { useMemo, useRef, useEffect } from "react"
import { useRouter } from "next/navigation"
import gsap from "gsap"
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table"
import { Skeleton } from "@/components/ui/skeleton"
import { SeverityBadge } from "@/components/dashboard/severity-badge"
import { EmptyState } from "@/components/dashboard/empty-state"
import { useOrg } from "@/hooks/use-org"
import { $api } from "@/lib/api"
import { ShieldAlert } from "lucide-react"

function formatRelativeTime(dateString: string): string {
  const date = new Date(dateString)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMins / 60)
  const diffDays = Math.floor(diffHours / 24)

  if (diffMins < 1) return "just now"
  if (diffMins < 60) return `${diffMins}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  if (diffDays < 30) return `${diffDays}d ago`
  return date.toLocaleDateString()
}

interface SkillSummary {
  skill_id: string
  ecosystem: string
  lastSeen: string
  violationCount: number
  latestSeverity: string
}

export default function SkillsPage() {
  const { orgSlug } = useOrg()
  const router = useRouter()
  const pageRef = useRef<HTMLDivElement>(null)

  const { data, isLoading } = $api.useQuery(
    "get",
    "/ee/v1/orgs/{slug}/events",
    { params: { path: { slug: orgSlug! }, query: { limit: 200 } } },
    { staleTime: 30_000, enabled: !!orgSlug }
  )

  const skills = useMemo<SkillSummary[]>(() => {
    if (!data) return []
    const map = new Map<
      string,
      SkillSummary
    >()
    for (const ev of data) {
      const existing = map.get(ev.skill_id)
      if (!existing) {
        map.set(ev.skill_id, {
          skill_id: ev.skill_id,
          ecosystem: ev.ecosystem,
          lastSeen: ev.event_timestamp,
          violationCount: 1,
          latestSeverity: ev.severity,
        })
      } else {
        existing.violationCount++
        if (new Date(ev.event_timestamp) > new Date(existing.lastSeen)) {
          existing.lastSeen = ev.event_timestamp
          existing.latestSeverity = ev.severity
        }
      }
    }
    return Array.from(map.values())
  }, [data])

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
      <h1 className="text-2xl font-semibold tracking-tight">Skills</h1>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : skills.length === 0 ? (
        <EmptyState
          icon={<ShieldAlert className="size-10" />}
          heading="No skills found"
          body="No skills have been verified or flagged yet."
        />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Skill ID</TableHead>
              <TableHead>Ecosystem</TableHead>
              <TableHead>Violations</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>Last Seen</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {skills.map((skill) => (
              <TableRow
                key={skill.skill_id}
                className="hover:bg-muted/50 transition-colors duration-150 cursor-pointer"
                onClick={() =>
                  router.push(
                    `/dashboard/skills/${encodeURIComponent(skill.skill_id)}`
                  )
                }
              >
                <TableCell className="font-medium text-sm">
                  {skill.skill_id}
                </TableCell>
                <TableCell className="text-sm">{skill.ecosystem}</TableCell>
                <TableCell className="text-sm tabular-nums">
                  {skill.violationCount}
                </TableCell>
                <TableCell>
                  <SeverityBadge severity={skill.latestSeverity} />
                </TableCell>
                <TableCell className="text-sm text-muted-foreground">
                  {formatRelativeTime(skill.lastSeen)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  )
}
