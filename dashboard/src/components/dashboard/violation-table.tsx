"use client"

import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table"
import { Tooltip, TooltipTrigger, TooltipContent } from "@/components/ui/tooltip"
import { Skeleton } from "@/components/ui/skeleton"
import { SeverityBadge } from "@/components/dashboard/severity-badge"

interface ViolationEvent {
  id: number
  event_type: string
  ecosystem: string
  skill_id: string
  severity: string
  rule: string
  event_timestamp: string
  created_at: string
}

interface ViolationTableProps {
  events: ViolationEvent[]
  isLoading: boolean
  onRowClick?: (skillId: string) => void
}

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

export function ViolationTable({
  events,
  isLoading,
  onRowClick,
}: ViolationTableProps) {
  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full" />
        ))}
      </div>
    )
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Timestamp</TableHead>
          <TableHead>Ecosystem</TableHead>
          <TableHead>Severity</TableHead>
          <TableHead>Skill Name</TableHead>
          <TableHead>Type</TableHead>
          <TableHead>Rule</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {events.map((event) => (
          <TableRow
            key={event.id}
            className={
              onRowClick
                ? "hover:bg-muted/50 transition-colors duration-150 cursor-pointer"
                : "hover:bg-muted/50 transition-colors duration-150"
            }
            onClick={() => onRowClick?.(event.skill_id)}
          >
            <TableCell>
              <Tooltip>
                <TooltipTrigger render={<span />}>
                  {formatRelativeTime(event.event_timestamp)}
                </TooltipTrigger>
                <TooltipContent>
                  {new Date(event.event_timestamp).toLocaleString()}
                </TooltipContent>
              </Tooltip>
            </TableCell>
            <TableCell className="text-sm">{event.ecosystem}</TableCell>
            <TableCell>
              <SeverityBadge severity={event.severity} />
            </TableCell>
            <TableCell
              className={onRowClick ? "text-sm font-medium" : "text-sm"}
            >
              {event.skill_id}
            </TableCell>
            <TableCell className="text-sm">{event.event_type}</TableCell>
            <TableCell className="text-sm text-muted-foreground">
              {event.rule}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}
