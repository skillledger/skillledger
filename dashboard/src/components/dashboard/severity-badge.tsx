"use client"

import { Badge } from "@/components/ui/badge"

const severityStyles: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10 border-red-500/20",
  high: "text-orange-500 bg-orange-500/10 border-orange-500/20",
  medium: "text-yellow-500 bg-yellow-500/10 border-yellow-500/20",
  low: "text-blue-500 bg-blue-500/10 border-blue-500/20",
  info: "text-gray-500 bg-gray-500/10 border-gray-500/20",
}

interface SeverityBadgeProps {
  severity: string
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  const normalized = severity.toLowerCase()
  return (
    <Badge
      variant="outline"
      className={severityStyles[normalized] ?? severityStyles.info}
    >
      {normalized.charAt(0).toUpperCase() + normalized.slice(1)}
    </Badge>
  )
}
