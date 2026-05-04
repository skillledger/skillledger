"use client"

import { Badge } from "@/components/ui/badge"

const statusConfig: Record<
  string,
  { className: string; text: string }
> = {
  verified: {
    className: "text-green-500 bg-green-500/10 border-green-500/20",
    text: "Verified",
  },
  unverified: {
    className: "text-gray-400 bg-gray-400/10 border-gray-400/20",
    text: "Unverified",
  },
  failed: {
    className: "text-red-500 bg-red-500/10 border-red-500/20",
    text: "Failed",
  },
}

interface StatusBadgeProps {
  status: "verified" | "unverified" | "failed"
}

export function StatusBadge({ status }: StatusBadgeProps) {
  const config = statusConfig[status] ?? statusConfig.unverified
  return (
    <Badge variant="outline" className={config.className}>
      {config.text}
    </Badge>
  )
}
