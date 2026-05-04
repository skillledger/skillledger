"use client"

import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select"
import { Button } from "@/components/ui/button"

interface FilterBarProps {
  ecosystem: string
  severity: string
  timeRange: string
  onEcosystemChange: (val: string) => void
  onSeverityChange: (val: string) => void
  onTimeRangeChange: (val: string) => void
  onClearAll: () => void
  hasActiveFilters: boolean
}

const ecosystems = [
  "all",
  "claude-code",
  "mcp",
  "openclaw",
  "anthropic",
  "openai",
  "codex",
  "opencode",
]

const severities = ["all", "critical", "high", "medium", "low"]

const timeRanges = [
  { value: "24h", label: "Last 24h" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
  { value: "all", label: "All time" },
]

export function FilterBar({
  ecosystem,
  severity,
  timeRange,
  onEcosystemChange,
  onSeverityChange,
  onTimeRangeChange,
  onClearAll,
  hasActiveFilters,
}: FilterBarProps) {
  return (
    <div className="flex items-center gap-3 flex-wrap">
      <Select
        value={ecosystem}
        onValueChange={(val) => {
          if (val !== null) onEcosystemChange(val)
        }}
      >
        <SelectTrigger>
          <SelectValue placeholder="Ecosystem" />
        </SelectTrigger>
        <SelectContent>
          {ecosystems.map((eco) => (
            <SelectItem key={eco} value={eco}>
              {eco === "all" ? "All Ecosystems" : eco}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      <Select
        value={severity}
        onValueChange={(val) => {
          if (val !== null) onSeverityChange(val)
        }}
      >
        <SelectTrigger>
          <SelectValue placeholder="Severity" />
        </SelectTrigger>
        <SelectContent>
          {severities.map((sev) => (
            <SelectItem key={sev} value={sev}>
              {sev === "all"
                ? "All Severities"
                : sev.charAt(0).toUpperCase() + sev.slice(1)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      <Select
        value={timeRange}
        onValueChange={(val) => {
          if (val !== null) onTimeRangeChange(val)
        }}
      >
        <SelectTrigger>
          <SelectValue placeholder="Time Range" />
        </SelectTrigger>
        <SelectContent>
          {timeRanges.map((tr) => (
            <SelectItem key={tr.value} value={tr.value}>
              {tr.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      {hasActiveFilters && (
        <Button variant="ghost" size="sm" onClick={onClearAll}>
          Clear all
        </Button>
      )}
    </div>
  )
}
