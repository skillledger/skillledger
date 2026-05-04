"use client"

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts"
import { Skeleton } from "@/components/ui/skeleton"

interface TrendPoint {
  date: string
  violations: number
}

interface ViolationTrendChartProps {
  data: TrendPoint[]
  isLoading: boolean
}

export function ViolationTrendChart({
  data,
  isLoading,
}: ViolationTrendChartProps) {
  if (isLoading) {
    return <Skeleton className="h-[300px] w-full" />
  }

  return (
    <ResponsiveContainer width="100%" height={300}>
      <LineChart
        data={data}
        margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
      >
        <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
        <XAxis dataKey="date" className="text-xs" />
        <YAxis className="text-xs" />
        <Tooltip />
        <Line
          type="monotone"
          dataKey="violations"
          stroke="var(--chart-4)"
          strokeWidth={2}
          dot={false}
          animationDuration={800}
          animationEasing="ease-out"
        />
      </LineChart>
    </ResponsiveContainer>
  )
}
