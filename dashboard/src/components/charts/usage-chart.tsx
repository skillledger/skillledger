"use client"

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts"
import { Skeleton } from "@/components/ui/skeleton"

interface UsagePoint {
  month: string
  count: number
}

interface UsageChartProps {
  data: UsagePoint[]
  isLoading: boolean
}

export function UsageChart({ data, isLoading }: UsageChartProps) {
  if (isLoading) {
    return <Skeleton className="h-[300px] w-full" />
  }

  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart
        data={data}
        margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
      >
        <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
        <XAxis dataKey="month" className="text-xs" />
        <YAxis className="text-xs" />
        <Tooltip />
        <Bar
          dataKey="count"
          fill="var(--chart-1)"
          animationDuration={800}
        />
      </BarChart>
    </ResponsiveContainer>
  )
}
