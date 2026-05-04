"use client"

import { Card, CardContent } from "@/components/ui/card"

interface StatCardProps {
  label: string
  value: number
  trend?: { value: number; label: string }
}

export function StatCard({ label, value, trend }: StatCardProps) {
  return (
    <Card className="group hover:shadow-md transition-shadow duration-200">
      <CardContent className="p-6">
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className="text-[2rem] font-semibold leading-none mt-1">
          {value.toLocaleString()}
        </p>
        {trend && (
          <p className="text-xs text-muted-foreground mt-2">
            {trend.value >= 0 ? "+" : ""}
            {trend.value} {trend.label}
          </p>
        )}
      </CardContent>
    </Card>
  )
}
