"use client"

import { Card, CardContent } from "@/components/ui/card"

interface EmptyStateProps {
  icon?: React.ReactNode
  heading: string
  body: string
  action?: React.ReactNode
}

export function EmptyState({ icon, heading, body, action }: EmptyStateProps) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center py-16 text-center">
        {icon && <div className="mb-4 text-muted-foreground">{icon}</div>}
        <h3 className="text-lg font-semibold">{heading}</h3>
        <p className="mt-2 text-sm text-muted-foreground max-w-md">{body}</p>
        {action && <div className="mt-6">{action}</div>}
      </CardContent>
    </Card>
  )
}
