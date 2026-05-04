"use client"

import { CheckCircle2, Circle, XCircle } from "lucide-react"
import { cn } from "@/lib/utils"

interface ProvenanceStep {
  label: string
  status: "complete" | "pending" | "failed"
  timestamp?: string
  detail?: string
}

interface ProvenanceStepperProps {
  steps: ProvenanceStep[]
}

const statusConfig = {
  complete: {
    icon: CheckCircle2,
    iconClass: "text-green-500",
    lineClass: "bg-green-500",
  },
  pending: {
    icon: Circle,
    iconClass: "text-gray-400",
    lineClass: "border-l-2 border-dashed border-gray-300",
  },
  failed: {
    icon: XCircle,
    iconClass: "text-red-500",
    lineClass: "bg-red-500",
  },
}

export function ProvenanceStepper({ steps }: ProvenanceStepperProps) {
  return (
    <div className="flex flex-col">
      {steps.map((step, index) => {
        const config = statusConfig[step.status]
        const Icon = config.icon
        const isLast = index === steps.length - 1

        return (
          <div key={step.label} className="flex gap-3">
            {/* Icon + connecting line column */}
            <div className="flex flex-col items-center">
              <Icon className={cn("size-5 shrink-0", config.iconClass)} />
              {!isLast && (
                <div
                  className={cn(
                    "flex-1 min-h-8 w-0.5",
                    step.status === "pending"
                      ? config.lineClass
                      : config.lineClass
                  )}
                  style={
                    step.status === "pending"
                      ? undefined
                      : { minHeight: "2rem" }
                  }
                />
              )}
            </div>

            {/* Content column */}
            <div className="pb-6">
              <p className="text-sm font-medium leading-5">{step.label}</p>
              {step.timestamp && (
                <p className="text-xs text-muted-foreground mt-0.5">
                  {new Date(step.timestamp).toLocaleString()}
                </p>
              )}
              {step.detail && (
                <p className="text-xs font-mono text-muted-foreground mt-1 break-all">
                  {step.detail}
                </p>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}
