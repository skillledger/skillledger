import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"

export default function DashboardPage() {
  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <Card className="w-full max-w-lg">
        <CardHeader>
          <CardTitle className="text-2xl">Welcome to SkillLedger Dashboard</CardTitle>
          <CardDescription>
            Supply-chain security management for AI agent skills
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">
            Feature pages will be available in a future update. Use the
            navigation to explore available tools.
          </p>
        </CardContent>
      </Card>
    </div>
  )
}
