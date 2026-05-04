"use client"

import { useState, useRef, useEffect, useCallback } from "react"
import dynamic from "next/dynamic"
import gsap from "gsap"
import { Skeleton } from "@/components/ui/skeleton"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { EmptyState } from "@/components/dashboard/empty-state"
import { useOrg } from "@/hooks/use-org"
import { $api } from "@/lib/api"
import { FileCode2 } from "lucide-react"

const Editor = dynamic(
  () => import("@monaco-editor/react").then((mod) => mod.default),
  { ssr: false, loading: () => <Skeleton className="h-[500px] w-full" /> }
)

const monacoOptions = {
  minimap: { enabled: false },
  fontSize: 14,
  fontFamily: "var(--font-geist-mono), monospace",
  wordWrap: "on" as const,
  automaticLayout: true,
  scrollBeyondLastLine: false,
}

export default function PolicyEditorPage() {
  const { orgSlug } = useOrg()
  const pageRef = useRef<HTMLDivElement>(null)

  const [dslCode, setDslCode] = useState("")
  const [regoPreview, setRegoPreview] = useState("")
  const [compileError, setCompileError] = useState("")
  const [isCompiling, setIsCompiling] = useState(false)
  const [isDeploying, setIsDeploying] = useState(false)
  const [showDeployDialog, setShowDeployDialog] = useState(false)
  const [deployError, setDeployError] = useState("")

  // Load existing policy
  const { data: existingPolicy, isLoading: isPolicyLoading } = $api.useQuery(
    "get",
    "/ee/v1/orgs/{slug}/policy",
    { params: { path: { slug: orgSlug! } } },
    { staleTime: 30_000, enabled: !!orgSlug, retry: false }
  )

  // Seed editor with existing policy
  useEffect(() => {
    if (existingPolicy?.rego) {
      setDslCode(existingPolicy.rego)
      setRegoPreview(existingPolicy.rego)
    }
  }, [existingPolicy])

  // GSAP page fade-in
  useEffect(() => {
    if (pageRef.current) {
      gsap.fromTo(
        pageRef.current,
        { opacity: 0, y: 12 },
        { opacity: 1, y: 0, duration: 0.4, ease: "power2.out" }
      )
    }
  }, [])

  const handleCompile = useCallback(async () => {
    if (!orgSlug || !dslCode.trim()) return
    setIsCompiling(true)
    setCompileError("")

    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/ee/v1/orgs/${encodeURIComponent(orgSlug)}/policy`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ rego: dslCode, deploy: false }),
        }
      )

      if (!response.ok) {
        const err = await response.json().catch(() => ({ detail: "Compilation failed" }))
        setCompileError(err.detail || "Compilation failed")
        return
      }

      const result = await response.json()
      setRegoPreview(result.rego)
      setCompileError("")
    } catch (err) {
      setCompileError(err instanceof Error ? err.message : "Network error")
    } finally {
      setIsCompiling(false)
    }
  }, [orgSlug, dslCode])

  const handleDeploy = useCallback(async () => {
    if (!orgSlug || !dslCode.trim()) return
    setIsDeploying(true)
    setDeployError("")

    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/ee/v1/orgs/${encodeURIComponent(orgSlug)}/policy`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ rego: dslCode, deploy: true }),
        }
      )

      if (!response.ok) {
        const err = await response.json().catch(() => ({ detail: "Deploy failed" }))
        setDeployError(err.detail || "Deploy failed")
        return
      }

      const result = await response.json()
      setRegoPreview(result.rego)
      setShowDeployDialog(false)
      setDeployError("")
    } catch (err) {
      setDeployError(err instanceof Error ? err.message : "Network error")
    } finally {
      setIsDeploying(false)
    }
  }, [orgSlug, dslCode])

  const buttonsDisabled = !orgSlug || !dslCode.trim()

  return (
    <div ref={pageRef} className="space-y-6" style={{ opacity: 0 }}>
      <h1 className="text-2xl font-semibold tracking-tight">Policy Editor</h1>

      {isPolicyLoading ? (
        <div className="space-y-4">
          <Skeleton className="h-[500px] w-full" />
        </div>
      ) : (
        <>
          {/* Split pane editor layout */}
          <div className="grid grid-cols-1 lg:grid-cols-[60fr_40fr] gap-4">
            {/* DSL editor (left) */}
            <div className="space-y-2">
              <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                SkillLedger DSL
              </label>
              <div className="rounded-lg border overflow-hidden">
                <Editor
                  theme="vs-dark"
                  defaultLanguage="plaintext"
                  height="500px"
                  value={dslCode}
                  onChange={(value) => setDslCode(value ?? "")}
                  options={monacoOptions}
                />
              </div>
            </div>

            {/* Rego preview (right) */}
            <div className="space-y-2">
              <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Compiled Rego (read-only)
              </label>
              <div className="rounded-lg border overflow-hidden">
                <Editor
                  theme="vs-dark"
                  defaultLanguage="plaintext"
                  height="500px"
                  value={regoPreview}
                  options={{ ...monacoOptions, readOnly: true }}
                />
              </div>
            </div>
          </div>

          {/* Compile error display */}
          {compileError && (
            <div
              role="alert"
              className="rounded-lg border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
            >
              {compileError}
            </div>
          )}

          {/* Action buttons */}
          <div className="flex items-center gap-3">
            <Button
              onClick={handleCompile}
              disabled={buttonsDisabled || isCompiling}
            >
              {isCompiling ? "Compiling..." : "Compile Policy"}
            </Button>
            <Button
              variant="destructive"
              onClick={() => setShowDeployDialog(true)}
              disabled={buttonsDisabled || isDeploying}
            >
              Deploy to Org
            </Button>
          </div>

          {/* Empty state when no policy exists and editor is empty */}
          {!existingPolicy && !dslCode.trim() && (
            <EmptyState
              icon={<FileCode2 className="size-10" />}
              heading="No policy configured"
              body="No policy configured yet. Write your first SkillLedger DSL policy above."
            />
          )}

          {/* Deploy confirmation dialog */}
          <Dialog
            open={showDeployDialog}
            onOpenChange={setShowDeployDialog}
          >
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Deploy Policy?</DialogTitle>
                <DialogDescription>
                  This will push the current policy to all organization CLIs.
                  They will enforce it on their next run.
                </DialogDescription>
              </DialogHeader>

              {deployError && (
                <div
                  role="alert"
                  className="rounded-lg border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
                >
                  {deployError}
                </div>
              )}

              <DialogFooter>
                <Button
                  variant="outline"
                  onClick={() => {
                    setShowDeployDialog(false)
                    setDeployError("")
                  }}
                >
                  Cancel
                </Button>
                <Button
                  variant="destructive"
                  onClick={handleDeploy}
                  disabled={isDeploying}
                >
                  {isDeploying ? "Deploying..." : "Deploy"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </>
      )}
    </div>
  )
}
