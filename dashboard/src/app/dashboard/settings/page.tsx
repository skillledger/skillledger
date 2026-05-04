"use client"

import { useRef, useEffect, useState } from "react"
import gsap from "gsap"
import { Building2 } from "lucide-react"
import { $api } from "@/lib/api"
import { fetchClient } from "@/lib/api-client"
import { useOrg } from "@/hooks/use-org"
import { EmptyState } from "@/components/dashboard/empty-state"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { useQueryClient } from "@tanstack/react-query"

function formatRelativeDate(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24))
  if (diffDays === 0) return "Today"
  if (diffDays === 1) return "Yesterday"
  if (diffDays < 30) return `${diffDays} days ago`
  if (diffDays < 365) return `${Math.floor(diffDays / 30)} months ago`
  return `${Math.floor(diffDays / 365)} years ago`
}

function getRoleBadgeVariant(role: string): "default" | "secondary" | "outline" {
  switch (role) {
    case "owner":
      return "default"
    case "admin":
      return "secondary"
    default:
      return "outline"
  }
}

interface MemberInfo {
  user_id: number
  email: string
  role: string
  joined_at: string
}

export default function SettingsPage() {
  const containerRef = useRef<HTMLDivElement>(null)
  const queryClient = useQueryClient()
  const { orgSlug, orgName, isLoading: orgLoading } = useOrg()

  const [removingMember, setRemovingMember] = useState<MemberInfo | null>(null)
  const [removeLoading, setRemoveLoading] = useState(false)
  const [removeError, setRemoveError] = useState("")

  const [inviteEmail, setInviteEmail] = useState("")
  const [inviteRole, setInviteRole] = useState<"owner" | "admin" | "member" | "viewer">("member")
  const [isInviting, setIsInviting] = useState(false)
  const [inviteError, setInviteError] = useState("")
  const [inviteSuccess, setInviteSuccess] = useState("")

  useEffect(() => {
    if (containerRef.current) {
      gsap.from(containerRef.current, {
        opacity: 0,
        y: 8,
        duration: 0.3,
        ease: "power2.out",
      })
    }
  }, [])

  const {
    data: members,
    isLoading: membersLoading,
  } = $api.useQuery(
    "get",
    "/ee/v1/orgs/{slug}/members",
    { params: { path: { slug: orgSlug! } } },
    { enabled: !!orgSlug }
  )

  const memberList = (members ?? []) as MemberInfo[]
  const isLoading = orgLoading || membersLoading

  async function handleRemoveMember() {
    if (!removingMember || !orgSlug) return
    setRemoveLoading(true)
    setRemoveError("")

    try {
      await fetchClient.DELETE("/ee/v1/orgs/{slug}/members/{user_id}", {
        params: {
          path: { slug: orgSlug, user_id: removingMember.user_id },
        },
      })
      queryClient.invalidateQueries({
        queryKey: ["get", "/ee/v1/orgs/{slug}/members"],
      })
      setRemovingMember(null)
    } catch (err) {
      setRemoveError(
        err instanceof Error ? err.message : "Failed to remove member"
      )
    } finally {
      setRemoveLoading(false)
    }
  }

  async function handleInvite(e: React.FormEvent) {
    e.preventDefault()
    if (!inviteEmail.trim() || !orgSlug) return
    setIsInviting(true)
    setInviteError("")
    setInviteSuccess("")

    try {
      await fetchClient.POST("/ee/v1/orgs/{slug}/invites", {
        params: { path: { slug: orgSlug } },
        body: { email: inviteEmail.trim(), role: inviteRole },
      })
      queryClient.invalidateQueries({
        queryKey: ["get", "/ee/v1/orgs/{slug}/members"],
      })
      setInviteEmail("")
      setInviteSuccess(`Invitation sent to ${inviteEmail.trim()}`)
      setTimeout(() => setInviteSuccess(""), 5000)
    } catch (err) {
      setInviteError(
        err instanceof Error ? err.message : "Failed to send invitation"
      )
    } finally {
      setIsInviting(false)
    }
  }

  return (
    <div ref={containerRef} className="space-y-6">
      <h1 className="text-2xl font-semibold">Organization</h1>

      {isLoading ? (
        <>
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </>
      ) : (
        <>
          {/* Section 1: Org Info */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg font-semibold">
                Organization Details
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div>
                <Label className="text-xs text-muted-foreground">Name</Label>
                <p className="text-sm">{orgName ?? "No organization"}</p>
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">Slug</Label>
                <p className="text-sm font-mono text-muted-foreground">
                  {orgSlug ?? "N/A"}
                </p>
              </div>
            </CardContent>
          </Card>

          {/* Section 2: Members Table */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg font-semibold">Members</CardTitle>
            </CardHeader>
            <CardContent>
              {memberList.length === 0 ? (
                <EmptyState
                  icon={<Building2 className="size-10" />}
                  heading="No team members yet"
                  body="Invite your first team member below."
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Email</TableHead>
                      <TableHead>Role</TableHead>
                      <TableHead>Joined</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {memberList.map((member) => (
                      <TableRow key={member.user_id}>
                        <TableCell className="text-sm">
                          {member.email}
                        </TableCell>
                        <TableCell>
                          <Badge variant={getRoleBadgeVariant(member.role)}>
                            {member.role}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {formatRelativeDate(member.joined_at)}
                        </TableCell>
                        <TableCell className="text-right">
                          {member.role !== "owner" && (
                            <Button
                              variant="destructive"
                              size="sm"
                              onClick={() => setRemovingMember(member)}
                            >
                              Remove
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          <Separator />

          {/* Section 3: Invite Flow */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg font-semibold">
                Invite Member
              </CardTitle>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleInvite} className="flex items-end gap-3">
                <div className="flex-1">
                  <Label htmlFor="invite-email" className="text-xs">
                    Email
                  </Label>
                  <Input
                    id="invite-email"
                    type="email"
                    placeholder="team@example.com"
                    value={inviteEmail}
                    onChange={(e) => setInviteEmail(e.target.value)}
                    required
                  />
                </div>
                <div className="w-36">
                  <Label htmlFor="invite-role" className="text-xs">
                    Role
                  </Label>
                  <Select
                    value={inviteRole}
                    onValueChange={(val) => {
                      if (val !== null) setInviteRole(val)
                    }}
                  >
                    <SelectTrigger className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="admin">Admin</SelectItem>
                      <SelectItem value="member">Member</SelectItem>
                      <SelectItem value="viewer">Viewer</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <Button
                  type="submit"
                  disabled={isInviting || !inviteEmail.trim()}
                >
                  {isInviting ? "Inviting..." : "Invite Member"}
                </Button>
              </form>

              {inviteError && (
                <div
                  role="alert"
                  className="mt-3 rounded-lg border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
                >
                  {inviteError}
                </div>
              )}

              {inviteSuccess && (
                <div
                  role="status"
                  className="mt-3 rounded-lg border border-green-500/50 bg-green-500/10 px-3 py-2 text-sm text-green-600"
                >
                  {inviteSuccess}
                </div>
              )}
            </CardContent>
          </Card>
        </>
      )}

      {/* Remove Member Dialog */}
      <Dialog
        open={!!removingMember}
        onOpenChange={(open) => {
          if (!open) {
            setRemovingMember(null)
            setRemoveError("")
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              Remove {removingMember?.email}?
            </DialogTitle>
            <DialogDescription>
              They will lose access to this organization immediately.
            </DialogDescription>
          </DialogHeader>

          {removeError && (
            <div
              role="alert"
              className="rounded-lg border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
            >
              {removeError}
            </div>
          )}

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setRemovingMember(null)
                setRemoveError("")
              }}
              disabled={removeLoading}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleRemoveMember}
              disabled={removeLoading}
            >
              {removeLoading ? "Removing..." : "Remove"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
