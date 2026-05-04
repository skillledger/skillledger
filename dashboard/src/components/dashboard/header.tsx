"use client"

import { signOut } from "next-auth/react"
import { LogOut, User } from "lucide-react"
import { SidebarTrigger } from "@/components/ui/sidebar"
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuLabel,
} from "@/components/ui/dropdown-menu"
import { Button } from "@/components/ui/button"
import { useOrg } from "@/hooks/use-org"

export function Header() {
  const { orgName, userEmail } = useOrg()

  return (
    <header className="flex h-14 items-center gap-4 border-b bg-background px-6">
      <SidebarTrigger />

      {orgName && (
        <span className="text-xs text-muted-foreground">{orgName}</span>
      )}

      <div className="ml-auto flex items-center gap-2">
        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <Button variant="ghost" size="sm" className="gap-2">
                <User className="size-4" />
                <span className="text-sm">{userEmail ?? "Account"}</span>
              </Button>
            }
          />
          <DropdownMenuContent align="end" side="bottom" sideOffset={8}>
            {userEmail && (
              <>
                <DropdownMenuLabel>{userEmail}</DropdownMenuLabel>
                <DropdownMenuSeparator />
              </>
            )}
            <DropdownMenuItem onClick={() => signOut({ callbackUrl: "/login" })}>
              <LogOut className="size-4" />
              Sign Out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  )
}
