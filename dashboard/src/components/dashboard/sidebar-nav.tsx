"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import {
  BarChart3,
  AlertTriangle,
  Package,
  FileCode,
  CreditCard,
  Building2,
  KeyRound,
} from "lucide-react"
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
  SidebarSeparator,
} from "@/components/ui/sidebar"

const navGroups = [
  {
    label: "Security",
    items: [
      { label: "Posture Overview", icon: BarChart3, href: "/dashboard" },
      { label: "Violations", icon: AlertTriangle, href: "/dashboard/violations" },
      { label: "Skills", icon: Package, href: "/dashboard/skills" },
    ],
  },
  {
    label: "Policy",
    items: [
      { label: "Policy Editor", icon: FileCode, href: "/dashboard/policy" },
    ],
  },
  {
    label: "Billing",
    items: [
      { label: "Usage & Billing", icon: CreditCard, href: "/dashboard/billing" },
    ],
  },
  {
    label: "Settings",
    items: [
      { label: "Organization", icon: Building2, href: "/dashboard/settings" },
      { label: "SSO", icon: KeyRound, href: "/dashboard/settings/sso" },
    ],
  },
]

export function SidebarNav() {
  const pathname = usePathname()

  function isActive(href: string) {
    if (href === "/dashboard") {
      return pathname === "/dashboard"
    }
    return pathname.startsWith(href)
  }

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader className="px-4 py-4">
        <span className="text-sm font-semibold tracking-tight truncate">
          SkillLedger
        </span>
      </SidebarHeader>
      <SidebarSeparator />
      <SidebarContent>
        {navGroups.map((group, groupIndex) => (
          <div key={group.label}>
            {groupIndex > 0 && <SidebarSeparator />}
            <SidebarGroup>
              <SidebarGroupLabel>{group.label}</SidebarGroupLabel>
              <SidebarMenu>
                {group.items.map((item) => (
                  <SidebarMenuItem key={item.href}>
                    <SidebarMenuButton
                      isActive={isActive(item.href)}
                      tooltip={item.label}
                      render={<Link href={item.href} />}
                    >
                      <item.icon />
                      <span>{item.label}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroup>
          </div>
        ))}
      </SidebarContent>
    </Sidebar>
  )
}
