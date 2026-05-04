"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

export function SsoButton() {
  const [slug, setSlug] = useState("")
  const [expanded, setExpanded] = useState(false)

  function handleSsoLogin() {
    if (!slug.trim()) return
    // Redirect to the SAML SP-initiated login endpoint
    // The IdP will eventually POST back to the ACS endpoint,
    // which redirects to /auth/callback with tokens in the URL fragment
    window.location.href = `${process.env.NEXT_PUBLIC_API_URL}/ee/v1/saml/${encodeURIComponent(slug.trim())}/login`
  }

  if (!expanded) {
    return (
      <Button
        variant="outline"
        className="w-full"
        onClick={() => setExpanded(true)}
      >
        Sign in with SSO
      </Button>
    )
  }

  return (
    <div className="space-y-3">
      <div className="space-y-2">
        <Label htmlFor="sso-slug">Organization slug</Label>
        <Input
          id="sso-slug"
          type="text"
          placeholder="acme-corp"
          value={slug}
          onChange={(e) => setSlug(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault()
              handleSsoLogin()
            }
          }}
          autoFocus
        />
      </div>
      <div className="flex gap-2">
        <Button
          variant="outline"
          className="flex-1"
          onClick={() => {
            setExpanded(false)
            setSlug("")
          }}
        >
          Cancel
        </Button>
        <Button
          className="flex-1"
          onClick={handleSsoLogin}
          disabled={!slug.trim()}
        >
          Continue with SSO
        </Button>
      </div>
    </div>
  )
}
