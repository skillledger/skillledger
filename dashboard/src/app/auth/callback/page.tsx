"use client"

import { useEffect, useState } from "react"
import { signIn } from "next-auth/react"
import { useRouter } from "next/navigation"
import Link from "next/link"

export default function SamlCallbackPage() {
  const router = useRouter()
  const [error, setError] = useState("")

  useEffect(() => {
    async function handleCallback() {
      // Read tokens from URL fragment (set by ACS redirect)
      // Fragments are client-side only and never sent to the server
      const hash = window.location.hash.substring(1)
      const params = new URLSearchParams(hash)
      const accessToken = params.get("access_token")
      const refreshToken = params.get("refresh_token")

      if (!accessToken || !refreshToken) {
        setError("Missing authentication tokens. Please try signing in again.")
        return
      }

      try {
        const result = await signIn("saml-callback", {
          accessToken,
          refreshToken,
          redirect: false,
        })

        if (result?.ok) {
          router.push("/dashboard")
        } else {
          setError("SSO sign-in failed. Please try again.")
        }
      } catch {
        setError("An error occurred during SSO sign-in.")
      }
    }

    handleCallback()
  }, [router])

  if (error) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-muted/40 px-4">
        <div className="w-full max-w-sm space-y-4 text-center">
          <p className="text-sm text-destructive">{error}</p>
          <Link
            href="/login"
            className="text-sm text-muted-foreground underline hover:text-foreground"
          >
            Return to login
          </Link>
        </div>
      </main>
    )
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-muted/40 px-4">
      <p className="text-sm text-muted-foreground">
        Completing SSO login...
      </p>
    </main>
  )
}
