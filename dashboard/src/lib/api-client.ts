"use client"

import createFetchClient, { type Middleware } from "openapi-fetch"
import type { paths } from "@/generated/api-types"
import { getSession } from "next-auth/react"

const authMiddleware: Middleware = {
  async onRequest({ request }) {
    const session = await getSession()
    if (session?.accessToken) {
      request.headers.set("Authorization", `Bearer ${session.accessToken}`)
    }
    return request
  },
}

export const fetchClient = createFetchClient<paths>({
  baseUrl: process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000",
})
fetchClient.use(authMiddleware)
