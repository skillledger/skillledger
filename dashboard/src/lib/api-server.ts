import createFetchClient from "openapi-fetch"
import type { paths } from "@/generated/api-types"

export async function createServerClient() {
  const { auth } = await import("@/lib/auth")
  const session = await auth()
  const client = createFetchClient<paths>({
    baseUrl: process.env.API_URL || process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000",
  })
  if (session?.accessToken) {
    client.use({
      async onRequest({ request }) {
        request.headers.set("Authorization", `Bearer ${session.accessToken}`)
        return request
      },
    })
  }
  return client
}
