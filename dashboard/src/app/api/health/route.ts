import { NextResponse } from "next/server"

export async function GET() {
  const apiUrl = process.env.API_URL || process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

  try {
    const res = await fetch(`${apiUrl}/openapi.json`, {
      method: "HEAD",
      signal: AbortSignal.timeout(5000),
    })

    if (res.ok) {
      return NextResponse.json({ status: "ok", api: "connected" })
    }

    return NextResponse.json({ status: "ok", api: "disconnected" })
  } catch {
    return NextResponse.json({ status: "ok", api: "disconnected" })
  }
}
