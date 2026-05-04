/* eslint-disable @typescript-eslint/no-unused-vars */
import NextAuth from "next-auth"

declare module "next-auth" {
  interface Session {
    accessToken: string
    error?: string
  }

  interface User {
    accessToken: string
    refreshToken: string
  }

  interface JWT {
    accessToken?: string
    refreshToken?: string
    accessTokenExpires?: number
    error?: string
  }
}
