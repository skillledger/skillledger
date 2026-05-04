/* eslint-disable @typescript-eslint/no-unused-vars */
import NextAuth from "next-auth"

declare module "next-auth" {
  interface Session {
    accessToken?: string
    refreshToken?: string
    error?: string
  }

  interface User {
    accessToken?: string
    refreshToken?: string
  }
}

// JWT type augmentation for next-auth callbacks
// The JWT type is re-exported from the main "next-auth" module in v5
declare module "next-auth" {
  interface JWT {
    accessToken?: string
    refreshToken?: string
    accessTokenExpires?: number
    error?: string
  }
}
