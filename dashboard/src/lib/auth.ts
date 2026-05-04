import NextAuth from "next-auth"
import Credentials from "next-auth/providers/credentials"
import "./auth-types"

export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: [
    Credentials({
      id: "otp-verify",
      credentials: {
        email: { type: "email" },
        code: { type: "text" },
      },
      async authorize(credentials) {
        const res = await fetch(`${process.env.API_URL}/v1/auth/verify`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: credentials.email,
            code: credentials.code,
          }),
        })
        if (!res.ok) return null
        const tokens = await res.json()
        return {
          id: credentials.email as string,
          email: credentials.email as string,
          accessToken: tokens.access_token,
          refreshToken: tokens.refresh_token,
        }
      },
    }),
    Credentials({
      id: "saml-callback",
      credentials: {
        accessToken: { type: "text" },
        refreshToken: { type: "text" },
      },
      async authorize(credentials) {
        if (!credentials.accessToken || !credentials.refreshToken) return null
        return {
          id: "saml-user",
          accessToken: credentials.accessToken as string,
          refreshToken: credentials.refreshToken as string,
        }
      },
    }),
  ],
  session: { strategy: "jwt" },
  pages: {
    signIn: "/login",
  },
  callbacks: {
    async jwt({ token, user }) {
      // Initial sign-in: persist backend tokens into Auth.js JWT
      if (user) {
        token.accessToken = user.accessToken
        token.refreshToken = user.refreshToken
        token.email = user.email
        // SkillLedger access tokens expire in 60 minutes
        token.accessTokenExpires = Date.now() + 60 * 60 * 1000
      }

      // Token not expired yet -- return as-is
      if (Date.now() < (token.accessTokenExpires as number)) {
        return token
      }

      // Refresh expired access token
      try {
        const res = await fetch(`${process.env.API_URL}/v1/auth/refresh`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refresh_token: token.refreshToken }),
        })
        if (!res.ok) throw new Error("Refresh failed")
        const refreshed = await res.json()
        return {
          ...token,
          accessToken: refreshed.access_token,
          refreshToken: refreshed.refresh_token,
          accessTokenExpires: Date.now() + 60 * 60 * 1000,
        }
      } catch {
        return { ...token, error: "RefreshTokenError" }
      }
    },
    async session({ session, token }) {
      session.accessToken = token.accessToken as string
      session.error = token.error as string | undefined
      return session
    },
    authorized({ auth }) {
      return !!auth?.user
    },
  },
})
