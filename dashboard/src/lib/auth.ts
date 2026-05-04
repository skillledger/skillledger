import NextAuth from "next-auth"

// Stub Auth.js configuration -- will be fully configured in Plan 28-02
// with Credentials provider (OTP) and SAML provider.
export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: [],
  session: { strategy: "jwt" },
  pages: {
    signIn: "/login",
  },
})
