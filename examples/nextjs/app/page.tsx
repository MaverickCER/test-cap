// Public: no session needed.
export default function Home() {
  return (
    <main>
      <h1>test-cap on Next.js</h1>
      <p>
        Sign up and sign in through the /auth routes, then open /account (a password is enough) or
        /billing (a password and a TOTP code).
      </p>
    </main>
  )
}
