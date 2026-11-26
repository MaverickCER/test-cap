import { redirect } from "next/navigation"
import { account } from "../../server/account"

// Protected by the server helper, through the data-access layer, at AAL1: a password alone is enough. A visitor
// without a session, or one in the enrolment or recovery state, is sent home with the reason.
export default async function AccountPage() {
  const result = await account()
  if (result.kind === "denied") redirect(`/?need=${result.outcome}&returnTo=%2Faccount`)
  return (
    <main>
      <h1>Account</h1>
      <p>Signed in as {result.subject}.</p>
      <p>
        Session level: <span data-level={result.level}>{result.level}</span>.
      </p>
    </main>
  )
}
