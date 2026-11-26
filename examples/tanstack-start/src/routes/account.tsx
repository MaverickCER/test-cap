import { createFileRoute, redirect } from "@tanstack/react-router"
import { getAccount } from "../account.functions"

export const Route = createFileRoute("/account")({
  // A visitor without a session, or one that needs enrolment, is sent home with the reason.
  loader: async () => {
    const account = await getAccount()
    if (account.outcome !== "allow") {
      throw redirect({ href: `/?need=${account.outcome}&returnTo=%2Faccount` })
    }
    return account
  },
  component: Account,
})

function Account() {
  const { subject, level } = Route.useLoaderData()
  return (
    <main>
      <h1>Account</h1>
      <p data-subject={subject ?? ""} data-level={level ?? ""}>
        Signed in at {level}.
      </p>
    </main>
  )
}
