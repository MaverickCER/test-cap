import { redirect } from "next/navigation"
import { billing } from "../../server/billing"

// Protected by the server helper, through the data-access layer. A visitor without a session, or one whose session
// needs a step-up or enrolment, is sent home with the reason.
export default async function BillingPage() {
  const result = await billing()
  if (result.kind === "denied") redirect(`/?need=${result.outcome}&returnTo=%2Fbilling`)
  return (
    <main>
      <h1>Billing</h1>
      <p>Signed in as {result.subject}.</p>
      <ul>
        {result.invoices.map((invoice) => (
          <li key={invoice}>{invoice}</li>
        ))}
      </ul>
    </main>
  )
}
