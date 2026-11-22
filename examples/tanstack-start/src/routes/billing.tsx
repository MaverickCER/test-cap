import { createFileRoute } from "@tanstack/react-router"
import { getBilling } from "../billing.functions"

export const Route = createFileRoute("/billing")({
  loader: () => getBilling(),
  component: Billing,
})

function Billing() {
  const { subject, level } = Route.useLoaderData()
  return (
    <main>
      <h1>Billing</h1>
      <p data-subject={subject ?? ""}>Signed in at {level}.</p>
    </main>
  )
}
