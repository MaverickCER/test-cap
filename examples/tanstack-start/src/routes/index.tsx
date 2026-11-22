import { createFileRoute, Link } from "@tanstack/react-router"
import { closeAccount, exportInvoices } from "../billing.functions"

export const Route = createFileRoute("/")({ component: Home })

function Home() {
  return (
    <main>
      <h1>Welcome</h1>
      <p>
        This page is public. Every other page and every server function call needs a session at
        AAL2.
      </p>
      <p>
        <Link to="/billing">Billing</Link>
      </p>
      {/* The server function endpoints, for the example's end-to-end test. */}
      <ul>
        <li data-server-fn="exportInvoices">{exportInvoices.url}</li>
        <li data-server-fn="closeAccount">{closeAccount.url}</li>
      </ul>
    </main>
  )
}
