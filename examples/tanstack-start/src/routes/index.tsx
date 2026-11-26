import { createFileRoute, Link } from "@tanstack/react-router"
import { closeAccount, exportInvoices } from "../billing.functions"

export const Route = createFileRoute("/")({ component: Home })

function Home() {
  return (
    <main>
      <h1>Welcome</h1>
      <p>
        This page is public. Every other server function call needs a session at AAL2, and so does
        the billing page. The account page needs a signed-in session (AAL1) and checks it itself.
      </p>
      <p>
        <Link to="/billing">Billing</Link>
      </p>
      <p>
        {/* A plain link: a client-side navigation would call the page's server function, and the middleware answers
            that call at the default requirement, AAL2. A full page load reaches the check in the function itself. */}
        <a href="/account">Account</a>
      </p>
      {/* The server function endpoints, for the example's end-to-end test. */}
      <ul>
        <li data-server-fn="exportInvoices">{exportInvoices.url}</li>
        <li data-server-fn="closeAccount">{closeAccount.url}</li>
      </ul>
    </main>
  )
}
