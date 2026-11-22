import { billing } from "../../../server/billing"

// The same data as JSON: a 401 without a session, a 403 naming what the session lacks.
export async function GET(): Promise<Response> {
  const result = await billing()
  if (result.kind === "denied") {
    return Response.json(
      { error: result.outcome },
      { status: result.outcome === "unauthenticated" ? 401 : 403 },
    )
  }
  return Response.json({ invoices: result.invoices })
}
