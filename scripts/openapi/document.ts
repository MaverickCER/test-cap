/**
 * Builds the OpenAPI 3.1 document of the `/auth/*` routes that docs/api-reference/ renders with Scalar. Paths, methods
 * and body fields come from the dispatcher's own route table; summaries and replies come from ./routes.ts. Written by
 * `npm run docs:openapi`; test/docs/openapi.test.ts fails when the committed file is stale or a route is undocumented.
 */
import type { RouteSummary } from "../../src/core/dispatcher.js"
import { ANY_REPLIES, POST_REPLIES, type ReplyDoc, type RouteDoc } from "./routes.js"

type Json = string | number | boolean | null | readonly Json[] | { readonly [key: string]: Json }

const ERROR_SCHEMA = {
  type: "object",
  required: ["error"],
  properties: {
    error: { type: "string", description: "A fixed code; never says whether an account exists." },
  },
}

/** Merges reply tables; a later table's codes are added to an earlier one's for the same status. */
function mergeReplies(
  ...tables: readonly Readonly<Record<string, ReplyDoc>>[]
): Record<string, ReplyDoc> {
  const merged: Record<string, ReplyDoc> = {}
  for (const table of tables) {
    for (const [status, reply] of Object.entries(table)) {
      const known = merged[status]
      merged[status] =
        known === undefined
          ? reply
          : {
              description: known.description,
              codes: [...new Set([...(known.codes ?? []), ...(reply.codes ?? [])])],
            }
    }
  }
  return merged
}

function response(status: string, reply: ReplyDoc): Json {
  const error = status !== "200" && status !== "303"
  const codes = reply.codes ?? []
  const description =
    codes.length === 0
      ? reply.description
      : `${reply.description} Codes: ${codes.map((code) => `\`${code}\``).join(", ")}.`
  return {
    description,
    content: {
      "application/json": {
        schema: error
          ? {
              ...ERROR_SCHEMA,
              properties: { error: { ...ERROR_SCHEMA.properties.error, enum: codes } },
            }
          : { type: "object" },
      },
    },
  }
}

function requestBody(fields: Readonly<Record<string, boolean>>): Json {
  const properties = Object.fromEntries(
    [...Object.keys(fields), "csrfToken"].map((name) => [
      name,
      name === "csrfToken"
        ? {
            type: "string",
            description: "The synchronizer token, when it is not sent as `X-CSRF-Token`.",
          }
        : { type: "string" },
    ]),
  )
  const required = Object.entries(fields)
    .filter(([, isRequired]) => isRequired)
    .map(([name]) => name)
  const schema = { type: "object", additionalProperties: false, required, properties }
  return {
    required: true,
    content: { "application/x-www-form-urlencoded": { schema }, "application/json": { schema } },
  }
}

/** The OpenAPI 3.1 document for `routes`, documented by `docs`. Throws when a route has no entry in `docs`. */
export function buildOpenApi(
  routes: readonly RouteSummary[],
  docs: Readonly<Record<string, RouteDoc>>,
  version: string,
): Json {
  const paths: Record<string, Json> = {}
  for (const route of routes) {
    const doc = docs[route.path]
    if (doc === undefined)
      throw new Error(`${route.path} has no entry in scripts/openapi/routes.ts.`)
    const replies =
      route.method === "POST"
        ? mergeReplies(doc.replies, POST_REPLIES, ANY_REPLIES)
        : mergeReplies(doc.replies, ANY_REPLIES)
    const statuses = Object.keys(replies).sort()
    paths[route.path] = {
      [route.method.toLowerCase()]: {
        operationId: route.path.slice("/auth/".length).replace(/\//g, "-"),
        summary: doc.summary,
        description: doc.description,
        ...(route.method === "POST"
          ? { requestBody: requestBody(route.fields), security: [{ csrfHeader: [] }, {}] }
          : {}),
        responses: Object.fromEntries(
          statuses.map((status) => [status, response(status, replies[status] as ReplyDoc)]),
        ),
      },
    }
  }
  return {
    openapi: "3.1.0",
    info: {
      title: "test-cap /auth routes",
      version,
      description:
        "The routes `auth.handle` serves. Internal use only. Every `POST` needs the app's `Origin` and the synchronizer token from `GET /auth/session`, sent as the `X-CSRF-Token` header or a `csrfToken` field. Every reply carries `Cache-Control: no-store` and the security headers. Generated from the dispatcher's route table.",
    },
    servers: [{ url: "http://localhost:3000", description: "The README quick start" }],
    components: {
      securitySchemes: {
        sessionCookie: { type: "apiKey", in: "cookie", name: "__Host-test-cap" },
        csrfHeader: {
          type: "apiKey",
          in: "header",
          name: "X-CSRF-Token",
          description:
            "The synchronizer token. A `POST` may send it as the `csrfToken` body field instead, never both.",
        },
      },
    },
    paths,
  }
}
