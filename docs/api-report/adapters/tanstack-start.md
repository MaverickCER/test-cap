# adapters/tanstack-start

test-cap/tanstack-start: the TanStack Start adapter (ADR 0024). It converts and decides nothing:

- `tanstackStartMiddleware(auth, { public })` is the server function of a global request middleware. TanStack
  Start runs it for every request, pages, server routes and server function calls alike. It sends the request's
  head to the core's gate, which refuses an ambiguous path with a 400 and applies deny by default with the public
  list; a refusal is answered here, and every other request continues with `context.auth` set.
- `tanstackStartAuth(auth).handlers` serves the `/auth/$` server route: the body is read here, once, as bytes, and
  goes to `auth.handle`.
- `tanstackStartAuth(auth).require` and `.session` let a server function check a requirement itself, close to the
  data, and answer with the core's outcome.

TanStack Start is typed structurally, so this entry has no dependency on it.

## Interfaces

### TanstackStartAuth

What `tanstackStartAuth` returns.

#### Type Parameters

| Type Parameter |
| ------ |
| `Id` *extends* `string` |

#### Properties

##### handlers

```ts
readonly handlers: TanstackStartRouteHandlers;
```

The `/auth/$` server route's handlers.

#### Methods

##### require()

```ts
require(request, requirementId): Promise<RequireResult>;
```

Whether the request's session meets the requirement under `requirementId`, as one of five outcomes.

###### Parameters

| Parameter | Type |
| ------ | ------ |
| `request` | `Request` |
| `requirementId` | `Id` |

###### Returns

`Promise`\<[`RequireResult`](../index.md#requireresult)\>

##### session()

```ts
session(request): Promise<SessionInfo | null>;
```

The request's session, read from the store; `null` when it has none, or it is revoked or expired.

###### Parameters

| Parameter | Type |
| ------ | ------ |
| `request` | `Request` |

###### Returns

`Promise`\<[`SessionInfo`](../index.md#sessioninfo) \| `null`\>

***

### TanstackStartContext

The context the middleware adds for the routes and server functions after it.

#### Properties

##### auth

```ts
readonly auth: TanstackStartAuthInfo;
```

The subject deny by default let through, or `null`.

***

### TanstackStartMiddlewareInput

The parts of TanStack Start's request middleware options the adapter reads.

#### Type Parameters

| Type Parameter |
| ------ |
| `Next` |

#### Properties

##### next

```ts
readonly next: (options) => Next;
```

Continues to the next middleware, the route or the server function, with the adapter's context added.

###### Parameters

| Parameter | Type |
| ------ | ------ |
| `options` | \{ `context`: [`TanstackStartContext`](#tanstackstartcontext); \} |
| `options.context` | [`TanstackStartContext`](#tanstackstartcontext) |

###### Returns

`Next`

##### request

```ts
readonly request: Request;
```

The request as TanStack Start received it.

***

### TanstackStartMiddlewareOptions

What `tanstackStartMiddleware` takes.

#### Properties

##### public?

```ts
readonly optional public?: readonly string[];
```

The paths that need no session. An entry matches exactly (`"/"` is the root only), or ends in `/*` to match one or
more segments below it (`"/blog/*"`). Matching is case-sensitive. Everything else needs the default requirement,
server function calls included.

***

### TanstackStartRouteHandlers

The handlers for the `/auth/$` server route.

#### Properties

##### ANY

```ts
readonly ANY: TanstackStartRouteHandler;
```

Every method: the core answers a method a route does not take with a 405.

## Type Aliases

### TanstackStartAuthInfo

```ts
type TanstackStartAuthInfo = 
  | {
  subject: string;
}
  | null;
```

What `context.auth` holds: the subject on a protected route, `null` on a public one and under `/auth/`.

#### Union Members

##### Type Literal

```ts
{
  subject: string;
}
```

###### subject

```ts
readonly subject: string;
```

The account the request's session belongs to.

***

`null`

***

### TanstackStartMiddleware

```ts
type TanstackStartMiddleware = <Next>(input) => Promise<Awaited<Next> | Response>;
```

The server function of a request middleware: a refusal as a `Response`, or whatever `next` answered.

#### Type Parameters

| Type Parameter |
| ------ |
| `Next` |

#### Parameters

| Parameter | Type |
| ------ | ------ |
| `input` | [`TanstackStartMiddlewareInput`](#tanstackstartmiddlewareinput)\<`Next`\> |

#### Returns

`Promise`\<`Awaited`\<`Next`\> \| `Response`\>

***

### TanstackStartRouteHandler

```ts
type TanstackStartRouteHandler = (input) => Promise<Response>;
```

A server route handler: TanStack Start passes more than the request, and the adapter reads only the request.

#### Parameters

| Parameter | Type | Description |
| ------ | ------ | ------ |
| `input` | \{ `request`: `Request`; \} | - |
| `input.request` | `Request` | The request as TanStack Start received it. |

#### Returns

`Promise`\<`Response`\>

## Functions

### tanstackStartAuth()

```ts
function tanstackStartAuth<Id>(auth): TanstackStartAuth<Id>;
```

The `/auth/$` server route and the server helpers. Serve the route with
`server: { handlers: tanstackStartAuth(auth).handlers }`.

#### Type Parameters

| Type Parameter |
| ------ |
| `Id` *extends* `string` |

#### Parameters

| Parameter | Type |
| ------ | ------ |
| `auth` | [`Auth`](../index.md#auth)\<`Id`\> |

#### Returns

[`TanstackStartAuth`](#tanstackstartauth)\<`Id`\>

***

### tanstackStartMiddleware()

```ts
function tanstackStartMiddleware(auth, options?): TanstackStartMiddleware;
```

The global request middleware's server function: protects every route and server function at the default
requirement unless `options.public` lists its path. Register it with
`createStart(() => ({ requestMiddleware: [createMiddleware().server(tanstackStartMiddleware(auth, options))] }))`.

#### Parameters

| Parameter | Type |
| ------ | ------ |
| `auth` | [`Auth`](../index.md#auth)\<`string`\> |
| `options` | [`TanstackStartMiddlewareOptions`](#tanstackstartmiddlewareoptions) |

#### Returns

[`TanstackStartMiddleware`](#tanstackstartmiddleware)
