# adapters/express

test-cap/express: the Express adapter (ADR 0024). It converts and decides nothing:

- every request first goes to the core's gate, which refuses an ambiguous path with a 400 and applies deny by
  default with the public list this adapter passes it;
- a request under `/auth/` has its body read here, from the raw stream, never from `req.body`, and goes to
  `auth.handle`; when a body parser already consumed the stream, the request fails closed with a 500;
- every other request continues to the app with `req.auth` set, and its stream untouched for the app's own parsers.

Express is typed structurally, so this entry has no dependency on it.

## Interfaces

### ExpressAuthOptions

What `expressAuth` takes.

#### Properties

##### public?

```ts
readonly optional public?: readonly string[];
```

The paths that need no session. An entry matches exactly (`"/"` is the root only), or ends in `/*` to match one or
more segments below it (`"/blog/*"`). Matching is case-sensitive. Everything else needs the default requirement.

***

### ExpressLikeRequest

The parts of an Express (Node) request the adapter reads.

#### Properties

##### auth?

```ts
optional auth?: ExpressAuthInfo;
```

Set by the adapter.

##### body?

```ts
readonly optional body?: unknown;
```

Set by a body parser; its presence means the stream is no longer the core's to read.

##### method?

```ts
readonly optional method?: string;
```

The HTTP method as received.

##### originalUrl?

```ts
readonly optional originalUrl?: string;
```

Express's unrewritten URL; the adapter prefers it to `url`.

##### rawHeaders

```ts
readonly rawHeaders: readonly string[];
```

Every header line as received, name and value alternating.

##### readableEnded

```ts
readonly readableEnded: boolean;
```

True once something has read the whole body stream.

##### socket

```ts
readonly socket: {
  remoteAddress?: string;
};
```

The socket the request came in on.

###### remoteAddress?

```ts
readonly optional remoteAddress?: string;
```

The peer's address, never a forwarded header (ADR 0009).

##### url?

```ts
readonly optional url?: string;
```

The request target; `originalUrl` wins when Express has rewritten it.

#### Methods

##### on()

###### Call Signature

```ts
on(event, listener): unknown;
```

Receives one chunk of the raw body.

###### Parameters

| Parameter | Type |
| ------ | ------ |
| `event` | `"data"` |
| `listener` | (`chunk`) => `void` |

###### Returns

`unknown`

###### Call Signature

```ts
on(event, listener): unknown;
```

The body has been read whole.

###### Parameters

| Parameter | Type |
| ------ | ------ |
| `event` | `"end"` |
| `listener` | () => `void` |

###### Returns

`unknown`

###### Call Signature

```ts
on(event, listener): unknown;
```

The stream failed.

###### Parameters

| Parameter | Type |
| ------ | ------ |
| `event` | `"error"` |
| `listener` | (`error`) => `void` |

###### Returns

`unknown`

##### pause()

```ts
pause(): unknown;
```

Stops reading the body.

###### Returns

`unknown`

***

### ExpressLikeResponse

The parts of an Express (Node) response the adapter writes.

#### Properties

##### statusCode

```ts
statusCode: number;
```

The status to send.

##### writableFinished

```ts
readonly writableFinished: boolean;
```

True once the whole response has been handed to the socket.

#### Methods

##### end()

```ts
end(body?): unknown;
```

Sends the body, if any, and ends the response.

###### Parameters

| Parameter | Type |
| ------ | ------ |
| `body?` | `Uint8Array`\<`ArrayBufferLike`\> |

###### Returns

`unknown`

##### once()

```ts
once(event, listener): unknown;
```

The connection closed, before or after the response finished.

###### Parameters

| Parameter | Type |
| ------ | ------ |
| `event` | `"close"` |
| `listener` | () => `void` |

###### Returns

`unknown`

##### setHeader()

```ts
setHeader(name, value): unknown;
```

Sets one header; an array writes one line per value.

###### Parameters

| Parameter | Type |
| ------ | ------ |
| `name` | `string` |
| `value` | `string` \| readonly `string`[] |

###### Returns

`unknown`

## Type Aliases

### ExpressAuthInfo

```ts
type ExpressAuthInfo = 
  | {
  subject: string;
}
  | null;
```

What `req.auth` holds: the subject on a protected route, `null` on a public one.

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

### ExpressAuthMiddleware

```ts
type ExpressAuthMiddleware = (req, res, next) => void;
```

An Express middleware.

#### Parameters

| Parameter | Type |
| ------ | ------ |
| `req` | [`ExpressLikeRequest`](#expresslikerequest) |
| `res` | [`ExpressLikeResponse`](#expresslikeresponse) |
| `next` | (`error?`) => `void` |

#### Returns

`void`

## Functions

### expressAuth()

```ts
function expressAuth(auth, options?): ExpressAuthMiddleware;
```

Mounts test-cap on an Express app: serves `/auth/*` and protects every other route at the default requirement
unless `options.public` lists it. Mount it before any body parser.

#### Parameters

| Parameter | Type |
| ------ | ------ |
| `auth` | [`Auth`](../index.md#auth)\<`string`\> |
| `options` | [`ExpressAuthOptions`](#expressauthoptions) |

#### Returns

[`ExpressAuthMiddleware`](#expressauthmiddleware)
