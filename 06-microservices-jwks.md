# 06 - Microservices with JWKS

## Goal
Build an auth service plus two independent resource services that authenticate requests **without ever calling the auth service per request**.

## Architecture

```
             1. POST /auth/login       ┌──────────────┐
 Client ───────────────────────────►   │ auth :4000   │ holds PRIVATE keys
   │  ◄─────── access token (ES256)    │ /.well-known │
   │                                   │  /jwks.json  │
   │                                   └──────▲───────┘
   │ 2. Authorization: Bearer <jwt>           │ 3. fetch + cache public keys
   ├────────────────────────►┌────────────────┴──┐    (rarely, not per request)
   │                         │ orders :4001      │ aud = orders-api
   └────────────────────────►│ billing :4002     │ aud = billing-api
                             └───────────────────┘
```

Properties to appreciate:
- Resource services only know a **URL** (and an issuer name), not a secret.
- Verification is local CPU work (~0.1 ms); the auth service is **off the hot path**.
- Auth outage ≠ API outage: existing tokens keep working while cached keys and tokens are valid.
- Compromising `orders` does not let an attacker mint tokens.

## Concepts

### Trust boundaries
In a monolith there is one trust decision: "is this request from a logged-in user?" In a microservice system every service makes that decision independently, and the question becomes richer:

1. **Who issued this token?** → `iss` + signature via the issuer's JWKS.
2. **Is it meant for me?** → `aud`.
3. **Is it still valid?** → `exp`/`nbf` (and, in guide 07, revocation checks).
4. **What may the caller do here?** → `scope`/`roles` + the service's own rules.

Every service answers all four on every request. That is **zero trust** applied to service boundaries: being "inside the network" grants nothing.

### Why `aud` becomes critical
With many services trusting one issuer, every token is *cryptographically* valid everywhere. Without an audience check, a token minted for the low-risk `newsletter-api` could be replayed against `billing-api`. Worse, a malicious or compromised service that receives user tokens could reuse them against its neighbours (a **confused deputy**). One audience per service (or per group of services that genuinely share a trust level) contains that blast radius. The reference auth service only issues an audience the user is entitled to, with scopes **specific to that audience**.

### Scopes vs roles vs fine-grained permissions
| Concept | Example | Lives in | Answers |
|---|---|---|---|
| **Scope** | `orders:write` | token | what this *token* is allowed to be used for (delegated, coarse) |
| **Role** | `admin` | token or user DB | what kind of user this is |
| **Permission / ownership** | "may edit order #42" | the service's own data | the actual business rule |

Put coarse, stable facts in the token; keep fine-grained, fast-changing decisions in the service. A token is a snapshot that can be up to one TTL out of date. "Can Alice edit *this* order?" must be checked against current data.

### Service-to-service calls: whose identity?
When `orders` calls `billing` while serving Alice, it has two options:

| Approach | Token sent to billing | Good for |
|---|---|---|
| **Client credentials** (implemented here) | `orders`' own token: `sub=client:orders-svc`, `aud=billing-api`, `scope=billing:read` | "orders, as a system, may read invoices" |
| **Token exchange** (RFC 8693, stretch idea) | a new token for `billing-api` that says "orders acting on behalf of alice" | per-user authorization downstream |
| ~~Forwarding the user's token~~ | Alice's `orders-api` token | rejected by billing's `aud` check, and rightly so |

```
orders                         auth                          billing
  │ POST /oauth/token            │
  │ client_id + client_secret ──►│ check secret, narrow scopes
  │◄── access token (5m, cached) ┤
  │ GET /invoices  Bearer <svc token> ──────────────────────────►│ same jwtAuth middleware
  │◄──────────────────────────────────────────────────────── 200 ┤ caller = client:orders-svc
```

Internal calls go through **exactly the same verification path** as external ones. There is no "trusted internal network" shortcut.

### What is on the hot path
| Per request | Occasionally | Never |
|---|---|---|
| signature check (local CPU), claim checks, scope check | JWKS fetch (cache refresh / unknown `kid`), service-token fetch (cached until near expiry) | calling the auth service to validate a user token |

## Design decisions to make explicitly

| Question | Recommended answer |
|---|---|
| Audience | One `aud` per service (or a deliberate shared one). Reject tokens not meant for you. |
| Authorization data in token | Coarse: `scope`/`roles`. Fine-grained decisions stay in the service. |
| Issuer | One fixed `iss` string, pinned in every verifier. |
| Token lifetime | 5-15 min. |
| Service-to-service calls | Client-credentials tokens with their own `sub` and `scope`. |
| Token type | Mark access tokens with `typ: at+jwt` (RFC 9068) so they can't be confused with other JWTs (e.g. ID tokens). The reference auth service does this. |

## Lab

> **Reference implementation** (already includes the Redis features from guide 07, which switch on when a `redis` instance is passed; without it the code behaves exactly as described here):
>
> | Path | Role |
> |---|---|
> | [services/shared/auth-middleware.mjs](services/shared/auth-middleware.mjs) | `jwtAuth`, `requireScope`, `denylist`, `metrics` |
> | [services/shared/jwks-store.mjs](services/shared/jwks-store.mjs) | JWKS fetch + cache + kid-miss refetch + Redis fallback |
> | [services/shared/service-token.mjs](services/shared/service-token.mjs) | client-credentials token fetcher with cache |
> | [services/auth/](services/auth/) | `app.mjs` (routes), `keys.mjs` (key ring), `refresh-store.mjs`, `rate-limit.mjs`, `index.mjs` |
> | [services/orders/index.mjs](services/orders/index.mjs), [services/billing/index.mjs](services/billing/index.mjs) | resource services |

### Step 1: Shared verification package
Don't copy-paste middleware. Create `services/shared/auth-middleware.mjs`:

```js
import { createRemoteJWKSet, jwtVerify } from 'jose';

export function jwtAuth({ jwksUrl, issuer, audience, algorithms = ['ES256'] }) {
  const JWKS = createRemoteJWKSet(new URL(jwksUrl), { cooldownDuration: 10_000, cacheMaxAge: 5 * 60_000 });

  return async function authenticate(req, res, next) {
    const m = /^Bearer (.+)$/.exec(req.get('authorization') ?? '');
    if (!m) return res.status(401).set('WWW-Authenticate', 'Bearer').json({ error: 'missing_token' });
    try {
      const { payload } = await jwtVerify(m[1], JWKS, { issuer, audience, algorithms, clockTolerance: 5 });
      req.auth = payload;
      next();
    } catch (e) {
      res.status(401).set('WWW-Authenticate', `Bearer error="invalid_token"`)
         .json({ error: 'invalid_token', reason: e.code });   // reason: log it; consider omitting in prod
    }
  };
}

export const requireScope = (...needed) => (req, res, next) => {
  const have = new Set(String(req.auth.scope ?? '').split(' '));
  return needed.every((s) => have.has(s)) ? next() : res.status(403).json({ error: 'insufficient_scope', needed });
};
```

### Step 2: Auth service (`services/auth/app.mjs`)
Reuse the key ring and JWKS endpoint from guide 05, and extend token issuance:
- Accept `{ username, password, audience }` at `POST /auth/login`.
- Only issue an audience the user is allowed (`orders-api`, `billing-api`), with **scopes per audience**, space-separated (OAuth style).
- Keep `iss` fixed (`http://localhost:4000`), set `kid` in the header, `jti` and `exp` (5 min) in the claims.

Seed data in the reference implementation:

| User | `orders-api` scopes | `billing-api` scopes |
|---|---|---|
| alice | `orders:read orders:write` | `billing:read billing:write` |
| bob | `orders:read` | *(none)* |

| Service client | Allowed audience → scopes |
|---|---|
| `orders-svc` (secret `orders-secret`) | `billing-api` → `billing:read` |

> **Why the repo's middleware takes a `store` instead of a `jwksUrl`:** the simple version above calls `createRemoteJWKSet`, which keeps its cache only in process memory. The reference code wraps JWKS handling in a `JwksStore` (see guide 07, Lab 4) that also persists the last good JWKS to Redis, refreshes on a timer and on a pub/sub nudge, rate-limits refetches on unknown `kid`, and **refuses any JWKS containing private-key fields**. The calling code is the same shape: `jwtVerify(token, store.getKey, {...})`.

### Step 3: Orders service (`services/orders/index.mjs`)
```js
import express from 'express';
import { jwtAuth, requireScope } from '../shared/auth-middleware.mjs';

const app = express();
app.use(jwtAuth({
  jwksUrl: 'http://localhost:4000/.well-known/jwks.json',
  issuer: 'http://localhost:4000',
  audience: 'orders-api',
}));

app.get('/orders', requireScope('orders:read'), (req, res) =>
  res.json({ user: req.auth.sub, orders: [{ id: 1 }, { id: 2 }] }));
app.post('/orders', requireScope('orders:write'), express.json(), (req, res) =>
  res.status(201).json({ id: 3, createdBy: req.auth.sub }));

app.listen(4001, () => console.log('orders on :4001'));
```

### Step 4: Billing service
Copy orders to port 4002 with `audience: 'billing-api'` and a `billing:read` scope route.

### Step 5: Prove the properties

Start everything (Redis first; see guide 00):
```bash
npm run auth & npm run orders & npm run billing &
```
Quick manual run:
```bash
login() { curl -s localhost:4000/auth/login -H 'content-type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"pw\",\"audience\":\"$2\"}" | jq -r .access_token; }

A=$(login alice orders-api)
curl -s localhost:4001/orders -H "authorization: Bearer $A"                       # 200
curl -s -X POST localhost:4001/orders -H "authorization: Bearer $(login bob orders-api)"   # 403
curl -s localhost:4002/invoices -H "authorization: Bearer $A"                     # 401 (wrong aud)
curl -s localhost:4001/orders/7/invoice -H "authorization: Bearer $A"             # orders -> billing via service token
```

Then work through these, by hand first. The same checks, automated, are in `test/acceptance.test.mjs` (`npm test`).

1. Get a token for `orders-api`; call orders → 200; call billing → **401** (wrong `aud`).
2. Token without `orders:write` → `POST /orders` → 403.
3. **Kill the auth service.** Existing tokens still work on orders (cached JWKS). Restart orders while auth is down, what happens? (Cold-start dependency, solved in 07 with Redis / a persisted cache.)
4. Run key rotation from guide 05 while a load loop hits orders continuously (~20 req/s; see the rotation test in `test/acceptance.test.mjs`). Count failures. Target: zero.

## Handling failure modes
- **JWKS endpoint down at cold start** → verifier can't verify. Mitigations: fetch on boot with retry, persist last-known JWKS to disk/Redis, health check that fails readiness until keys loaded.
- **Clock skew** → `clockTolerance` of a few seconds; run NTP.
- **Large fan-out of unknown `kid`** (attacker sends random kids) → `cooldownDuration` prevents hammering the auth service.

## Service-to-service tokens
Implemented in the reference code (`POST /oauth/token` in `services/auth/app.mjs`, `serviceTokenClient` in `services/shared/service-token.mjs`, `GET /orders/:id/invoice` in orders). Try building it yourself first.

Add `POST /oauth/token` with `grant_type=client_credentials` and a client id/secret table. Issue tokens where `sub = client:orders-svc`, `aud = billing-api`, `scope = billing:read`. Make orders call billing with that token. Now your internal calls use the same verification path.

## Exercises
1. Add a gateway on :8080 that verifies once and forwards `x-user-id` headers, and have services trust only the gateway. Discuss: what new risk appears? (Header spoofing if services are reachable directly. Zero trust says: still verify in each service.)
2. Add an `azp`/`client_id` claim and log it on every request.
3. Implement structured audit logs: `{ sub, jti, route, decision }` per request.
4. Write an integration test script (`node --test`) that spins up all three services and asserts the matrix: token × audience × scope → status code.

## Checkpoint questions
- What does each resource service need to know to verify a token?
- Why is `aud` essential when many services trust the same issuer?
- How does key rotation stay invisible to clients?
- What is the one thing JWKS-based verification cannot do for you? (Revocation. See 07.)
