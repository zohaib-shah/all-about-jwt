# JWT Hands-On Training (Node.js)

A practical, lab-driven course on JSON Web Tokens: from raw token anatomy to a multi-service architecture using JWKS and Redis.

Each guide explains the concepts first, then has you build them in a lab, then attack what you built. A complete reference implementation (labs, three services, 36 automated tests) is included so you can compare against it when you're stuck. Try each lab yourself before you open the reference code.

> ⚠️ **Educational code, not a production auth server.** It ships with demo credentials (`alice`/`pw`, `orders-secret`, `dev-admin`), a toy user store and HTTP on localhost. The services bind to `127.0.0.1` and Redis to loopback by default. Keep it that way. Use the patterns, not the code, in real systems.

New to the vocabulary? Keep the [glossary](GLOSSARY.md) open alongside the guides.

## Roadmap

| # | Guide | You will learn | Time |
|---|-------|----------------|------|
| 00 | [Setup](00-setup.md) | Tooling, project layout, conventions | 20 min |
| 01 | [JWT fundamentals](01-jwt-fundamentals.md) | Why tokens exist, anatomy, claims, what "verify" really means | 60 min |
| 02 | [Symmetric signing (HS256)](02-symmetric-hs256.md) | Shared secrets, sign/verify, tampering attacks | 60 min |
| 03 | [Asymmetric signing (RS256/ES256/EdDSA)](03-asymmetric-rs256.md) | Key pairs, public verification, algorithm choice | 60 min |
| 03a | [Algorithms explained](03a-algorithms-explained.md) | HS/RS/PS/ES/EdDSA compared, JWK mapping, benchmark lab | 40 min |
| 04 | [Access + refresh tokens](04-access-refresh-tokens.md) | Short-lived tokens, rotation, cookies | 75 min |
| 05 | [JWKS](05-jwks.md) | Publishing keys, `kid`, key rotation | 60 min |
| 06 | [Microservices with JWKS](06-microservices-jwks.md) | Auth service + independent resource services | 90 min |
| 07 | [Redis in the ecosystem](07-redis.md) | Revocation, refresh store, JWKS cache, rate limits | 90 min |
| 08 | [Security pitfalls & checklist](08-security-pitfalls.md) | Attacks, hardening, review checklist | 45 min |
| 09 | [Capstone](09-capstone.md) | Put everything together, with acceptance tests | 2-3 h |

Do them in order; each builds on the previous one.

## Learning path at a glance

```
HS256 (one shared secret)
   │  problem: every verifier can also forge tokens
   ▼
RS256/ES256 (private signs, public verifies)
   │  problem: how do services get/rotate the public key?
   ▼
JWKS (publish public keys at a URL, identify by kid)
   │  problem: JWTs can't be revoked; refresh tokens need state
   ▼
Redis (denylist, refresh-token store, caches, rate limits)
```

## Conventions

- Node.js **20+**, ESM (`"type": "module"`).
- Library: [`jose`](https://github.com/panva/jose) (works with every algorithm and JWKS). Express for HTTP.
- Each guide has: **Goal → Concepts → Lab → Exercises → Checkpoint questions**.
- "Try to break it" sections are not optional. Attacking your own code is how this sticks.
- Never use the demo secrets/keys from this course in real systems.

## Final folder layout (what you will have built)

```
jwt-handson/
├── package.json
├── lab01/ ... lab05/          # small standalone scripts
├── services/
│   ├── auth/                  # issues tokens, serves /.well-known/jwks.json
│   ├── orders/                # resource service, verifies via JWKS
│   └── billing/               # second resource service
└── docker-compose.yml         # redis (and optionally the services)
```

## Running the finished code

Everything in the guides is implemented in this repo.

```bash
npm install
docker compose up -d redis          # needed for guide 07 / capstone

node lab01/exercises.mjs            # guide 01
node lab02/attacks.mjs              # guide 02 (also: lab02/crack.mjs, lab02/server.mjs)
node lab03/compare-algs.mjs         # guides 03/03a (also: issuer.mjs, verifier.mjs, confusion.mjs)
node lab04/theft.mjs                # guide 04 (also: client.mjs, server.mjs)
node lab05/rotation-drill.mjs       # guide 05
node lab07/demo.mjs                 # guide 07 Redis demos

npm run auth & npm run orders & npm run billing &   # guides 06/07/09 services on :4000-4002
npm run attacks                     # guide 08 attack suite against the live services

npm test                            # unit + acceptance suites (needs Redis; uses DB 15)
```

Layout notes: `services/auth/app.mjs` (routes), `services/shared/` (JWKS store, middleware, Redis, service tokens). Self-review: [REVIEW.md](REVIEW.md).
