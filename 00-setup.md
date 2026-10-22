# 00 - Setup

## Goal
A working Node project, the tools to inspect tokens, and Redis available for later.

## Prerequisites
- Node.js 20+ (`node -v`)
- `curl` and optionally `jq`
- Docker (for Redis in guide 07). Alternative: `brew install redis`.

## Steps

### 1. Initialise the project
```bash
cd jwt-handson
npm init -y
npm pkg set type=module
npm i jose express ioredis cookie-parser
npm i -D nodemon
```

Versions this course was verified with: Node 24, `jose` 6, `express` 5, `ioredis` 6. (Express 5 and ioredis 6 are newer than most tutorials; if a snippet elsewhere misbehaves, check these first.)

Add these scripts to `package.json` (they are used from guide 06 onward):
```bash
npm pkg set scripts.dev=nodemon \
  scripts.auth="node services/auth/index.mjs" \
  scripts.orders="node services/orders/index.mjs" \
  scripts.billing="node services/billing/index.mjs" \
  scripts.attacks="node lab08/attacks.mjs" \
  scripts.test="node --test test/middleware.test.mjs test/acceptance.test.mjs lab02/server.test.mjs lab04/server.test.mjs"
```
> Node 24 treats `node --test test/` as a module path, so list test files explicitly.

### 2. Folder per lab
```bash
mkdir lab01 lab02 lab03 lab04 lab05 lab07 lab08 tools test
mkdir -p services/auth services/orders services/billing services/shared
```

Create a `.gitignore` (habit matters even in training):
```
node_modules/
*.pem
.env
jar.txt
stolen.txt
```

### 3. Tools for inspecting tokens
- Browser: <https://jwt.io> (paste **only fake tokens** from this course; never real production tokens).
- CLI helper: save as `tools/decode.mjs` and use `node tools/decode.mjs <token>`:

```js
import { decodeJwt, decodeProtectedHeader } from 'jose';
const t = process.argv[2];
console.log('header ', decodeProtectedHeader(t));
console.log('payload', decodeJwt(t));
```

> `decode` does **not** verify anything. Remember this; it is the root of many bugs.

### 4. Sanity check
```js
// lab01/hello.mjs
import { SignJWT, jwtVerify } from 'jose';
const key = new TextEncoder().encode('demo-secret-demo-secret-demo-secret!');
const jwt = await new SignJWT({ hello: 'world' })
  .setProtectedHeader({ alg: 'HS256' })
  .setExpirationTime('5m')
  .sign(key);
console.log(jwt);
console.log((await jwtVerify(jwt, key)).payload);
```
Run `node lab01/hello.mjs`. You should see a token and `{ hello: 'world', exp: ... }`.

### 5. Redis (needed from guide 07)
```bash
cat > docker-compose.yml <<'EOF'
services:
  redis:
    image: redis:7
    ports: ["6379:6379"]
    command: ["redis-server", "--appendonly", "yes"]
EOF
docker compose up -d redis
docker compose exec redis redis-cli ping    # PONG
```
On macOS make sure Docker Desktop is running first (`open -a Docker`), otherwise `docker compose` fails with "Cannot connect to the Docker daemon".

## Checkpoint
- Can you run the script and see the payload?
- Can you explain why `decodeJwt` is not enough to trust a token? (Answer in guide 01.)
