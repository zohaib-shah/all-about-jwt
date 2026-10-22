# Glossary

Quick definitions of the terms used across the guides. The number in brackets is the guide that explains it in depth.

| Term | Meaning |
|---|---|
| **Access token** | Short-lived credential sent with every API call; here a JWT. [04] |
| **`alg`** | Header field naming the signature algorithm. Verifiers must pin the allowed values, never trust the header. [01, 03] |
| **Algorithm confusion** | Attack where an RSA/EC public key is used as an HMAC secret because the verifier let the token pick `alg`. [03] |
| **`aud` (audience)** | Claim naming the service(s) a token is for. Each verifier checks it contains itself. [01, 06] |
| **Authentication / Authorization** | *Who are you?* / *What may you do?* 401 vs 403. [01] |
| **base64url** | URL-safe base64 without padding; encoding, not encryption. [01] |
| **Bearer token** | Whoever holds it can use it, like cash. [01] |
| **BFF (backend-for-frontend)** | Server component that holds tokens on behalf of a browser app, which keeps only a session cookie. [04] |
| **Claim** | A statement in the payload (`sub`, `exp`, `scope`, …). [01] |
| **Client credentials** | OAuth grant where a *service* authenticates with its own id/secret to get a token. [06] |
| **Clock tolerance (leeway)** | Seconds of skew allowed when checking `exp`/`nbf`. [01] |
| **Confused deputy** | A trusted service tricked into using its authority (or a user's token) for someone else. [06] |
| **CSRF** | Another site makes the browser send requests with your cookies. Defended by `SameSite`, Origin checks. [04] |
| **Denylist** | Set of revoked token ids (`jti`), each stored until the token would expire anyway. [07] |
| **Fail-open / fail-closed** | When a dependency (Redis) is down: allow the request, or refuse it. [07] |
| **Family (refresh)** | All refresh tokens descended from one login; revoked together on reuse. [04] |
| **HMAC** | Keyed hash used by HS256/384/512; same secret signs and verifies. [02] |
| **`iat` / `exp` / `nbf`** | Issued-at / expiry / not-before, as NumericDate (seconds since epoch). [01] |
| **`iss` (issuer)** | Who minted the token; verifiers pin the exact value. [01] |
| **JOSE** | The family of specs: JWS, JWE, JWK, JWA, JWT. [01] |
| **`jti`** | Unique token id; the handle for revocation. [07] |
| **JWK / JWKS** | A key as JSON / a set of them, published at `/.well-known/jwks.json`. [05] |
| **JWK thumbprint** | SHA-256 of a key's public parameters (RFC 7638); used here as the `kid`. [05] |
| **JWS / JWE** | Signed / encrypted JOSE object. Everyday "JWT" = JWS with JSON claims. [01] |
| **`jku` / `x5u` / `jwk` header** | Header fields that point to or embed a key. Ignore them: attacker-controlled. [08] |
| **`kid`** | Key id in the header; selects the verification key from the JWKS. Untrusted input. [05] |
| **Key rotation** | Replacing signing keys: publish → switch → retire. [05] |
| **NumericDate** | Seconds (not ms) since 1970-01-01 UTC. [01] |
| **Opaque token** | Random reference string with no readable content; looked up server-side. [04] |
| **PKCS#8 / SPKI / PEM** | Private-key / public-key encodings; PEM is their base64 text form. [03] |
| **Refresh token** | Long-lived, stateful credential used only to get new access tokens. [04] |
| **Reuse detection** | Presenting an already-used refresh token revokes its whole family. [04] |
| **Scope** | Space-separated permissions carried by a token (`orders:read`). [06] |
| **`sub` (subject)** | Whom the token is about: a user id, or `client:<id>` for services. [01] |
| **TOCTOU** | Time-of-check/time-of-use race; why refresh consumption is an atomic Lua script. [07] |
| **TTL** | Time to live; Redis keys expire automatically, aligned with token lifetimes. [07] |
| **Watermark (`valid-after`)** | Per-user timestamp; tokens issued at or before it are rejected ("log out everywhere"). [07] |
| **XSS** | Attacker JavaScript running in your page; why tokens don't belong in `localStorage`. [04] |
| **Zero trust** | Every service verifies every request; the network location grants nothing. [06] |
