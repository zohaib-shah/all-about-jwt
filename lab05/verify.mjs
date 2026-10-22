// Usage: node lab05/verify.mjs <token>   (auth must be running on :4000)
import { createRemoteJWKSet, jwtVerify } from 'jose';

const JWKS = createRemoteJWKSet(new URL('http://localhost:4000/.well-known/jwks.json'), {
  cooldownDuration: 10_000, // min time between refetches on kid miss
  cacheMaxAge: 60_000,
});

const { payload, protectedHeader } = await jwtVerify(process.argv[2], JWKS, {
  issuer: 'http://localhost:4000', audience: 'demo-api', algorithms: ['ES256'],
});
console.log(protectedHeader, payload);
