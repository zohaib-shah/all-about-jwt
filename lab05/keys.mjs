import { generateKeyPair, exportJWK, calculateJwkThumbprint } from 'jose';

export const ALGORITHM = 'ES256';
const ring = []; // [{ kid, privateKey, publicJwk, createdAt }]
let signingKid = null;

export async function addKey({ activate = false } = {}) {
  const { privateKey, publicKey } = await generateKeyPair(ALGORITHM, { extractable: true });
  const jwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(jwk); // stable, derived from the key itself
  ring.push({ kid, privateKey, publicJwk: { ...jwk, kid, alg: ALGORITHM, use: 'sig' }, createdAt: Date.now() });
  if (activate || !signingKid) signingKid = kid;
  return kid;
}

export const activate = (kid) => {
  if (!ring.some((k) => k.kid === kid)) throw new Error('unknown kid');
  signingKid = kid;
};
export const retire = (kid) => {
  if (kid === signingKid) throw new Error('cannot retire the active signing key');
  const i = ring.findIndex((k) => k.kid === kid);
  if (i >= 0) ring.splice(i, 1);
};
export const signingKey = () => ring.find((k) => k.kid === signingKid);
export const jwks = () => ({ keys: ring.map((k) => k.publicJwk) });
