import { generateKeyPair, exportJWK, importJWK, calculateJwkThumbprint } from 'jose';
import { readFile, writeFile } from 'node:fs/promises';

export const ALGORITHM = 'ES256';
const PUBLIC_FIELDS = ['kty', 'crv', 'x', 'y'];

/** Key ring with optional on-disk persistence (private JWKs, mode 0600) so restarts don't invalidate tokens. */
export function createKeyRing({ file = null } = {}) {
  const ring = []; // { kid, privateKey, privateJwk, publicJwk, createdAt }
  let signingKid = null;

  const toEntry = async (privateJwk, createdAt = Date.now()) => {
    const publicJwk = Object.fromEntries(PUBLIC_FIELDS.map((f) => [f, privateJwk[f]]).filter(([, v]) => v));
    const kid = await calculateJwkThumbprint(publicJwk);
    return {
      kid, privateJwk, createdAt,
      privateKey: await importJWK(privateJwk, ALGORITHM),
      publicJwk: { ...publicJwk, kid, alg: ALGORITHM, use: 'sig' },
    };
  };

  const save = async () => {
    if (!file) return;
    const data = { signingKid, keys: ring.map((k) => ({ privateJwk: k.privateJwk, createdAt: k.createdAt })) };
    await writeFile(file, JSON.stringify(data), { mode: 0o600 });
  };

  return {
    async init() {
      if (file) {
        try {
          const data = JSON.parse(await readFile(file, 'utf8'));
          for (const k of data.keys) ring.push(await toEntry(k.privateJwk, k.createdAt));
          signingKid = data.signingKid;
        } catch { /* first run */ }
      }
      if (!ring.length) await this.add({ activate: true });
      return this;
    },
    async add({ activate = false } = {}) {
      const { privateKey } = await generateKeyPair(ALGORITHM, { extractable: true });
      const e = await toEntry(await exportJWK(privateKey));
      ring.push(e);
      if (activate || !signingKid) signingKid = e.kid;
      await save();
      return e.kid;
    },
    async activate(kid) {
      if (!ring.some((k) => k.kid === kid)) throw new Error('unknown kid');
      signingKid = kid;
      await save();
    },
    async retire(kid) {
      if (kid === signingKid) throw new Error('cannot retire the active signing key');
      const i = ring.findIndex((k) => k.kid === kid);
      if (i >= 0) ring.splice(i, 1);
      await save();
    },
    signingKey: () => ring.find((k) => k.kid === signingKid),
    jwks: () => ({ keys: ring.map((k) => k.publicJwk) }),
    list: () => ring.map((k) => ({ kid: k.kid, active: k.kid === signingKid, createdAt: k.createdAt })),
  };
}
