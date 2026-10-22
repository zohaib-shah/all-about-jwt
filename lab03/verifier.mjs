// Has ONLY the public key. Usage: node lab03/verifier.mjs <token>
import { readFile } from 'node:fs/promises';
import { importSPKI, SignJWT, jwtVerify } from 'jose';

const pem = await readFile(new URL('./keys/public.pem', import.meta.url), 'utf8');
const publicKey = await importSPKI(pem, 'RS256');

const { payload } = await jwtVerify(process.argv[2], publicKey, {
  algorithms: ['RS256'], issuer: 'https://auth.local', audience: 'orders-api',
});
console.log('VERIFIED', payload);

// The verifier cannot mint tokens:
try {
  await new SignJWT({ role: 'admin' }).setProtectedHeader({ alg: 'RS256' }).sign(publicKey);
} catch (e) {
  console.log('cannot sign with public key ->', e.message);
}
