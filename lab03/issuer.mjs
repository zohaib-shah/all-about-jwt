// Has the PRIVATE key. Prints a token.  Usage: node lab03/issuer.mjs
import { readFile } from 'node:fs/promises';
import { importPKCS8, SignJWT } from 'jose';

const pem = await readFile(new URL('./keys/private.pem', import.meta.url), 'utf8');
const privateKey = await importPKCS8(pem, 'RS256');
console.log(await new SignJWT({ role: 'user' })
  .setProtectedHeader({ alg: 'RS256' })
  .setSubject('u1').setIssuer('https://auth.local').setAudience('orders-api')
  .setExpirationTime('15m')
  .sign(privateKey));
