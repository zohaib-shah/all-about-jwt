import { readFile } from 'node:fs/promises';
import { importPKCS8, importSPKI, SignJWT, jwtVerify } from 'jose';

const privateKey = await importPKCS8(await readFile('keys/private.pem', 'utf8'), 'RS256');
const publicKey  = await importSPKI(await readFile('keys/public.pem', 'utf8'), 'RS256');

const jwt = await new SignJWT({ role: 'user' })
  .setProtectedHeader({ alg: 'RS256' })
  .setJti("1234")
  .setSubject('u1').setIssuer('https://auth.local').setAudience('orders-api')
  .setExpirationTime('15m')
  .sign(privateKey);

const { payload, protectedHeader } = await jwtVerify(jwt, publicKey, {
  algorithms: ['RS256'], issuer: 'https://auth.local', audience: 'orders-api',
});
console.log(protectedHeader, payload);
console.log('token length', jwt.length);