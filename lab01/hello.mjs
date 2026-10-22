import { SignJWT, jwtVerify } from 'jose';
const key = new TextEncoder().encode('demo-secret-demo-secret-demo-secret!');
const jwt = await new SignJWT({ hello: 'world' })
  .setProtectedHeader({ alg: 'HS256' })
  .setExpirationTime('5m')
  .sign(key);
console.log(jwt);
console.log((await jwtVerify(jwt, key)).payload);
