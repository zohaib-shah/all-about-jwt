import { SignJWT } from 'jose';

const key = new TextEncoder().encode('demo-secret-demo-secret-demo-secret!');
const token = await new SignJWT({ role: 'admin' })
  .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
  .setSubject('user-42')
  .setIssuer('https://auth.local')
  .setAudience('orders-api')
  .setIssuedAt()
  .setExpirationTime('15m')
  .setJti(crypto.randomUUID())
  .sign(key);

const [h, p, s] = token.split('.');
const decode = (b64u) => JSON.parse(Buffer.from(b64u, 'base64url').toString());

console.log('token  :', token);
console.log('header :', decode(h));
console.log('payload:', decode(p));
console.log('sig    :', s, `(${Buffer.from(s, 'base64url').length} bytes)`);
