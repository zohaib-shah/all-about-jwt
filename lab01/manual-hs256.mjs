import { createHmac } from 'node:crypto';
import { jwtVerify } from 'jose';

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const secret = 'demo-secret-demo-secret-demo-secret!';

const header = b64u({ alg: 'HS256', typ: 'JWT' });
const payload = b64u({ sub: 'user-1', exp: Math.floor(Date.now() / 1000) + 300 });
const sig = createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');

const token = `${header}.${payload}.${sig}`;
console.log(token);

// a hand-made token must verify with a real library
const { payload: p } = await jwtVerify(token, new TextEncoder().encode(secret), { algorithms: ['HS256'] });
console.log('jose verified it:', p);
