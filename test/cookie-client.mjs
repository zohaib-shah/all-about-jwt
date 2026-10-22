// Tiny cookie-jar fetch client for demos/tests (browser stand-in)
export class Client {
  constructor(base) { this.base = base; this.cookies = {}; this.access = null; }
  clone() { const c = new Client(this.base); c.cookies = { ...this.cookies }; return c; }
  async fetch(path, opts = {}) {
    const headers = { ...(opts.headers ?? {}) };
    const cookie = Object.entries(this.cookies).map(([k, v]) => `${k}=${v}`).join('; ');
    if (cookie && path.startsWith('/auth')) headers.cookie = cookie; // cookie Path=/auth
    if (this.access && !headers.authorization) headers.authorization = `Bearer ${this.access}`;
    const res = await fetch(this.base + path, { ...opts, headers });
    for (const sc of res.headers.getSetCookie?.() ?? []) {
      const [pair, ...attrs] = sc.split(';');
      const [k, v] = pair.split('=');
      if (/max-age=0|expires=thu, 01 jan 1970/i.test(attrs.join(';'))) delete this.cookies[k];
      else this.cookies[k] = v;
    }
    return res;
  }
  json(path, body) {
    return this.fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body ?? {}) });
  }
}
