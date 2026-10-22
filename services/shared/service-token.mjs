// client_credentials token fetcher with in-memory cache (service-to-service calls)
export function serviceTokenClient({ authUrl, clientId, clientSecret, audience, scope }) {
  let cached = null;
  return async function getToken() {
    if (cached && cached.exp - 30_000 > Date.now()) return cached.token;
    const res = await fetch(`${authUrl}/oauth/token`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret, audience, scope }),
    });
    if (!res.ok) throw new Error(`service token request failed: ${res.status}`);
    const body = await res.json();
    cached = { token: body.access_token, exp: Date.now() + body.expires_in * 1000 };
    return cached.token;
  };
}
