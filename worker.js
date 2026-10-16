import { Hono } from 'hono';
import * as jose from 'jose';

const app = new Hono();

let keyPromise;

/**
 * Load the signing key from the SIGNING_KEY secret (a private RSA JWK).
 * Falls back to an in-memory key when the secret is not set. That key differs
 * per isolate and changes on every deploy, so tokens can intermittently fail
 * verification; set SIGNING_KEY in production (see `npm run generate-key`).
 */
function getKeys(env) {
  if (!keyPromise) {
    keyPromise = loadKeys(env).catch((e) => {
      keyPromise = undefined;
      throw e;
    });
  }
  return keyPromise;
}

async function loadKeys(env) {
  let privateJwk;

  if (env.SIGNING_KEY) {
    privateJwk = JSON.parse(env.SIGNING_KEY);
  } else {
    console.warn('SIGNING_KEY is not set; using an ephemeral per-isolate signing key');
    const { privateKey } = await jose.generateKeyPair('RS256', { extractable: true });
    privateJwk = await jose.exportJWK(privateKey);
  }

  const publicJwk = { kty: privateJwk.kty, n: privateJwk.n, e: privateJwk.e };
  const kid = await jose.calculateJwkThumbprint(publicJwk);

  return {
    kid,
    privateKey: await jose.importJWK(privateJwk, 'RS256'),
    publicJwk: { ...publicJwk, kid, alg: 'RS256', use: 'sig' },
  };
}

/**
 * Read a required env var or throw.
 */
function requireEnv(env, key) {
  const val = env[key];
  if (!val) throw new Error(`Missing required environment variable: ${key}`);
  return val;
}

/**
 * Parse ALLOWED_GUILDS from a comma-separated string into an array.
 * Returns empty array if not set.
 */
function parseGuilds(env) {
  const raw = env.ALLOWED_GUILDS || '';
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Fetch every guild ID the user is in. Discord returns at most 200 guilds per
 * page, so follow the `after` cursor until a short page comes back.
 * Returns a Response on failure so the caller can return it directly.
 */
async function fetchGuildIds(accessToken) {
  const ids = [];
  let after = '0';

  for (;;) {
    const res = await fetch(
      `https://discord.com/api/v10/users/@me/guilds?limit=200&after=${after}`,
      { headers: { Authorization: 'Bearer ' + accessToken } }
    );

    if (!res.ok) {
      console.error('Discord guilds fetch failed:', res.status, await res.text());
      return new Response('Failed to fetch Discord guilds', { status: 502 });
    }

    const page = await res.json();

    if (!Array.isArray(page)) {
      console.error('Discord guilds response is not an array:', page);
      return new Response('Invalid Discord guilds response', { status: 502 });
    }

    ids.push(...page.map((g) => g.id));
    if (page.length < 200) return ids;
    after = page[page.length - 1].id;
  }
}

/* ---------------- HEALTH ---------------- */

app.get('/health', (c) => {
  return c.json({ status: 'ok' });
});

/* ---------------- DISCOVERY ---------------- */

app.get('/.well-known/openid-configuration', (c) => {
  const base = new URL(c.req.url).origin;

  return c.json({
    issuer: base,
    authorization_endpoint: base + '/authorize',
    token_endpoint: base + '/token',
    jwks_uri: base + '/jwks.json',
    response_types_supported: ['code'],
    id_token_signing_alg_values_supported: ['RS256'],
    subject_types_supported: ['public'],
  });
});

/* ---------------- AUTHORIZE ---------------- */

app.get('/authorize', (c) => {
  const clientId = requireEnv(c.env, 'CLIENT_ID');
  const redirectUri = requireEnv(c.env, 'REDIRECT_URI');
  const adminRoleId = c.env.ADMIN_ROLE_ID || '';

  // Only request guilds.members.read when admin detection is enabled
  const scopes = adminRoleId
    ? 'identify email guilds guilds.members.read'
    : 'identify email guilds';

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: scopes,
  });

  const state = c.req.query('state');
  if (state) params.set('state', state);

  return c.redirect('https://discord.com/oauth2/authorize?' + params);
});

/* ---------------- TOKEN ---------------- */

app.post('/token', async (c) => {
  const clientId = requireEnv(c.env, 'CLIENT_ID');
  const clientSecret = requireEnv(c.env, 'CLIENT_SECRET');
  const redirectUri = requireEnv(c.env, 'REDIRECT_URI');
  const allowedGuilds = parseGuilds(c.env);
  const adminRoleId = c.env.ADMIN_ROLE_ID || '';
  const adminGuildId = c.env.ADMIN_GUILD_ID || (allowedGuilds.length ? allowedGuilds[0] : '');

  const body = await c.req.parseBody();

  // Exchange authorization code for access token
  const params = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: 'authorization_code',
    code: body.code,
    redirect_uri: redirectUri,
  });

  const token = await fetch('https://discord.com/api/v10/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params,
  }).then((r) => r.json());

  if (token.error) {
    console.error('Discord token exchange failed:', token.error, token.error_description);
    return c.json({ error: 'Token exchange failed', detail: token.error_description }, 400);
  }

  // Fetch user profile
  const userRes = await fetch('https://discord.com/api/v10/users/@me', {
    headers: { Authorization: 'Bearer ' + token.access_token },
  });

  if (!userRes.ok) {
    console.error('Discord user fetch failed:', userRes.status, await userRes.text());
    return c.text('Failed to fetch Discord user profile', 502);
  }

  const user = await userRes.json();

  if (!user.id) {
    console.error('Discord user response missing id:', user);
    return c.text('Invalid Discord user response', 502);
  }

  if (!user.verified) {
    return c.text('Your Discord account email is not verified', 403);
  }

  if (allowedGuilds.length) {
    const guildIds = await fetchGuildIds(token.access_token);

    if (guildIds instanceof Response) return guildIds;

    if (!allowedGuilds.some((id) => guildIds.includes(id))) {
      return c.text('Not in required Discord server', 403);
    }
  }

  // Check admin role (only when ADMIN_ROLE_ID is configured)
  let isAdmin = false;

  if (adminRoleId && adminGuildId) {
    try {
      const memberRes = await fetch(
        `https://discord.com/api/v10/users/@me/guilds/${adminGuildId}/member`,
        { headers: { Authorization: 'Bearer ' + token.access_token } }
      );

      if (!memberRes.ok) {
        console.error('Discord guild member fetch failed:', memberRes.status);
      } else {
        const member = await memberRes.json();
        if (member.roles && Array.isArray(member.roles)) {
          isAdmin = member.roles.includes(adminRoleId);
        }
      }
    } catch (e) {
      console.error('Failed to fetch guild member for admin check:', e);
    }
  }

  const { kid, privateKey } = await getKeys(c.env);

  const idToken = await new jose.SignJWT({
    sub: user.id,
    name: user.global_name || user.username,
    preferred_username: user.username,
    email: user.email,
    email_verified: true,
    discord_user: {
      id: user.id,
      username: user.username,
      global_name: user.global_name,
      avatar: user.avatar,
      discriminator: user.discriminator,
      is_admin: isAdmin,
    },
  })
    .setProtectedHeader({ alg: 'RS256', kid })
    .setIssuedAt()
    .setExpirationTime('1h')
    .setAudience(clientId)
    .setIssuer(new URL(c.req.url).origin)
    .sign(privateKey);

  return c.json({
    access_token: token.access_token,
    token_type: 'Bearer',
    id_token: idToken,
  });
});

/* ---------------- JWKS ---------------- */

app.get('/jwks.json', async (c) => {
  const { publicJwk } = await getKeys(c.env);

  return c.json({ keys: [publicJwk] });
});

export default app;
