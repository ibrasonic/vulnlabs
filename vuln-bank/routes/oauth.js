// routes/oauth.js — OAuth 2.0 / OpenID Connect Authorization Server, plus a
// small demo Relying Party so the lab has the full IdP+RP flow runnable
// against itself.
//
// Deliberately vulnerable. See VULNERABILITIES.txt entries [43]-[51].
//
//   [43] Lax redirect_uri validation — startsWith() instead of exact match.
//   [44] state parameter is optional and the demo RP never validates it — CSRF.
//   [45] Implicit flow (response_type=token / token id_token) enabled — token
//        leaks via URL fragment, lingers in browser history & Referer.
//   [46] PKCE code_challenge_method=plain accepted — defeats the protection.
//   [47] Authorization codes are reusable and have a 24h TTL — code replay.
//   [48] id_token alg=none honoured if the client passes
//        id_token_signing_alg=none; the demo RP also decodes id_token without
//        verifying the algorithm.
//   [49] scope is ignored at /oauth/userinfo — full PII returned regardless.
//   [50] nOAuth: prompt=none with login_hint sets the email claim on the
//        id_token to the hint, no matter who is signed in. RP merges by email.
//   [51] ROPC (password) grant enabled with no client authentication required
//        for public clients — plaintext credentials to a third party.
//   [52] Predictable refresh tokens: base64(user_id + ':' + epoch_ms).

const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');
const db = require('../lib/db');
const { md5, requireSession, JWT_SECRET } = require('../lib/auth');

const router = express.Router();

// In-memory grant store. Lost on restart, which is the lab norm.
const codes = new Map();          // code -> grant
const refreshTokens = new Map();   // refresh_token -> { user_id, client_id, scope }

// Registered clients. Two: a confidential web app and a public mobile client.
const CLIENTS = {
  'partner-portal': {
    client_id: 'partner-portal',
    client_secret: 'partner-portal-secret-2024',
    redirect_uris: ['http://localhost:3001/partners/demo-app/callback'],
    grant_types: ['authorization_code', 'refresh_token', 'password'],
    name: 'Partner Portal (Demo RP)'
  },
  'novatrust-mobile': {
    client_id: 'novatrust-mobile',
    client_secret: null,                                       // public client
    redirect_uris: ['novatrustapp://callback', 'http://localhost:3001/partners/mobile/callback'],
    grant_types: ['authorization_code', 'password'],
    name: 'NovaTrust Mobile'
  }
};

// VULN [43]: prefix match. Attacker registers callback=http://localhost:3001/
// partners/demo-app/callback.evil.example/ — passes startsWith() and is then
// not re-validated at the token endpoint either.
function redirectUriAllowed(client, supplied) {
  if (!supplied) return false;
  return client.redirect_uris.some(u => supplied.startsWith(u));
}

// === Discovery ============================================================
router.get('/.well-known/openid-configuration', (req, res) => {
  const base = `${req.protocol}://${req.get('host')}`;
  res.json({
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    userinfo_endpoint: `${base}/oauth/userinfo`,
    jwks_uri: `${base}/.well-known/jwks.json`,
    response_types_supported: ['code', 'token', 'id_token', 'id_token token', 'code id_token'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'password', 'implicit'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['HS256', 'none'],   // VULN [48]
    scopes_supported: ['openid', 'email', 'profile', 'accounts.read', 'transfer'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
    code_challenge_methods_supported: ['plain', 'S256']         // VULN [46]
  });
});

router.get('/.well-known/jwks.json', (req, res) => {
  // We sign with HS256 (symmetric), so the JWKS is empty. The endpoint exists
  // so RPs that probe it during discovery don't see a 404.
  res.json({ keys: [] });
});

// === Authorize ===========================================================
router.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state, nonce,
          code_challenge, code_challenge_method, prompt, login_hint,
          id_token_signing_alg } = req.query;

  const client = CLIENTS[client_id];
  if (!client) return res.status(400).type('text/plain').send('unknown client_id');
  if (!redirectUriAllowed(client, redirect_uri)) {
    return res.status(400).type('text/plain').send('redirect_uri not registered');
  }

  if (!req.session || !req.session.userId) {
    return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  }

  // VULN [50] nOAuth: prompt=none with login_hint skips consent AND uses the
  // hint as the email claim on the id_token. RP that merges accounts by email
  // (see /partners/demo-app/callback below) lets attacker assume any victim.
  if (prompt === 'none') {
    return issueCodeAndRedirect(req, res, client, redirect_uri, {
      scope, state, nonce, code_challenge, code_challenge_method,
      id_token_signing_alg, email_hint: login_hint, response_type
    });
  }

  // NOTE: EJS lifts a local named `client` into its compile options (treats
  // it as the `client: true` flag), which strips `include` from the template
  // scope. Renamed to `app` here to avoid the collision.
  res.render('oauth_consent', {
    app: client,
    scopes: String(scope || 'openid').split(/\s+/).filter(Boolean),
    redirect_uri,
    response_type: response_type || 'code',
    state: state || '',
    nonce: nonce || '',
    code_challenge: code_challenge || '',
    code_challenge_method: code_challenge_method || '',
    id_token_signing_alg: id_token_signing_alg || 'HS256'
  });
});

router.post('/oauth/authorize', requireSession, (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state, nonce,
          code_challenge, code_challenge_method, id_token_signing_alg,
          decision } = req.body;

  const client = CLIENTS[client_id];
  if (!client) return res.status(400).type('text/plain').send('unknown client_id');
  if (!redirectUriAllowed(client, redirect_uri)) {
    return res.status(400).type('text/plain').send('redirect_uri not registered');
  }
  if (decision !== 'allow') {
    const sep = redirect_uri.includes('?') ? '&' : '?';
    const qs = new URLSearchParams({ error: 'access_denied' });
    if (state) qs.append('state', state);
    return res.redirect(redirect_uri + sep + qs.toString());
  }
  issueCodeAndRedirect(req, res, client, redirect_uri, {
    scope, state, nonce, code_challenge, code_challenge_method,
    id_token_signing_alg, response_type
  });
});

function issueCodeAndRedirect(req, res, client, redirect_uri, opts) {
  const code = crypto.randomBytes(16).toString('hex');
  codes.set(code, {
    client_id: client.client_id,
    user_id: req.session.userId,
    redirect_uri,
    scope: opts.scope || 'openid',
    nonce: opts.nonce || null,
    code_challenge: opts.code_challenge || null,
    code_challenge_method: opts.code_challenge_method || null,
    id_token_signing_alg: opts.id_token_signing_alg || 'HS256',
    email_hint: opts.email_hint || null,
    issued_at: Date.now(),
    used: false
  });

  // VULN [45]: implicit flow — issue access_token (and optionally id_token)
  // in the URL fragment. RFC 6819 deprecated this; OAuth 2.1 removes it.
  if (opts.response_type && /token/.test(opts.response_type)) {
    const grant = codes.get(code);
    const tokens = issueTokens(client, grant, { include_id_token: /id_token/.test(opts.response_type) });
    const frag = new URLSearchParams({
      access_token: tokens.access_token,
      token_type: 'Bearer',
      expires_in: String(tokens.expires_in),
      scope: tokens.scope
    });
    if (opts.state) frag.append('state', opts.state);
    if (tokens.id_token) frag.append('id_token', tokens.id_token);
    return res.redirect(redirect_uri + '#' + frag.toString());
  }

  const sep = redirect_uri.includes('?') ? '&' : '?';
  const params = new URLSearchParams({ code });
  if (opts.state) params.append('state', opts.state);
  res.redirect(redirect_uri + sep + params.toString());
}

// === Token ===============================================================
router.post('/oauth/token', (req, res) => {
  const grant = req.body.grant_type;
  if (grant === 'authorization_code') return tokenAuthCode(req, res);
  if (grant === 'refresh_token')      return tokenRefresh(req, res);
  if (grant === 'password')           return tokenPassword(req, res);
  return res.status(400).json({ error: 'unsupported_grant_type' });
});

function authenticateClient(req) {
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Basic ')) {
    const decoded = Buffer.from(auth.slice(6), 'base64').toString('utf8');
    const idx = decoded.indexOf(':');
    const cid = decoded.slice(0, idx);
    const secret = decoded.slice(idx + 1);
    const client = CLIENTS[cid];
    if (client && client.client_secret === secret) return client;
    return null;
  }
  const cid = req.body.client_id;
  const client = CLIENTS[cid];
  if (!client) return null;
  if (client.client_secret === null) return client;          // public client
  if (client.client_secret === req.body.client_secret) return client;
  return null;
}

function tokenAuthCode(req, res) {
  const client = authenticateClient(req);
  if (!client) return res.status(401).json({ error: 'invalid_client' });

  const { code, redirect_uri, code_verifier } = req.body;
  const entry = codes.get(code);
  if (!entry) return res.status(400).json({ error: 'invalid_grant' });
  if (entry.client_id !== client.client_id) return res.status(400).json({ error: 'invalid_grant' });

  // VULN [43]: redirect_uri is checked with the same lax prefix match as on
  // /authorize, not against the original grant's redirect_uri.
  if (!redirectUriAllowed(client, redirect_uri)) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
  }

  // VULN [46]: code_challenge_method=plain accepted, defeating PKCE.
  if (entry.code_challenge) {
    const method = entry.code_challenge_method || 'plain';
    if (method === 'plain') {
      if (code_verifier !== entry.code_challenge) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'pkce mismatch' });
      }
    } else if (method === 'S256') {
      const expect = crypto.createHash('sha256').update(code_verifier || '')
        .digest('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
      if (expect !== entry.code_challenge) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'pkce mismatch' });
      }
    }
  }

  // VULN [47]: 24h TTL and we do NOT delete the code or mark it used. Replay.
  if (Date.now() - entry.issued_at > 24 * 3600 * 1000) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'code expired' });
  }

  const tokens = issueTokens(client, entry, { include_id_token: /openid/.test(entry.scope) });
  res.json(tokens);
}

function tokenRefresh(req, res) {
  const client = authenticateClient(req);
  if (!client) return res.status(401).json({ error: 'invalid_client' });
  const r = refreshTokens.get(req.body.refresh_token);
  if (!r) return res.status(400).json({ error: 'invalid_grant' });
  const entry = {
    client_id: client.client_id,
    user_id: r.user_id,
    scope: r.scope,
    id_token_signing_alg: 'HS256',
    nonce: null,
    email_hint: null
  };
  const tokens = issueTokens(client, entry, { include_id_token: /openid/.test(r.scope) });
  res.json(tokens);
}

// VULN [51]: ROPC (resource owner password credentials). Public clients can
// hit this with no client_secret and harvest plaintext passwords.
function tokenPassword(req, res) {
  const client = authenticateClient(req);
  if (!client) return res.status(401).json({ error: 'invalid_client' });
  const { username, password, scope } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ? AND password_md5 = ?')
    .get(username || '', md5(password || ''));
  if (!user) return res.status(401).json({ error: 'invalid_grant' });
  const entry = {
    client_id: client.client_id,
    user_id: user.id,
    scope: scope || 'openid',
    id_token_signing_alg: 'HS256',
    nonce: null,
    email_hint: null
  };
  const tokens = issueTokens(client, entry, { include_id_token: true });
  res.json(tokens);
}

function issueTokens(client, entry, { include_id_token }) {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(entry.user_id);
  const now = Math.floor(Date.now() / 1000);

  const access_claims = {
    sub: String(user.id),
    aud: client.client_id,
    iss: 'http://localhost:3001',
    iat: now,
    exp: now + 3600,
    scope: entry.scope,
    username: user.username,
    role: user.role
  };
  const access_token = jwt.sign(access_claims, JWT_SECRET, { algorithm: 'HS256' });

  let id_token = null;
  if (include_id_token) {
    const id_claims = {
      iss: 'http://localhost:3001',
      sub: String(user.id),
      aud: client.client_id,
      iat: now,
      exp: now + 3600,
      // VULN [50] nOAuth: the hint wins over the authenticated user's email.
      email: entry.email_hint || user.email,
      email_verified: true,
      name: user.full_name,
      preferred_username: user.username
    };
    if (entry.nonce) id_claims.nonce = entry.nonce;

    if (entry.id_token_signing_alg === 'none') {
      // VULN [48]: produce an unsigned id_token if the client asked for one.
      const h = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
      const p = Buffer.from(JSON.stringify(id_claims)).toString('base64url');
      id_token = h + '.' + p + '.';
    } else {
      id_token = jwt.sign(id_claims, JWT_SECRET, { algorithm: 'HS256' });
    }
  }

  // VULN [52]: predictable refresh tokens — base64(user_id:epoch_ms). An
  // attacker who knows a user_id can grind candidate tokens.
  const refresh_token = Buffer.from(user.id + ':' + Date.now()).toString('base64');
  refreshTokens.set(refresh_token, {
    user_id: user.id,
    client_id: client.client_id,
    scope: entry.scope
  });

  const out = {
    access_token,
    token_type: 'Bearer',
    expires_in: 3600,
    refresh_token,
    scope: entry.scope
  };
  if (id_token) out.id_token = id_token;
  return out;
}

// === Userinfo ============================================================
router.get('/oauth/userinfo', (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'invalid_token' });
  let decoded;
  try {
    // VULN [48] mirror: also accepts alg=none access tokens.
    decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'none'] });
  } catch (e) {
    return res.status(401).json({ error: 'invalid_token', error_description: e.message });
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(decoded.sub);
  if (!user) return res.status(404).json({ error: 'no_such_user' });
  // VULN [49]: scope ignored — full PII returned regardless of what the
  // client asked for. A token with scope=openid alone gets SSN + DOB.
  res.json({
    sub: String(user.id),
    email: user.email,
    email_verified: true,
    name: user.full_name,
    preferred_username: user.username,
    phone_number: user.phone,
    address: { formatted: user.address },
    ssn: user.ssn,
    dob: user.dob,
    role: user.role
  });
});

// === Demo Relying Party ==================================================
// A small "third-party app" served from the same origin so the lab has the
// full OAuth client side runnable without setting up a second host.

router.get('/partners/demo-app', (req, res) => {
  res.render('partners_demo', {
    client_id: 'partner-portal',
    redirect_uri: 'http://localhost:3001/partners/demo-app/callback',
    error: req.query.error || null
  });
});

router.get('/partners/demo-app/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) {
    return res.render('partners_demo_callback', { error: String(error), tokens: null, claims: null });
  }
  if (!code) {
    return res.render('partners_demo_callback', { error: 'no code returned', tokens: null, claims: null });
  }

  // VULN [44]: state is not validated against anything stored server-side.

  try {
    const base = `${req.protocol}://${req.get('host')}`;
    // The redirect_uri sent at /token must match what was used at /authorize,
    // so pin it to the registered URI rather than rebuilding from req.host
    // (which can drift between localhost and 127.0.0.1).
    const registeredRedirect = CLIENTS['partner-portal'].redirect_uris[0];
    const resp = await fetch(base + '/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: String(code),
        redirect_uri: registeredRedirect,
        client_id: 'partner-portal',
        client_secret: 'partner-portal-secret-2024'
      })
    });
    const tokens = await resp.json();
    if (tokens.error) {
      return res.render('partners_demo_callback', { error: tokens.error, tokens, claims: null });
    }

    // VULN [48] mirror: decode id_token without verifying the alg.
    let claims = null;
    if (tokens.id_token) {
      const parts = tokens.id_token.split('.');
      if (parts.length >= 2) {
        try { claims = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8')); }
        catch (e) { /* ignore */ }
      }
    }

    // VULN [50] final stage: merge accounts by email claim. The RP signs the
    // user in as whichever local user has that email — letting nOAuth land.
    if (claims && claims.email) {
      const u = db.prepare('SELECT * FROM users WHERE email = ?').get(claims.email);
      if (u) {
        req.session.userId = u.id;
        req.session.username = u.username;
        req.session.role = u.role;
      }
    }

    res.render('partners_demo_callback', { error: null, tokens, claims });
  } catch (e) {
    res.render('partners_demo_callback', { error: e.message, tokens: null, claims: null });
  }
});

module.exports = router;
